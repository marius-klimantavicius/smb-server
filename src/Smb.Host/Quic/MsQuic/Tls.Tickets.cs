using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using Managed.Security;
using static Managed.Security.PicoTls;

namespace Managed.Transport.Hosting;

public sealed unsafe partial class MsQuicHost
{
    private static ReadOnlySpan<byte> TicketEnvelopeMagic => "DOTCC-QUIC-TKTv1"u8;
    private const int TicketEnvelopeHeader = 32;

    private static void ConfigureServerTickets(TlsSecurityConfig security)
    {
        var callback = (st_ptls_encrypt_ticket_t*)security.Memory.Allocate(sizeof(st_ptls_encrypt_ticket_t));
        callback->cb = &TlsProtectTicket;
        security.Context->encrypt_ticket = callback;
    }

    private static int PushTlsBytes(st_ptls_buffer_t* output, ReadOnlySpan<byte> bytes)
    {
        if (output == null || output->off > output->capacity || output->off > ulong.MaxValue - (ulong)bytes.Length)
            return 80;

        var result = ptls_buffer_reserve(output, (ulong)bytes.Length);
        if (result != 0)
            return result;

        bytes.CopyTo(new Span<byte>(output->@base + output->off, bytes.Length));
        output->off += (ulong)bytes.Length;
        return 0;
    }

    private static ulong TicketSessionIssueTime(ReadOnlySpan<byte> session)
    {
        if (session.Length < 18 || BinaryPrimitives.ReadUInt16BigEndian(session) != session.Length - 2 || !session.Slice(2, 8).SequenceEqual("ptls0001"u8))
            throw new InvalidOperationException("Unexpected pinned picotls session encoding");

        return BinaryPrimitives.ReadUInt64BigEndian(session[10..]);
    }

    private static int TlsProtectTicket(st_ptls_encrypt_ticket_t* self, st_ptls_t* tls, int encryption, st_ptls_buffer_t* output, st_ptls_iovec_t input)
    {
        try
        {
            var owner = TlsOwner(tls);
            if (!owner.Server || owner.Security.Tickets == null || input.len is 0 or > 65535 || input.@base == null)
                return PTLS_ERROR_SESSION_NOT_FOUND;

            var provider = owner.Security.Tickets.Callback;
            if (encryption != 0)
            {
                // Initial automatic tickets are discarded. Application-requested
                // tickets bind the core's transport/application bytes statelessly.
                if (owner.ApplicationTicketData == null)
                    return provider->cb(provider, tls, 1, output, input);

                var session = new ReadOnlySpan<byte>(input.@base, (int)input.len);
                var size = checked(TicketEnvelopeHeader + session.Length + owner.ApplicationTicketData.Length);
                if (size > ushort.MaxValue - 97)
                    return PTLS_ALERT_INTERNAL_ERROR;

                var envelope = new byte[size];
                try
                {
                    TicketEnvelopeMagic.CopyTo(envelope);

                    var expiry = checked(TicketSessionIssueTime(session) + owner.Security.Tickets.LifetimeSeconds * 1000UL);
                    BinaryPrimitives.WriteUInt64BigEndian(envelope.AsSpan(16), expiry);
                    BinaryPrimitives.WriteInt32BigEndian(envelope.AsSpan(24), session.Length);
                    BinaryPrimitives.WriteInt32BigEndian(envelope.AsSpan(28), owner.ApplicationTicketData.Length);
                    session.CopyTo(envelope.AsSpan(TicketEnvelopeHeader));
                    owner.ApplicationTicketData.CopyTo(envelope, TicketEnvelopeHeader + session.Length);

                    fixed (byte* value = envelope)
                        return provider->cb(provider, tls, 1, output, new st_ptls_iovec_t { @base = value, len = (ulong)size });
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(envelope);
                }
            }

            var plaintext = PicotlsBuffer.Create();
            try
            {
                var result = provider->cb(provider, tls, 0, &plaintext, input);
                if (result is not (0 or 0x209) || plaintext.off < TicketEnvelopeHeader || plaintext.off > 65535)
                    return PTLS_ERROR_SESSION_NOT_FOUND;

                var envelope = new ReadOnlySpan<byte>(plaintext.@base, (int)plaintext.off);
                if (!envelope[..16].SequenceEqual(TicketEnvelopeMagic))
                    return PTLS_ERROR_SESSION_NOT_FOUND;

                var expiry = BinaryPrimitives.ReadUInt64BigEndian(envelope[16..]);
                var sessionLength = BinaryPrimitives.ReadInt32BigEndian(envelope[24..]);
                var applicationLength = BinaryPrimitives.ReadInt32BigEndian(envelope[28..]);
                if (sessionLength <= 0 || applicationLength < 0 || (long)TicketEnvelopeHeader + sessionLength + applicationLength != envelope.Length || checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()) >= expiry)
                    return PTLS_ERROR_SESSION_NOT_FOUND;

                var session = envelope.Slice(TicketEnvelopeHeader, sessionLength);
                var issued = TicketSessionIssueTime(session);
                if (issued > expiry || expiry - issued != owner.Security.Tickets.LifetimeSeconds * 1000UL)
                    return PTLS_ERROR_SESSION_NOT_FOUND;

                if (owner.Security.Callbacks.ReceiveTicket == null || owner.Security.Callbacks.ReceiveTicket(owner.Connection, (uint)applicationLength, plaintext.@base + TicketEnvelopeHeader + sessionLength) == 0)
                    return PTLS_ERROR_SESSION_NOT_FOUND;

                result = PushTlsBytes(output, session);
                return result == 0 ? PTLS_ERROR_REJECT_EARLY_DATA : result;
            }
            finally
            {
                if (plaintext.off != 0) CryptographicOperations.ZeroMemory(new Span<byte>(plaintext.@base, checked((int)plaintext.off)));
                dotcc_ptls_buffer_dispose(&plaintext);
            }
        }
        catch (Exception error)
        {
            CallbackScope.Capture(error);
            return PTLS_ERROR_LIBRARY;
        }
    }

    private sealed partial class TlsConnection
    {
        internal byte[]? ApplicationTicketData;

        private static void DiscardAutomaticTickets(ReadOnlySpan<byte> flight)
        {
            while (!flight.IsEmpty)
            {
                if (flight.Length < 4 || flight[0] != 4)
                    throw new InvalidOperationException("Unexpected TLS post-handshake output");

                var length = 4 + (flight[1] << 16 | flight[2] << 8 | flight[3]);
                if (length > flight.Length)
                    throw new InvalidOperationException("Truncated automatic TLS ticket");

                flight = flight[length..];
            }
        }

        private void ReleaseTicket(ReadOnlySpan<byte> application)
        {
            if (ApplicationTicketData != null)
                throw new InvalidOperationException("Reentrant TLS ticket request");

            ApplicationTicketData = application.ToArray();
            var output = PicotlsBuffer.Create();
            try
            {
                var result = dotcc_ptls_send_quic_ticket(Tls, &output);
                if (result != 0 || output.off == 0 || output.off > ushort.MaxValue)
                    throw new InvalidOperationException("TLS ticket generation failed: " + result);

                AppendOutput(3, new ReadOnlySpan<byte>(output.@base, (int)output.off));
            }
            finally
            {
                dotcc_ptls_buffer_dispose(&output);
                CryptographicOperations.ZeroMemory(ApplicationTicketData);
                ApplicationTicketData = null;
            }
        }

        private void DisposePendingTickets()
        {
            if (ApplicationTicketData != null)
                CryptographicOperations.ZeroMemory(ApplicationTicketData);

            ApplicationTicketData = null;
        }
    }
}