using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using Managed.Security;
using static Managed.Security.PicoTls;
using static Managed.Transport.MsQuic;

namespace Managed.Transport.Hosting;

public sealed unsafe partial class MsQuicHost
{
    private struct TlsCallbackContext
    {
        internal void* Host;
        internal void* Token;
    }

    private sealed partial class TlsConnection : IDisposable
    {
        [InlineArray(4)]
        private struct FrameHeaderBuffer
        {
            private byte _element0;
        }

        private readonly TlsCallbackContext* _callback;
        private FrameHeaderBuffer _frameHeader;
        private int _headerBytes;
        private uint _bodyRemaining;

        internal readonly object Gate = new object();
        internal readonly MsQuicHost Host;
        internal readonly TlsSecurityConfig Security;
        internal readonly TlsMemory Memory = new TlsMemory();
        internal readonly QUIC_CONNECTION* Connection;
        internal readonly bool Server;
        internal readonly byte[][] Protocols;
        internal readonly byte* ServerAlpn;
        internal QUIC_HKDF_LABELS Labels;
        internal st_ptls_t* Tls;
        internal readonly QUIC_TLS_SECRETS* Secrets;
        internal readonly st_ptls_handshake_properties_t* Properties;
        internal CXPLAT_TLS_PROCESS_STATE* State;
        internal CXPLAT_TLS_RESULT_FLAGS Results;
        internal bool Disposed, Started, TransportParametersReceived;
        internal byte[] PeerParameters = [];

        internal TlsConnection(MsQuicHost host, TlsSecurityConfig security, CXPLAT_TLS_CONFIG* config, CXPLAT_TLS_PROCESS_STATE* state)
        {
            Host = host;
            Security = security;
            Connection = config->Connection;
            Server = config->IsServer != 0;
            Labels = *config->HkdfLabels;
            State = state;
            ServerAlpn = config->AlpnBuffer;
            Secrets = config->TlsSecrets;
            security.Retain();

            try
            {
                using var scope = CallbackScope.Enter();
                if (config->AlpnBuffer == null || config->AlpnBufferLength == 0)
                    throw new ArgumentException("ALPN list is required");

                var protocols = new List<byte[]>();
                var offset = 0;
                while (offset < config->AlpnBufferLength)
                {
                    int length = config->AlpnBuffer[offset++];
                    if (length == 0 || length > config->AlpnBufferLength - offset)
                        throw new ArgumentException("Invalid ALPN list");

                    var protocol = new ReadOnlySpan<byte>(config->AlpnBuffer + offset, length);
                    if (protocol.Contains((byte)0))
                        throw new ArgumentException("This TLS profile requires ALPN without NUL bytes");

                    protocols.Add(protocol.ToArray());
                    offset += length;
                }

                Protocols = protocols.ToArray();
                Properties = (st_ptls_handshake_properties_t*)Memory.Allocate(sizeof(st_ptls_handshake_properties_t));
                _callback = (TlsCallbackContext*)Memory.Allocate(sizeof(TlsCallbackContext));
                _callback->Host = host.ContextPointer;

                var extensions = (st_ptls_raw_extension_t*)Memory.Allocate(2 * sizeof(st_ptls_raw_extension_t));
                extensions[0].type = config->TPType;
                extensions[0].data = new st_ptls_iovec_t { @base = Memory.Copy(new ReadOnlySpan<byte>(config->LocalTPBuffer, (int)config->LocalTPLength)), len = config->LocalTPLength };
                extensions[1].type = ushort.MaxValue;
                Properties->additional_extensions = extensions;
                Properties->collect_extension = &TlsCollectExtension;
                Properties->collected_extensions = &TlsCollectedExtensions;

                if (Server)
                {
                    dotcc_ptls_server_properties(Properties, 0);
                }
                else
                {
                    var offered = (st_ptls_iovec_t*)Memory.Allocate(checked(Protocols.Length * sizeof(st_ptls_iovec_t)));
                    for (var i = 0; i < Protocols.Length; i++)
                        offered[i] = new st_ptls_iovec_t { @base = Memory.Copy(Protocols[i]), len = (ulong)Protocols[i].Length };

                    st_ptls_iovec_t ticket = default;
                    if (security.ResumptionEnabled && config->ResumptionTicketLength != 0)
                    {
                        if (config->ResumptionTicketLength > ushort.MaxValue)
                            throw new ArgumentException("TLS ticket too large");

                        ticket = new st_ptls_iovec_t { @base = Memory.Copy(new ReadOnlySpan<byte>(config->ResumptionTicketBuffer, (int)config->ResumptionTicketLength)), len = config->ResumptionTicketLength };
                    }

                    dotcc_ptls_client_properties(Properties, offered, (ulong)Protocols.Length, ticket, 0);
                }

                Tls = Server ? ptls_server_new(security.Context) : ptls_client_new(security.Context);
                scope.ThrowIfFailed();
                if (Tls == null)
                    throw new OutOfMemoryException("picotls connection");

                *ptls_get_data_ptr(Tls) = _callback;
                if (!Server)
                {
                    if (config->ServerName == null)
                        throw new ArgumentException("Client server name is required");

                    var length = 0;
                    while (length < 256 && config->ServerName[length] != 0)
                        length++;

                    if (length is 0 or 256)
                        throw new ArgumentException("Invalid server name length");

                    if (ptls_set_server_name(Tls, config->ServerName, (ulong)length) != 0)
                        throw new ArgumentException("Invalid server name");
                }

                State->EarlyDataState = CXPLAT_TLS_EARLY_DATA_STATE.CXPLAT_TLS_EARLY_DATA_UNSUPPORTED;
                scope.ThrowIfFailed();
            }
            catch
            {
                Dispose();
                throw;
            }
        }

        internal void AttachToken(CXPLAT_TLS* token) => _callback->Token = token;

        internal CXPLAT_TLS_RESULT_FLAGS Process(CXPLAT_TLS_DATA_TYPE type, byte* input, uint* length, CXPLAT_TLS_PROCESS_STATE* state)
        {
            lock (Gate)
            {
                if (Disposed)
                    FatalInvariant("TLS connection used after release");

                State = state;
                Results = 0;
                var supplied = *length;
                *length = 0;
                if (!PacketReadable(input, supplied))
                    return Fail(50);

                try
                {
                    using var scope = CallbackScope.Enter();
                    if (type == CXPLAT_TLS_DATA_TYPE.CXPLAT_TLS_TICKET_DATA)
                    {
                        if (!Server || !Security.ResumptionEnabled || State->HandshakeComplete == 0)
                            return Fail(80);

                        ReleaseTicket(new ReadOnlySpan<byte>(input, (int)supplied));
                        scope.ThrowIfFailed();
                        *length = supplied;
                        return Results;
                    }

                    if (type != CXPLAT_TLS_DATA_TYPE.CXPLAT_TLS_CRYPTO_DATA)
                        return Fail(10);

                    if (!ValidateFraming(new ReadOnlySpan<byte>(input, (int)supplied), out var alert))
                        return Fail(alert);

                    if (supplied == 0 && (Server || Started))
                        return Results;

                    var start = !Server && !Started;
                    if (start && supplied != 0)
                        return Fail(10);

                    Started = true;
                    var epoch = ptls_get_read_epoch(Tls);
                    ulong expected = State->ReadKey switch
                    {
                        QUIC_PACKET_KEY_TYPE.QUIC_PACKET_KEY_INITIAL => 0,
                        QUIC_PACKET_KEY_TYPE.QUIC_PACKET_KEY_HANDSHAKE => 2,
                        QUIC_PACKET_KEY_TYPE.QUIC_PACKET_KEY_1_RTT => 3,
                        _ => ulong.MaxValue,
                    };

                    if (epoch != expected)
                        return Fail(10);

                    var output = PicotlsBuffer.Create();
                    var offsets = stackalloc ulong[5];
                    new Span<ulong>(offsets, 5).Clear();

                    try
                    {
                        var code = ptls_handle_message(Tls, &output, offsets, epoch, start ? null : input, supplied, Properties);
                        scope.ThrowIfFailed();

                        if (code != 0 && code != 0x202)
                            return Fail((ushort)((code & ~255) == 0 ? code : 80));

                        if (offsets[0] != 0 || offsets[4] != output.off || output.off > 1024 * 1024)
                            return Fail(80);

                        for (var i = 0; i < 4; i++)
                        {
                            if (offsets[i] > offsets[i + 1] || offsets[i + 1] > output.off)
                                return Fail(80);

                            var count = checked((int)(offsets[i + 1] - offsets[i]));
                            if (count == 0)
                                continue;

                            var flight = new ReadOnlySpan<byte>(output.@base + offsets[i], count);
                            if (i == 1)
                                return Fail(10);

                            if (Server && i == 3)
                                DiscardAutomaticTickets(flight);
                            else
                                AppendOutput(i, flight);
                        }
                    }
                    finally
                    {
                        dotcc_ptls_buffer_dispose(&output);
                    }

                    *length = supplied;
                    if (ptls_handshake_is_complete(Tls) != 0 && State->HandshakeComplete == 0)
                    {
                        if (!TransportParametersReceived)
                            return Fail(109);

                        SetNegotiatedAlpn();
                        State->HandshakeComplete = 1;
                        if (Server && State->ReadKeys[3].Value != null)
                        {
                            State->ReadKey = QUIC_PACKET_KEY_TYPE.QUIC_PACKET_KEY_1_RTT;
                            Results |= CXPLAT_TLS_RESULT_FLAGS.CXPLAT_TLS_RESULT_READ_KEY_UPDATED;
                        }

                        State->SessionResumed = (byte)(ptls_is_psk_handshake(Tls) != 0 ? 1 : 0);
                        Results |= CXPLAT_TLS_RESULT_FLAGS.CXPLAT_TLS_RESULT_HANDSHAKE_COMPLETE;
                    }

                    return Results;
                }
                catch (Exception)
                {
                    return Fail(80);
                }
                finally
                {
                    // Match the upstream provider's key/output boundary invariants.
                    if (State->WriteKeys[2].Value != null && State->BufferOffsetHandshake == 0)
                        State->BufferOffsetHandshake = State->BufferTotalLength;

                    if (State->WriteKeys[3].Value != null && State->BufferOffset1Rtt == 0)
                        State->BufferOffset1Rtt = State->BufferTotalLength;
                }
            }
        }

        private bool ValidateFraming(ReadOnlySpan<byte> input, out ushort alert)
        {
            alert = 0;
            while (!input.IsEmpty)
            {
                if (_bodyRemaining != 0)
                {
                    var consume = (int)Math.Min(_bodyRemaining, (uint)input.Length);
                    _bodyRemaining -= (uint)consume;
                    input = input[consume..];
                    continue;
                }

                var value = input[0];
                input = input[1..];
                if (_headerBytes == 0 && value == 24)
                {
                    alert = 10;
                    return false;
                }

                _frameHeader[_headerBytes++] = value;
                if (_headerBytes == 4)
                {
                    _bodyRemaining = (uint)(_frameHeader[1] << 16 | _frameHeader[2] << 8 | _frameHeader[3]);
                    _headerBytes = 0;
                    if (_bodyRemaining > 1024 * 1024)
                    {
                        alert = 50;
                        return false;
                    }
                }
            }

            return true;
        }

        private CXPLAT_TLS_RESULT_FLAGS Fail(ushort alert)
        {
            State->AlertCode = alert;
            Results |= CXPLAT_TLS_RESULT_FLAGS.CXPLAT_TLS_RESULT_ERROR;
            return Results;
        }

        private void AppendOutput(int epoch, ReadOnlySpan<byte> data)
        {
            var required = checked(State->BufferLength + data.Length);
            if (required > ushort.MaxValue || State->BufferTotalLength > uint.MaxValue - (uint)data.Length)
                throw new InvalidOperationException("TLS output exceeds core buffer bounds");

            if (required > State->BufferAllocLength)
            {
                var capacity = Math.Min(ushort.MaxValue, Math.Max(required, Math.Max(4096, State->BufferAllocLength * 2)));
                var replacement = (byte*)Host.AllocatePlatformMemory((ulong)capacity, QUIC_POOL_TLS_BUFFER);
                if (replacement == null)
                    throw new OutOfMemoryException();

                if (State->BufferLength != 0)
                    new ReadOnlySpan<byte>(State->Buffer, State->BufferLength).CopyTo(new Span<byte>(replacement, capacity));

                if (State->Buffer != null)
                    Host.FreePlatformMemory(State->Buffer, QUIC_POOL_TLS_BUFFER);

                State->Buffer = replacement;
                State->BufferAllocLength = (ushort)capacity;
            }

            if (epoch == 2 && State->BufferOffsetHandshake == 0)
                State->BufferOffsetHandshake = State->BufferTotalLength;
            if (epoch == 3 && State->BufferOffset1Rtt == 0)
                State->BufferOffset1Rtt = State->BufferTotalLength;

            data.CopyTo(new Span<byte>(State->Buffer + State->BufferLength, data.Length));
            State->BufferLength = (ushort)required;
            State->BufferTotalLength += (uint)data.Length;
            Results |= CXPLAT_TLS_RESULT_FLAGS.CXPLAT_TLS_RESULT_DATA;
        }

        private void SetNegotiatedAlpn()
        {
            var text = ptls_get_negotiated_protocol(Tls);
            if (text == null)
                throw new InvalidOperationException("Missing negotiated ALPN");

            var length = 0;
            while (length < 256 && text[length] != 0)
                length++;

            if (length is 0 or 256)
                throw new InvalidOperationException("Invalid negotiated ALPN");

            var protocol = new ReadOnlySpan<byte>(text, length);
            if (!Protocols.Any(value => value.AsSpan().SequenceEqual(new ReadOnlySpan<byte>(text, length))))
                throw new InvalidOperationException("Unconfigured negotiated ALPN");

            if (Server)
            {
                if (State->NegotiatedAlpn == null)
                    State->NegotiatedAlpn = ServerAlpn;

                if (State->NegotiatedAlpn == null || State->NegotiatedAlpn[0] != length || !new ReadOnlySpan<byte>(State->NegotiatedAlpn + 1, length).SequenceEqual(protocol))
                    throw new InvalidOperationException("TLS ALPN differs from the core's selection");
            }
            else
            {
                var value = (byte*)Memory.Allocate(length + 1);
                value[0] = (byte)length;
                protocol.CopyTo(new Span<byte>(value + 1, length));
                State->NegotiatedAlpn = value;
            }
        }

        internal uint GetParameter(uint parameter, uint* length, void* buffer)
        {
            if (length == null)
                return Status.InvalidParameter;

            lock (Gate)
            {
                if (Disposed || ptls_handshake_is_complete(Tls) == 0)
                    return Status.InvalidState;

                if (parameter == QUIC_PARAM_TLS_HANDSHAKE_INFO)
                {
                    QUIC_HANDSHAKE_INFO layout = default;
                    var legacySize = checked((uint)((byte*)&layout.CipherSuite - (byte*)&layout + sizeof(QUIC_CIPHER_SUITE)));
                    if (*length < legacySize)
                    {
                        *length = (uint)sizeof(QUIC_HANDSHAKE_INFO);
                        return Status.BufferTooSmall;
                    }

                    if (buffer == null)
                        return Status.InvalidParameter;

                    var suite = ptls_get_cipher(Tls)->id;
                    var aes128 = suite == 0x1301;
                    var info = new QUIC_HANDSHAKE_INFO
                    {
                        TlsProtocolVersion = QUIC_TLS_PROTOCOL_VERSION.QUIC_TLS_PROTOCOL_1_3,
                        CipherAlgorithm = aes128 ? QUIC_CIPHER_ALGORITHM.QUIC_CIPHER_ALGORITHM_AES_128 : QUIC_CIPHER_ALGORITHM.QUIC_CIPHER_ALGORITHM_AES_256,
                        CipherStrength = aes128 ? 128 : 256,
                        Hash = aes128 ? QUIC_HASH_ALGORITHM.QUIC_HASH_ALGORITHM_SHA_256 : QUIC_HASH_ALGORITHM.QUIC_HASH_ALGORITHM_SHA_384,
                        HashStrength = aes128 ? 256 : 384,
                        KeyExchangeAlgorithm = QUIC_KEY_EXCHANGE_ALGORITHM.QUIC_KEY_EXCHANGE_ALGORITHM_NONE,
                        KeyExchangeStrength = 256,
                        CipherSuite = (QUIC_CIPHER_SUITE)suite,
                        TlsGroup = QUIC_TLS_GROUP.QUIC_TLS_GROUP_SECP256R1,
                    };
                    var written = *length >= sizeof(QUIC_HANDSHAKE_INFO) ? (uint)sizeof(QUIC_HANDSHAKE_INFO) : legacySize;
                    new ReadOnlySpan<byte>(&info, (int)written).CopyTo(new Span<byte>(buffer, (int)written));
                    *length = written;
                    return Status.Success;
                }

                if (parameter == QUIC_PARAM_TLS_NEGOTIATED_ALPN)
                {
                    var text = ptls_get_negotiated_protocol(Tls);
                    if (text == null)
                        return Status.InvalidState;

                    uint count = 0;
                    while (count < 256 && text[count] != 0)
                        count++;

                    if (count is 0 or 256)
                        return Status.InvalidState;

                    if (*length < count)
                    {
                        *length = count;
                        return Status.BufferTooSmall;
                    }

                    if (buffer == null)
                        return Status.InvalidParameter;

                    new ReadOnlySpan<byte>(text, (int)count).CopyTo(new Span<byte>(buffer, (int)count));
                    *length = count;
                    return Status.Success;
                }

                return Status.NotSupported;
            }
        }

        public void Dispose()
        {
            lock (Gate)
            {
                if (Disposed)
                    return;

                Disposed = true;
                using var scope = CallbackScope.Enter();
                try
                {
                    if (Tls != null)
                    {
                        ptls_free(Tls);
                        Tls = null;
                    }
                }
                finally
                {
                    DisposePendingTickets();
                    Memory.Dispose();
                    Security.Dispose();
                }

                scope.ThrowIfFailed();
            }
        }
    }
}