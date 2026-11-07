using System;
using System.Collections.Generic;
using System.Linq;
using static Managed.Security.PicoTls;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace Managed.Security;

/// <summary>Immutable, shareable TLS 1.3 configuration. Disposal prevents new
/// connections; existing connections retain configuration and credential leases.</summary>
public sealed unsafe class PicotlsContext : IDisposable
{
    public const int MaximumOperationBytes = 8 * 1024 * 1024;
    private readonly Lock _gate = new Lock();
    private st_ptls_context_t* _native;
    private st_ptls_get_time_t* _clock;
    private st_ptls_save_ticket_t* _saveTicket;
    private HelloRegistration* _hello;
    private st_ptls_cipher_suite_t** _suites;
    private st_ptls_iovec_t* _protocols;
    private int _protocolCount;
    private IDisposable? _identityLease, _verifierLease, _ticketLease;
    private int _connections;
    private bool _disposed;

    internal bool EnforceRetry { get; }
    internal bool NegotiateBeforeKeyExchange { get; }
    internal bool SaveSessionTickets { get; }
    internal st_ptls_iovec_t* Protocols => _protocols;
    internal int ProtocolCount => _protocolCount;

    public bool IsServer { get; }

    [StructLayout(LayoutKind.Sequential)]
    private struct HelloRegistration
    {
        public st_ptls_on_client_hello_t Header;
        public nint Handle;
    }

    private sealed record HelloPolicy(byte[][] Protocols);

    private static readonly delegate*<void*, ulong, void> RandomPointer = &RandomBytes;
    private static readonly delegate*<st_ptls_get_time_t*, ulong> TimePointer = &TimeMilliseconds;
    private static readonly delegate*<st_ptls_on_client_hello_t*, st_ptls_t*, st_ptls_on_client_hello_parameters_t*, int> HelloPointer = &OnClientHello;

    public PicotlsContext(
        bool isServer,
        BclCryptoProvider.CertificateVerifier? verifier,
        BclCryptoProvider.SigningIdentity? identity = null,
        IEnumerable<string>? applicationProtocols = null,
        ushort? cipherSuite = null,
        bool requireClientAuthentication = false,
        int maximumHandshakeBuffer = 1024 * 1024,
        bool enforceRetry = false,
        bool negotiateBeforeKeyExchange = false,
        BclCryptoProvider.TicketProtector? ticketProtector = null,
        bool saveSessionTickets = false)
    {
        if (!isServer || requireClientAuthentication)
            ArgumentNullException.ThrowIfNull(verifier);
        if (isServer)
            ArgumentNullException.ThrowIfNull(identity);
        if (!isServer && requireClientAuthentication)
            throw new ArgumentException("Client authentication is a server policy.");
        if (!isServer && ticketProtector != null)
            throw new ArgumentException("Ticket protection is a server policy.");
        if (isServer && saveSessionTickets)
            throw new ArgumentException("Saving session tickets is a client policy.");
        if (maximumHandshakeBuffer is < 16384 or > MaximumOperationBytes)
            throw new ArgumentOutOfRangeException(nameof(maximumHandshakeBuffer));
        if (cipherSuite is not (null or 0x1301 or 0x1302))
            throw new ArgumentOutOfRangeException(nameof(cipherSuite));

        IsServer = isServer;
        EnforceRetry = enforceRetry;
        NegotiateBeforeKeyExchange = negotiateBeforeKeyExchange;
        SaveSessionTickets = saveSessionTickets;

        try
        {
            BclCryptoProvider.InitializeSymmetric();
            BclCryptoProvider.InitializeAsymmetric();
            var encoded = (applicationProtocols ?? ["dotcc-picotls"]).Select(EncodeProtocol).ToArray();
            if (encoded.Length is 0 or > 32)
                throw new ArgumentException("Specify between one and 32 ALPN protocols.");

            _native = (st_ptls_context_t*)Allocate(sizeof(st_ptls_context_t));
            _clock = (st_ptls_get_time_t*)Allocate(sizeof(st_ptls_get_time_t));
            _clock->cb = TimePointer;
            _native->get_time = _clock;
            _native->random_bytes = RandomPointer;
            _native->key_exchanges = BclCryptoProvider.AsymmetricKeyExchanges;

            if (cipherSuite is { } selected)
            {
                _suites = (st_ptls_cipher_suite_t**)Allocate(2 * sizeof(nint));
                var available = BclCryptoProvider.SymmetricCipherSuites;
                _suites[0] = available[0]->id == selected ? available[0] : available[1];
                _native->cipher_suites = _suites;
            }
            else
            {
                _native->cipher_suites = BclCryptoProvider.SymmetricCipherSuites;
            }

            _native->max_buffer_size = (ulong)maximumHandshakeBuffer;
            _native->use_exporter = 1;
            _native->require_dhe_on_psk = 1;
            _native->require_client_authentication = requireClientAuthentication ? 1u : 0u;
            // Zero-initialization leaves TLS 1.2, early data, compression and ECH disabled.
            _identityLease = identity?.RetainAndApply(_native);
            _verifierLease = verifier?.RetainAndApply(_native);
            _ticketLease = ticketProtector?.RetainAndApply(_native);

            if (saveSessionTickets)
            {
                _saveTicket = (st_ptls_save_ticket_t*)Allocate(sizeof(st_ptls_save_ticket_t));
                _saveTicket->cb = SavedSessionTicket.SaveTicketPointer;
                _native->save_ticket = _saveTicket;
            }

            _protocols = (st_ptls_iovec_t*)Allocate(encoded.Length * sizeof(st_ptls_iovec_t));
            foreach (var protocol in encoded)
            {
                var data = (byte*)Allocate(protocol.Length);
                protocol.CopyTo(new Span<byte>(data, protocol.Length));
                _protocols[_protocolCount++] = new st_ptls_iovec_t { @base = data, len = (ulong)protocol.Length };
            }

            if (isServer)
            {
                _hello = (HelloRegistration*)Allocate(sizeof(HelloRegistration));
                _hello->Handle = GCHandle.ToIntPtr(GCHandle.Alloc(new HelloPolicy(encoded)));
                _hello->Header.cb = HelloPointer;
                _native->on_client_hello = &_hello->Header;
            }
        }
        catch
        {
            Dispose(false);
            throw;
        }
    }

    private static byte[] EncodeProtocol(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length is 0 or > 255 || value.Any(c => c is '\0' or > '\x7f'))
            throw new ArgumentException("ALPN names must contain 1–255 nonzero ASCII bytes.");

        return Encoding.ASCII.GetBytes(value);
    }

    internal static void* Allocate(int size)
    {
        var result = Libc.malloc(Math.Max(size, 1));
        if (result == null)
            throw new OutOfMemoryException();

        new Span<byte>(result, Math.Max(size, 1)).Clear();
        return result;
    }

    internal st_ptls_context_t* Acquire()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            checked { _connections++; }

            return _native;
        }
    }

    internal void Release()
    {
        lock (_gate)
        {
            if (--_connections == 0 && _disposed)
                Free(true);
        }
    }

    internal bool OffersProtocol(string value)
    {
        if (value.Any(c => c > '\x7f'))
            return false;

        var encoded = Encoding.ASCII.GetBytes(value);
        for (var i = 0; i < _protocolCount; i++)
        {
            if (_protocols[i].len == (ulong)encoded.Length && encoded.AsSpan().SequenceEqual(new ReadOnlySpan<byte>(_protocols[i].@base, encoded.Length)))
                return true;
        }

        return false;
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    private void Dispose(bool isDisposing)
    {
        if (!isDisposing)
        {
            Free(false);
            return;
        }

        lock (_gate)
        {
            if (_disposed) return;

            _disposed = true;
            if (_connections == 0)
                Free(true);
        }
    }

    ~PicotlsContext()
    {
        Dispose(false);
    }

    private void Free(bool isDisposing)
    {
        Libc.free(_native);
        _native = null;

        Libc.free(_clock);
        _clock = null;

        Libc.free(_saveTicket);
        _saveTicket = null;

        Libc.free(_suites);
        _suites = null;

        if (_hello != null)
        {
            if (_hello->Handle != 0)
                GCHandle.FromIntPtr(_hello->Handle).Free();

            Libc.free(_hello);
            _hello = null;
        }

        for (var i = 0; i < _protocolCount; i++)
            Libc.free(_protocols[i].@base);

        Libc.free(_protocols);
        _protocols = null;
        _protocolCount = 0;

        if (!isDisposing)
            return;

        try
        {
            _identityLease?.Dispose();
        }
        finally
        {
            _identityLease = null;

            try
            {
                _verifierLease?.Dispose();
            }
            finally
            {
                _verifierLease = null;
                _ticketLease?.Dispose();
                _ticketLease = null;
            }
        }
    }

    private static void RandomBytes(void* output, ulong length)
    {
        try
        {
            CallbackScope.RequireActive();
            if (CallbackScope.HasFailure)
                return;

            if (length > MaximumOperationBytes || (output == null && length != 0))
                throw new ArgumentOutOfRangeException(nameof(length));

            RandomNumberGenerator.Fill(new Span<byte>(output, (int)length));
        }
        catch (Exception error)
        {
            CallbackScope.Capture(error);
        }
    }

    private static ulong TimeMilliseconds(st_ptls_get_time_t* self)
    {
        try
        {
            CallbackScope.RequireActive();
            return checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        }
        catch (Exception error)
        {
            CallbackScope.Capture(error);
            return 0;
        }
    }

    private static int OnClientHello(st_ptls_on_client_hello_t* self, st_ptls_t* tls, st_ptls_on_client_hello_parameters_t* input)
    {
        try
        {
            CallbackScope.RequireActive();
            if (CallbackScope.HasFailure)
                return PTLS_ERROR_LIBRARY;
            if (input == null || input->negotiated_protocols.count > 256)
                return PTLS_ALERT_ILLEGAL_PARAMETER;
            if (input->negotiated_protocols.count != 0 && input->negotiated_protocols.list == null)
                return PTLS_ALERT_ILLEGAL_PARAMETER;
            if (input->server_name.len > 255)
                return PTLS_ALERT_ILLEGAL_PARAMETER;

            if (input->server_name.len != 0)
            {
                if (input->server_name.@base == null || new ReadOnlySpan<byte>(input->server_name.@base, (int)input->server_name.len).Contains((byte)0))
                    return PTLS_ALERT_ILLEGAL_PARAMETER;

                var result = ptls_set_server_name(tls, input->server_name.@base, input->server_name.len);
                if (result != 0) return result;
            }

            var policy = (HelloPolicy)GCHandle.FromIntPtr(((HelloRegistration*)self)->Handle).Target!;
            foreach (var protocol in policy.Protocols)
            {
                for (ulong i = 0; i < input->negotiated_protocols.count; i++)
                {
                    var offered = input->negotiated_protocols.list[i];
                    if (offered.len == (ulong)protocol.Length && offered.@base != null && protocol.AsSpan().SequenceEqual(new ReadOnlySpan<byte>(offered.@base, protocol.Length)))
                    {
                        fixed (byte* selected = protocol)
                            return ptls_set_negotiated_protocol(tls, selected, (ulong)protocol.Length);
                    }
                }
            }

            return PTLS_ALERT_NO_APPLICATION_PROTOCOL; // no_application_protocol; every facade connection requires ALPN.
        }
        catch (Exception error)
        {
            CallbackScope.Capture(error);
            return error is OutOfMemoryException ? PTLS_ERROR_NO_MEMORY : PTLS_ERROR_LIBRARY;
        }
    }
}