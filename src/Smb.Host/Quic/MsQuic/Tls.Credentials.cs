using System;
using System.Collections.Generic;
using System.Linq;
using static Managed.Transport.MsQuic;
using static Managed.Security.PicoTls;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using Managed.Security;
using PicLibc = Managed.Security.PicoTls.Libc;

namespace Managed.Transport.Hosting;

public sealed unsafe partial class MsQuicHost
{
    // Explicit managed ABI extensions; neither value impersonates a native provider.
    internal const int PicotlsProviderIdentity = 0x10000;
    internal const int ManagedCredentialType = 0x10000;

    internal sealed class CredentialRegistration : IDisposable
    {
        private readonly MsQuicHost _host;

        internal readonly object Gate = new object();
        internal nint Token;
        internal readonly bool Server;
        internal readonly ushort CipherSuite;

        internal CredentialRegistration(MsQuicHost host, TlsCredentials owner)
        {
            _host = host;
            Server = owner.Server;
            CipherSuite = owner.CipherSuite;

            try
            {
                Token = (nint)host.AddResource(owner);
            }
            catch
            {
                owner.Dispose();
                throw;
            }
        }

        public void Dispose()
        {
            lock (Gate)
            {
                if (Token == 0)
                    return;

                _host.ReleaseResource<TlsCredentials>((void*)Token);
                Token = 0;
            }
        }

        internal bool BelongsTo(MsQuicHost candidate) => ReferenceEquals(_host, candidate);
    }

    internal sealed class TlsCredentials : IDisposable
    {
        private readonly Lock _gate = new Lock();
        private int _references = 1;

        internal readonly bool Server;
        internal readonly bool ApplicationValidation;
        internal readonly ushort CipherSuite;
        internal readonly BclCryptoProvider.SigningIdentity? Identity;
        internal readonly BclCryptoProvider.CertificateVerifier? Verifier;

        internal TlsCredentials(bool server, ushort cipherSuite, BclCryptoProvider.SigningIdentity? identity, BclCryptoProvider.CertificateVerifier? verifier, bool applicationValidation = false)
        {
            Server = server;
            CipherSuite = cipherSuite;
            Identity = identity;
            Verifier = verifier;
            ApplicationValidation = applicationValidation;
        }

        internal void Retain()
        {
            lock (_gate)
            {
                if (_references == 0)
                    throw new ObjectDisposedException(nameof(TlsCredentials));

                _references = checked(_references + 1);
            }
        }

        public void Dispose()
        {
            lock (_gate)
            {
                if (_references <= 0)
                    FatalInvariant("TLS credential lease released twice");
                if (--_references != 0)
                    return;

                Identity?.Dispose();
                Verifier?.Dispose();
            }
        }
    }

    internal CredentialRegistration CreateClientCredential(IEnumerable<X509Certificate2> trustedRoots, ushort cipherSuite = 0, X509RevocationMode revocationMode = X509RevocationMode.NoCheck)
    {
        ValidateTlsSuite(cipherSuite);
        ArgumentNullException.ThrowIfNull(trustedRoots);

        var roots = trustedRoots.ToArray();
        if (roots.Length == 0)
            throw new ArgumentException("At least one explicit trust root is required", nameof(trustedRoots));

        var verifier = new BclCryptoProvider.CertificateVerifier(roots, revocationMode);
        try
        {
            return new CredentialRegistration(this, new TlsCredentials(false, cipherSuite, null, verifier));
        }
        catch
        {
            verifier.Dispose();
            throw;
        }
    }

    internal CredentialRegistration CreateServerCredential(X509Certificate2 leaf, IEnumerable<X509Certificate2>? intermediates = null, ushort cipherSuite = 0)
    {
        ValidateTlsSuite(cipherSuite);
        ArgumentNullException.ThrowIfNull(leaf);

        var identity = new BclCryptoProvider.SigningIdentity(leaf, intermediates);
        try
        {
            return new CredentialRegistration(this, new TlsCredentials(true, cipherSuite, identity, null));
        }
        catch
        {
            identity.Dispose();
            throw;
        }
    }

    // The facade owns trust/name validation and may override policy errors in its callback.
    // TLS signature verification remains in the provider, including for client identities.
    internal CredentialRegistration CreateApplicationCredential(bool server, X509Certificate2? leaf, IEnumerable<X509Certificate2>? intermediates = null)
    {
        if (server)
            ArgumentNullException.ThrowIfNull(leaf);

        BclCryptoProvider.SigningIdentity? identity = null;
        BclCryptoProvider.CertificateVerifier? verifier = null;
        try
        {
            if (leaf != null)
                identity = new BclCryptoProvider.SigningIdentity(leaf, intermediates);
            verifier = BclCryptoProvider.CertificateVerifier.CreateForApplicationValidation();
            return new CredentialRegistration(this, new TlsCredentials(server, 0, identity, verifier, true));
        }
        catch
        {
            identity?.Dispose();
            verifier?.Dispose();
            throw;
        }
    }

    private static void ValidateTlsSuite(ushort cipherSuite)
    {
        if (cipherSuite is not (0 or 0x1301 or 0x1302))
            throw new ArgumentOutOfRangeException(nameof(cipherSuite));
    }

    internal uint LoadCredential(QUIC_HANDLE* configuration, CredentialRegistration credential) => LoadCredential(configuration, credential, 0, null);

    internal uint LoadCredential(QUIC_HANDLE* configuration, CredentialRegistration credential, QUIC_CREDENTIAL_FLAGS additionalFlags, delegate*<QUIC_HANDLE*, void*, uint, void> asyncHandler, uint? allowedCipherSuites = null)
    {
        ArgumentNullException.ThrowIfNull(credential);
        if (!credential.BelongsTo(this))
            throw new ArgumentException("Credential belongs to another host", nameof(credential));

        lock (credential.Gate)
        {
            ObjectDisposedException.ThrowIf(credential.Token == 0, credential);
            QUIC_CREDENTIAL_CONFIG config = default;
            config.Type = (QUIC_CREDENTIAL_TYPE)ManagedCredentialType;
            config.Flags = (QUIC_CREDENTIAL_FLAGS)(0x2000 | (credential.Server ? 0 : 1)) | additionalFlags;
            config.AsyncHandler = asyncHandler;
            config.CertificateContext = (void*)credential.Token;
            config.AllowedCipherSuites = (QUIC_ALLOWED_CIPHER_SUITE_FLAGS)(allowedCipherSuites ?? credential.CipherSuite switch
            {
                0x1301 => 1u, 0x1302 => 2u, _ => 3u,
            });
            return MsQuicConfigurationLoadCredential(configuration, &config);
        }
    }

    private sealed class TlsMemory : IDisposable
    {
        private readonly List<(nint Pointer, int Size)> _blocks = [];

        internal void* Allocate(int size)
        {
            if (size < 0)
                throw new ArgumentOutOfRangeException(nameof(size));

            var pointer = PicLibc.malloc(Math.Max(1, size));
            if (pointer == null)
                throw new OutOfMemoryException();

            new Span<byte>(pointer, Math.Max(1, size)).Clear();
            try
            {
                _blocks.Add(((nint)pointer, Math.Max(1, size)));
                return pointer;
            }
            catch
            {
                PicLibc.free(pointer);
                throw;
            }
        }

        internal byte* Copy(ReadOnlySpan<byte> value)
        {
            var result = (byte*)Allocate(value.Length);
            value.CopyTo(new Span<byte>(result, value.Length));
            return result;
        }

        public void Dispose()
        {
            foreach (var block in _blocks)
            {
                new Span<byte>((void*)block.Pointer, block.Size).Clear();
                PicLibc.free((void*)block.Pointer);
            }

            _blocks.Clear();
        }
    }

    private sealed class TlsSecurityConfig : IDisposable
    {
        private readonly Lock _gate = new Lock();
        private int _references = 1;

        internal readonly TlsCredentials Credentials;
        internal readonly TlsMemory Memory = new TlsMemory();
        internal readonly CXPLAT_TLS_CALLBACKS Callbacks;
        internal readonly st_ptls_context_t* Context;
        internal readonly BclCryptoProvider.TicketProtector? Tickets;
        internal readonly bool ResumptionEnabled;
        internal readonly uint CredentialFlags;

        internal TlsSecurityConfig(TlsCredentials credentials, CXPLAT_TLS_CALLBACKS callbacks, bool resumptionEnabled, uint allowedSuites, uint credentialFlags)
        {
            Credentials = credentials;
            Callbacks = callbacks;
            CredentialFlags = credentialFlags;
            credentials.Retain();

            try
            {
                using var scope = CallbackScope.Enter();
                BclCryptoProvider.InitializeSymmetric();
                BclCryptoProvider.InitializeAsymmetric();

                Context = (st_ptls_context_t*)Memory.Allocate(sizeof(st_ptls_context_t));
                Context->random_bytes = &TlsRandom;
                Context->get_time = (st_ptls_get_time_t*)Memory.Allocate(sizeof(st_ptls_get_time_t));
                Context->get_time->cb = &TlsTime;
                Context->key_exchanges = BclCryptoProvider.AsymmetricKeyExchanges;

                var suites = (st_ptls_cipher_suite_t**)Memory.Allocate(3 * sizeof(nint));
                var count = 0;
                for (var i = 0; BclCryptoProvider.SymmetricCipherSuites[i] != null; i++)
                {
                    var suite = BclCryptoProvider.SymmetricCipherSuites[i];
                    var bit = suite->id == 0x1301 ? 1u : suite->id == 0x1302 ? 2u : 0u;
                    if ((allowedSuites & bit) != 0 && (credentials.CipherSuite == 0 || credentials.CipherSuite == suite->id))
                        suites[count++] = suite;
                }

                if (count == 0)
                    throw new ArgumentException("No allowed TLS cipher suite");

                Context->cipher_suites = suites;
                Context->max_buffer_size = 1024 * 1024;
                Context->require_dhe_on_psk = 1;
                Context->require_client_authentication = (credentialFlags & 0x40) != 0 ? 1u : 0u;
                Context->omit_end_of_early_data = 1;
                Context->send_change_cipher_spec = 0;
                Context->max_early_data_size = 0;
                Context->update_traffic_key = (st_ptls_update_traffic_key_t*)Memory.Allocate(sizeof(st_ptls_update_traffic_key_t));
                Context->update_traffic_key->cb = &TlsTrafficKey;

                credentials.Identity?.ApplyTo(Context);
                credentials.Verifier?.ApplyTo(Context);

                if ((credentialFlags & 0x10) != 0)
                {
                    var verifier = (st_ptls_verify_certificate_t*)Memory.Allocate(sizeof(st_ptls_verify_certificate_t));
                    *verifier = *credentials.Verifier!.Callback;
                    verifier->cb = &TlsVerifyCertificate;
                    Context->verify_certificate = verifier;
                }

                ResumptionEnabled = resumptionEnabled;
                if (credentials.Server)
                {
                    Context->on_client_hello = (st_ptls_on_client_hello_t*)Memory.Allocate(sizeof(st_ptls_on_client_hello_t));
                    Context->on_client_hello->cb = &TlsClientHello;
                    if (resumptionEnabled)
                    {
                        Tickets = new BclCryptoProvider.TicketProtector(TimeSpan.FromHours(1));
                        Tickets.ApplyTo(Context);
                        ConfigureServerTickets(this);
                    }
                }
                else
                {
                    Context->save_ticket = (st_ptls_save_ticket_t*)Memory.Allocate(sizeof(st_ptls_save_ticket_t));
                    Context->save_ticket->cb = &TlsSaveTicket;
                }

                scope.ThrowIfFailed();
            }
            catch
            {
                Tickets?.Dispose();
                Memory.Dispose();
                credentials.Dispose();
                throw;
            }
        }

        internal void Retain()
        {
            lock (_gate)
            {
                if (_references == 0)
                    throw new ObjectDisposedException(nameof(TlsSecurityConfig));

                _references = checked(_references + 1);
            }
        }

        public void Dispose()
        {
            lock (_gate)
            {
                if (_references <= 0)
                    FatalInvariant("TLS configuration lease released twice");

                if (--_references != 0)
                    return;

                Tickets?.Dispose();
                Memory.Dispose();
                Credentials.Dispose();
            }
        }
    }
}