using System;
using System.Collections.Generic;
using System.Linq;
using static Managed.Security.PicoTls;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace Managed.Security;

public static unsafe partial class BclCryptoProvider
{
    public const int MaximumCertificateBytes = 1024 * 1024;

    [StructLayout(LayoutKind.Sequential)]
    private struct ExchangeContext
    {
        public st_ptls_key_exchange_context_t Header;
        public nint Handle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SignContext
    {
        public st_ptls_sign_certificate_t Header;
        public nint Handle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct VerifyContext
    {
        public st_ptls_verify_certificate_t Header;
        public nint Handle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct AsymmetricTables
    {
        public st_ptls_key_exchange_algorithm_t P256;
        public st_ptls_key_exchange_algorithm_t* First;
        public st_ptls_key_exchange_algorithm_t* End;
        public ushort Ecdsa, Rsa, SignatureEnd;
    }

    private static readonly Lock AsymmetricGate = new Lock();
    private static AsymmetricTables* _asymmetric;
    private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

    public static st_ptls_key_exchange_algorithm_t* P256KeyExchange
    {
        get
        {
            InitializeAsymmetric();
            return &_asymmetric->P256;
        }
    }

    public static st_ptls_key_exchange_algorithm_t** AsymmetricKeyExchanges
    {
        get
        {
            InitializeAsymmetric();
            return &_asymmetric->First;
        }
    }

    private static readonly delegate*<st_ptls_key_exchange_algorithm_t*, st_ptls_key_exchange_context_t**, int> ExchangeCreatePointer = &ExchangeCreate;
    private static readonly delegate*<st_ptls_key_exchange_context_t**, int, st_ptls_iovec_t*, st_ptls_iovec_t, int> ExchangeCompletePointer = &ExchangeComplete;
    private static readonly delegate*<st_ptls_key_exchange_algorithm_t*, st_ptls_iovec_t*, st_ptls_iovec_t*, st_ptls_iovec_t, int> ExchangeSyncPointer = &ExchangeSync;
    private static readonly delegate*<st_ptls_sign_certificate_t*, st_ptls_t*, st_ptls_async_job_t**, ushort*, st_ptls_buffer_t*, st_ptls_iovec_t, ushort*, ulong, int> SignPointer = &SignCertificate;
    private static readonly delegate*<st_ptls_verify_certificate_t*, st_ptls_t*, byte*, delegate*<void*, ushort, st_ptls_iovec_t, st_ptls_iovec_t, int>*, void**, st_ptls_iovec_t*, ulong, int> VerifyCertificatePointer = &VerifyCertificate;
    private static readonly delegate*<void*, ushort, st_ptls_iovec_t, st_ptls_iovec_t, int> VerifySignaturePointer = &VerifySignature;

    public static void InitializeAsymmetric()
    {
        lock (AsymmetricGate)
        {
            if (_asymmetric != null)
                return;

            using var probe = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            using var peer = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            var secret = probe.DeriveRawSecretAgreement(peer.PublicKey);
            AsymmetricTables* table = null;
            try
            {
                if (secret.Length != 32)
                    throw new PlatformNotSupportedException("P-256 requires a 32-byte raw secret.");

                table = (AsymmetricTables*)AllocateZeroed(sizeof(AsymmetricTables));
                table->P256.id = 23;
                table->P256.name = Libc.L("secp256r1\0"u8);
                table->P256.create = ExchangeCreatePointer;
                table->P256.exchange = ExchangeSyncPointer;
                table->First = &table->P256;
                table->Ecdsa = PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256;
                table->Rsa = PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256;
                table->SignatureEnd = ushort.MaxValue;
                _asymmetric = table;
                table = null;
            }
            finally
            {
                Libc.free(table);
                CryptographicOperations.ZeroMemory(secret);
            }
        }
    }

    private sealed class ExchangeState(ECDiffieHellman key) : IDisposable
    {
        public ECDiffieHellman Key { get; } = key;
        public void Dispose() => Key.Dispose();
    }

    private static st_ptls_iovec_t CopyBytes(ReadOnlySpan<byte> bytes)
    {
        var storage = (byte*)AllocateZeroed(Math.Max(1, bytes.Length));
        bytes.CopyTo(new Span<byte>(storage, bytes.Length));
        return new st_ptls_iovec_t { @base = storage, len = (ulong)bytes.Length };
    }

    private static byte[] EncodePoint(ECDiffieHellman key)
    {
        var parameters = key.ExportParameters(false);
        if (parameters.Q.X?.Length != 32 || parameters.Q.Y?.Length != 32)
            throw new CryptographicException("Invalid P-256 coordinate widths.");

        var output = new byte[65];
        output[0] = 4;
        parameters.Q.X.CopyTo(output, 1);
        parameters.Q.Y.CopyTo(output, 33);
        return output;
    }

    private static ECDiffieHellman ImportPoint(st_ptls_iovec_t point)
    {
        if (point.len != 65 || point.@base == null || point.@base[0] != 4)
            throw new CryptographicException("P-256 requires an uncompressed 65-byte SEC1 point.");

        var bytes = ReadBytes(point.@base, point.len, 65);
        return ECDiffieHellman.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = bytes.Slice(1, 32).ToArray(), Y = bytes.Slice(33, 32).ToArray() }
        });
    }

    private static void ReleaseExchange(ExchangeContext* context)
    {
        if (context == null) return;

        try
        {
            ReleaseState(ref context->Handle);
        }
        catch (Exception error)
        {
            CallbackScope.Capture(error);
        }
        finally
        {
            Libc.free(context->Header.pubkey.@base);
            Libc.free(context);
        }
    }

    private static int ExchangeCreate(st_ptls_key_exchange_algorithm_t* algorithm, st_ptls_key_exchange_context_t** output)
    {
        ExchangeContext* context = null;
        ECDiffieHellman? key = null;
        try
        {
            if (output == null || algorithm == null || algorithm->id != 23)
                return PTLS_ALERT_ILLEGAL_PARAMETER;

            *output = null;
            if (!BeginCallback())
                return PTLS_ERROR_LIBRARY;

            key = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            context = (ExchangeContext*)AllocateZeroed(sizeof(ExchangeContext));
            context->Handle = OwnState(new ExchangeState(key));
            key = null;
            context->Header.algo = algorithm;
            context->Header.on_exchange = ExchangeCompletePointer;
            context->Header.pubkey = CopyBytes(EncodePoint(State<ExchangeState>(context->Handle).Key));
            *output = &context->Header;
            context = null;
            return 0;
        }
        catch (Exception error)
        {
            return SetupError(error);
        }
        finally
        {
            try
            {
                if (key != null) DisposeState(key);
            }
            catch (Exception error)
            {
                CallbackScope.Capture(error);
            }

            ReleaseExchange(context);
        }
    }

    private static int ExchangeComplete(st_ptls_key_exchange_context_t** keyex, int release, st_ptls_iovec_t* secret, st_ptls_iovec_t peerkey)
    {
        var context = keyex == null ? null : (ExchangeContext*)*keyex;
        byte[]? derived = null;
        try
        {
            if (context == null)
                return PTLS_ALERT_ILLEGAL_PARAMETER;
            if (secret == null)
                return 0; // Cleanup-only invocation; no peer key required.

            *secret = default;
            if (!BeginCallback())
                return PTLS_ERROR_LIBRARY;

            using var peer = ImportPoint(peerkey);
            derived = State<ExchangeState>(context->Handle).Key.DeriveRawSecretAgreement(peer.PublicKey);
            if (derived.Length != 32)
                throw new CryptographicException("Unexpected raw P-256 secret width.");

            *secret = CopyBytes(derived);
            return 0;
        }
        catch (CryptographicException)
        {
            return PTLS_ALERT_ILLEGAL_PARAMETER;
        }
        catch (Exception error)
        {
            return SetupError(error);
        }
        finally
        {
            if (derived != null)
                CryptographicOperations.ZeroMemory(derived);

            if (release != 0 && keyex != null)
            {
                *keyex = null;
                ReleaseExchange(context);
            }
        }
    }

    private static int ExchangeSync(st_ptls_key_exchange_algorithm_t* algorithm, st_ptls_iovec_t* publicKey, st_ptls_iovec_t* secret, st_ptls_iovec_t peerkey)
    {
        st_ptls_key_exchange_context_t* context = null;
        st_ptls_iovec_t resultSecret = default, resultPublic = default;
        try
        {
            if (publicKey == null || secret == null)
                return PTLS_ALERT_ILLEGAL_PARAMETER;

            *publicKey = default;
            *secret = default;
            var result = ExchangeCreate(algorithm, &context);
            if (result != 0)
                return result;

            result = ExchangeComplete(&context, 0, &resultSecret, peerkey);
            if (result != 0)
                return result;

            resultPublic = CopyBytes(ReadBytes(context->pubkey.@base, context->pubkey.len, 65));
            *publicKey = resultPublic;
            *secret = resultSecret;
            resultPublic = default;
            resultSecret = default;
            return 0;
        }
        catch (Exception error)
        {
            return SetupError(error);
        }
        finally
        {
            if (resultSecret.@base != null)
            {
                WriteBytes(resultSecret.@base, resultSecret.len).Clear();
                Libc.free(resultSecret.@base);
            }

            Libc.free(resultPublic.@base);
            ReleaseExchange((ExchangeContext*)context);
        }
    }

    private sealed class SigningState : IDisposable
    {
        public readonly object Gate = new object();
        public readonly ECDsa? Ec;
        public readonly RSA? Rsa;
        public ushort Algorithm => (ushort)(Ec != null ? PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256 : PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256);

        public SigningState(X509Certificate2 certificate)
        {
            RequireDigitalSignature(certificate);
            if (certificate.PublicKey.Oid.Value == "1.2.840.10045.2.1")
            {
                Ec = certificate.GetECDsaPrivateKey() ?? throw new ArgumentException("Certificate has no ECDSA private key.");
                try
                {
                    RequireP256(Ec);
                }
                catch
                {
                    Ec.Dispose();
                    throw;
                }
            }
            else if (certificate.PublicKey.Oid.Value == "1.2.840.113549.1.1.1")
            {
                Rsa = certificate.GetRSAPrivateKey() ?? throw new ArgumentException("Certificate has no RSA private key.");
                if (Rsa.KeySize < 2048)
                {
                    Rsa.Dispose();
                    throw new ArgumentException("RSA authentication requires at least 2048 bits.");
                }
            }
            else
            {
                throw new ArgumentException("Only P-256 ECDSA and rsaEncryption RSA-PSS/SHA-256 identities are supported.");
            }
        }

        public void Dispose()
        {
            Ec?.Dispose();
            Rsa?.Dispose();
        }
    }

    private static void RequireP256(ECDsa key)
    {
        if (key.KeySize != 256 || key.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7")
            throw new CryptographicException("ECDSA authentication requires named P-256.");
    }

    private static void RequireDigitalSignature(X509Certificate2 certificate)
    {
        foreach (var extension in certificate.Extensions)
        {
            if (extension.Oid?.Value == "2.5.29.15")
            {
                var usage = extension as X509KeyUsageExtension ?? new X509KeyUsageExtension(extension, extension.Critical);
                if ((usage.KeyUsages & X509KeyUsageFlags.DigitalSignature) == 0)
                    throw new CryptographicException("TLS certificate KeyUsage must permit digital signatures when present.");
            }
        }
    }

    /// <summary>Owns a signing callback, leaf key, and stable certificate chain.
    /// Retain it until every referring context/connection has been destroyed.</summary>
    public sealed class SigningIdentity : IDisposable
    {
        private readonly Lock _lifetimeGate = new Lock();
        private int _leases;
        private bool _disposeRequested;
        private SignContext* _context;
        private st_ptls_iovec_t* _chain;
        private int _chainCount;

        public SigningIdentity(X509Certificate2 leaf, IEnumerable<X509Certificate2>? intermediates = null)
        {
            ArgumentNullException.ThrowIfNull(leaf);
            SigningState? state = null;
            try
            {
                var certificates = new List<byte[]> { leaf.RawData };
                if (intermediates != null)
                {
                    foreach (var certificate in intermediates)
                    {
                        if (certificates.Count >= PTLS_MAX_CERTS_IN_CONTEXT) throw new ArgumentException("Certificate chain is too long.");

                        certificates.Add(certificate.RawData);
                    }
                }

                if (certificates.Sum(certificate => (long)certificate.Length) > MaximumCertificateBytes)
                    throw new ArgumentException("Certificate chain exceeds the size limit.");

                state = new SigningState(leaf);
                _context = (SignContext*)AllocateZeroed(sizeof(SignContext));
                _context->Handle = OwnState(state);
                state = null;
                _context->Header.cb = SignPointer;
                _chain = (st_ptls_iovec_t*)AllocateZeroed(checked(certificates.Count * sizeof(st_ptls_iovec_t)));

                foreach (var certificate in certificates)
                    _chain[_chainCount++] = CopyBytes(certificate);
            }
            catch
            {
                if (state != null)
                    DisposeState(state);
                Dispose(false);
                throw;
            }
        }

        public st_ptls_sign_certificate_t* Callback => _context != null ? &_context->Header : throw new ObjectDisposedException(nameof(SigningIdentity));

        public void ApplyTo(st_ptls_context_t* target)
        {
            if (target == null)
                throw new ArgumentNullException(nameof(target));

            target->sign_certificate = Callback;
            target->certificates.list = _chain;
            target->certificates.count = (ulong)_chainCount;
        }

        internal IDisposable RetainAndApply(st_ptls_context_t* target)
        {
            lock (_lifetimeGate)
            {
                ObjectDisposedException.ThrowIf(_disposeRequested, this);
                var lease = new ProviderLease(ReleaseLease);
                ApplyTo(target);
                _leases++;
                return lease;
            }
        }

        private void ReleaseLease()
        {
            lock (_lifetimeGate)
            {
                if (--_leases == 0 && _disposeRequested)
                    Free();
            }
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
                Free();
                return;
            }

            lock (_lifetimeGate)
            {
                if (_disposeRequested)
                    return;

                _disposeRequested = true;
                if (_leases == 0)
                    Free();
            }
        }

        ~SigningIdentity()
        {
            Dispose(false);
        }

        private void Free()
        {
            var previous = _context;
            _context = null;
            try
            {
                if (previous != null)
                    ReleaseState(ref previous->Handle);
            }
            finally
            {
                Libc.free(previous);
                for (var i = 0; i < _chainCount; i++)
                    Libc.free(_chain[i].@base);
                Libc.free(_chain);
                _chain = null;
                _chainCount = 0;
            }
        }
    }

    private static int SignCertificate(st_ptls_sign_certificate_t* self, st_ptls_t* tls, st_ptls_async_job_t** async, ushort* selected, st_ptls_buffer_t* output, st_ptls_iovec_t input, ushort* algorithms, ulong count)
    {
        byte[]? signature = null;
        try
        {
            if (!BeginCallback())
                return PTLS_ERROR_LIBRARY;
            if (self == null || selected == null || output == null || (algorithms == null && count != 0))
                return PTLS_ALERT_ILLEGAL_PARAMETER;
            if (async != null && *async != null)
                return PTLS_ERROR_LIBRARY; // This provider performs synchronous signing only.

            var length = CheckedLength(count, 32767);
            var state = State<SigningState>(((SignContext*)self)->Handle);
            var offered = false;
            for (var i = 0; i < length; i++)
            {
                if (algorithms[i] == state.Algorithm)
                {
                    offered = true;
                    break;
                }
            }

            if (!offered) return PTLS_ALERT_HANDSHAKE_FAILURE;

            var bytes = ReadBytes(input.@base, input.len);
            lock (state.Gate)
                signature = state.Ec != null ? state.Ec.SignData(bytes, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence) : state.Rsa!.SignData(bytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

            fixed (byte* data = signature)
            {
                var result = ptls_buffer__do_pushv(output, data, (ulong)signature.Length);
                if (result == 0)
                    *selected = state.Algorithm;

                return result;
            }
        }
        catch (Exception error)
        {
            return SetupError(error);
        }
        finally
        {
            if (signature != null)
                CryptographicOperations.ZeroMemory(signature);
        }
    }

    private sealed class VerificationPolicy : IDisposable
    {
        public readonly X509Certificate2Collection Roots = new X509Certificate2Collection();
        public readonly X509RevocationMode RevocationMode;
        public readonly bool AllowWildcards;

        public VerificationPolicy(IEnumerable<X509Certificate2> roots, X509RevocationMode revocationMode, bool allowWildcards)
        {
            if (revocationMode is not (X509RevocationMode.NoCheck or X509RevocationMode.Offline or X509RevocationMode.Online))
                throw new ArgumentOutOfRangeException(nameof(revocationMode));

            RevocationMode = revocationMode;
            AllowWildcards = allowWildcards;
            try
            {
                foreach (var root in roots)
                    Roots.Add(X509CertificateLoader.LoadCertificate(root.RawData));

                if (Roots.Count == 0)
                    throw new ArgumentException("At least one explicit trust root is required.");
            }
            catch
            {
                Dispose();
                throw;
            }
        }

        public void Dispose()
        {
            foreach (var certificate in Roots) certificate.Dispose();
            Roots.Clear();
        }
    }

    /// <summary>Owns an explicit certificate trust/revocation policy and callback.
    /// The caller must retain it for all referring connections. The public constructor enforces its trust policy.</summary>
    /// <remarks>Managed host adapters can delegate trust decisions to their application while retaining signature verification.</remarks>
    public sealed class CertificateVerifier : IDisposable
    {
        private readonly Lock _lifetimeGate = new Lock();
        private int _leases;
        private bool _disposeRequested;
        private VerifyContext* _context;

        public CertificateVerifier(IEnumerable<X509Certificate2> trustedRoots, X509RevocationMode revocationMode, bool allowWildcards = true)
        {
            ArgumentNullException.ThrowIfNull(trustedRoots);
            InitializeAsymmetric();
            VerificationPolicy? policy = null;
            try
            {
                policy = new VerificationPolicy(trustedRoots, revocationMode, allowWildcards);
                _context = (VerifyContext*)AllocateZeroed(sizeof(VerifyContext));
                _context->Handle = OwnState(policy);
                policy = null;
                _context->Header.cb = VerifyCertificatePointer;
                _context->Header.algos = &_asymmetric->Ecdsa;
            }
            catch
            {
                if (policy != null) DisposeState(policy);
                Dispose(false);
                throw;
            }
        }

        // Only host adapters that enforce application certificate approval may use this.
        // CertificateVerify is still cryptographically verified by VerifySignature.
        internal static CertificateVerifier CreateForApplicationValidation() => new CertificateVerifier();

        private CertificateVerifier()
        {
            InitializeAsymmetric();
            _context = (VerifyContext*)AllocateZeroed(sizeof(VerifyContext));
            _context->Header.cb = VerifyCertificatePointer;
            _context->Header.algos = &_asymmetric->Ecdsa;
        }

        public st_ptls_verify_certificate_t* Callback => _context != null ? &_context->Header : throw new ObjectDisposedException(nameof(CertificateVerifier));

        public void ApplyTo(st_ptls_context_t* target)
        {
            if (target == null)
                throw new ArgumentNullException(nameof(target));

            target->verify_certificate = Callback;
        }

        internal IDisposable RetainAndApply(st_ptls_context_t* target)
        {
            lock (_lifetimeGate)
            {
                ObjectDisposedException.ThrowIf(_disposeRequested, this);
                var lease = new ProviderLease(ReleaseLease);
                ApplyTo(target);
                _leases++;
                return lease;
            }
        }

        private void ReleaseLease()
        {
            lock (_lifetimeGate)
            {
                if (--_leases == 0 && _disposeRequested)
                    Free();
            }
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
                Free();
                return;
            }

            lock (_lifetimeGate)
            {
                if (_disposeRequested) return;

                _disposeRequested = true;
                if (_leases == 0)
                    Free();
            }
        }

        ~CertificateVerifier()
        {
            Dispose(false);
        }

        private void Free()
        {
            var previous = _context;
            _context = null;
            try
            {
                if (previous != null)
                    ReleaseState(ref previous->Handle);
            }
            finally
            {
                Libc.free(previous);
            }
        }
    }

    private sealed class ProviderLease(Action release) : IDisposable
    {
        private Action? _callback = release;
        public void Dispose() => Interlocked.Exchange(ref _callback, null)?.Invoke();
    }

    private sealed class VerificationKey : IDisposable
    {
        public readonly ECDsa? Ec;
        public readonly RSA? Rsa;
        public ushort Algorithm => (ushort)(Ec != null ? PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256 : PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256);

        public VerificationKey(X509Certificate2 leaf)
        {
            if (leaf.PublicKey.Oid.Value == "1.2.840.10045.2.1")
            {
                Ec = leaf.GetECDsaPublicKey() ?? throw new CryptographicException("Missing ECDSA leaf key.");
                try
                {
                    RequireP256(Ec);
                }
                catch
                {
                    Ec.Dispose();
                    throw;
                }
            }
            else if (leaf.PublicKey.Oid.Value == "1.2.840.113549.1.1.1")
            {
                Rsa = leaf.GetRSAPublicKey() ?? throw new CryptographicException("Missing RSA leaf key.");
                if (Rsa.KeySize < 2048)
                {
                    Rsa.Dispose();
                    throw new CryptographicException("RSA leaf key is too small.");
                }
            }
            else
            {
                throw new CryptographicException("Unsupported leaf key or RSA-PSS certificate key restriction.");
            }
        }

        public void Dispose()
        {
            Ec?.Dispose();
            Rsa?.Dispose();
        }
    }

    private static string ReadServerName(byte* name)
    {
        if (name == null)
            throw new CryptographicException("Server endpoint name is required.");

        var length = 0;
        while (length < 256 && name[length] != 0) length++;
        if (length is 0 or 256)
            throw new CryptographicException("Invalid server endpoint name.");

        return StrictUtf8.GetString(new ReadOnlySpan<byte>(name, length));
    }

    private static int VerifyCertificate(st_ptls_verify_certificate_t* self, st_ptls_t* tls, byte* serverName, delegate*<void*, ushort, st_ptls_iovec_t, st_ptls_iovec_t, int>* verifySignature, void** verifyData, st_ptls_iovec_t* certificateData, ulong count)
    {
        List<X509Certificate2>? certificates = null;
        VerificationKey? key = null;
        try
        {
            if (verifySignature == null || verifyData == null || self == null || tls == null)
                return PTLS_ALERT_ILLEGAL_PARAMETER;

            *verifySignature = null;
            *verifyData = null;
            if (!BeginCallback())
                return PTLS_ERROR_LIBRARY;

            certificates = new List<X509Certificate2>();

            if (count == 0)
                return PTLS_ALERT_CERTIFICATE_REQUIRED;

            if (certificateData == null || count > PTLS_MAX_CERTS_IN_CONTEXT)
                return PTLS_ALERT_BAD_CERTIFICATE;

            var total = 0;
            for (var i = 0; i < (int)count; i++)
            {
                var size = CheckedLength(certificateData[i].len, MaximumCertificateBytes);
                total = checked(total + size);
                if (total > MaximumCertificateBytes) return PTLS_ALERT_BAD_CERTIFICATE;

                certificates.Add(X509CertificateLoader.LoadCertificate(ReadBytes(certificateData[i].@base, (ulong)size, MaximumCertificateBytes).ToArray()));
            }

            if (((VerifyContext*)self)->Handle != 0)
            {
                var policy = State<VerificationPolicy>(((VerifyContext*)self)->Handle);
                var server = ptls_is_server(tls) != 0;
                using var chain = new X509Chain();
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.AddRange(policy.Roots);
                chain.ChainPolicy.RevocationMode = policy.RevocationMode;
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                chain.ChainPolicy.DisableCertificateDownloads = true;
                chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(2);
                chain.ChainPolicy.ApplicationPolicy.Add(new Oid(server ? "1.3.6.1.5.5.7.3.2" : "1.3.6.1.5.5.7.3.1"));

                for (var i = 1; i < certificates.Count; i++)
                    chain.ChainPolicy.ExtraStore.Add(certificates[i]);

                if (!chain.Build(certificates[0]))
                {
                    var flags = chain.ChainStatus.Aggregate(X509ChainStatusFlags.NoError, (status, item) => status | item.Status);
                    if ((flags & X509ChainStatusFlags.Revoked) != 0)
                        return PTLS_ALERT_CERTIFICATE_REVOKED;
                    if ((flags & X509ChainStatusFlags.NotTimeValid) != 0)
                        return PTLS_ALERT_CERTIFICATE_EXPIRED;
                    if ((flags & (X509ChainStatusFlags.UntrustedRoot | X509ChainStatusFlags.PartialChain)) != 0)
                        return PTLS_ALERT_UNKNOWN_CA;

                    return PTLS_ALERT_BAD_CERTIFICATE;
                }

                if (!server && !certificates[0].MatchesHostname(ReadServerName(serverName), policy.AllowWildcards, allowCommonName: false))
                    return PTLS_ALERT_BAD_CERTIFICATE;
            }

            RequireDigitalSignature(certificates[0]);
            try
            {
                key = new VerificationKey(certificates[0]);
            }
            catch (CryptographicException)
            {
                return PTLS_ALERT_UNSUPPORTED_CERTIFICATE;
            }

            var handle = OwnState(key);
            key = null;
            *verifyData = (void*)handle;
            *verifySignature = VerifySignaturePointer;
            return 0;
        }
        catch (CryptographicException)
        {
            return PTLS_ALERT_BAD_CERTIFICATE;
        }
        catch (Exception error)
        {
            return SetupError(error);
        }
        finally
        {
            try
            {
                if (key != null)
                    DisposeState(key);
            }
            catch (Exception error) { CallbackScope.Capture(error); }

            if (certificates != null)
            {
                foreach (var certificate in certificates)
                {
                    try
                    {
                        certificate.Dispose();
                    }
                    catch (Exception error)
                    {
                        CallbackScope.Capture(error);
                    }
                }
            }
        }
    }

    private static int VerifySignature(void* opaque, ushort algorithm, st_ptls_iovec_t data, st_ptls_iovec_t signature)
    {
        var handle = (nint)opaque;
        try
        {
            if (handle == 0)
                return PTLS_ALERT_ILLEGAL_PARAMETER;
            if (data.len == 0 && signature.len == 0)
                return 0; // Upstream abort cleanup, with state consumed below.
            if (!BeginCallback())
                return PTLS_ERROR_LIBRARY;

            var key = State<VerificationKey>(handle);
            if (algorithm != key.Algorithm)
                return PTLS_ALERT_ILLEGAL_PARAMETER;

            var valid = key.Ec?.VerifyData(ReadBytes(data.@base, data.len), ReadBytes(signature.@base, signature.len), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence) ?? key.Rsa!.VerifyData(ReadBytes(data.@base, data.len), ReadBytes(signature.@base, signature.len), HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            return valid ? 0 : PTLS_ALERT_DECRYPT_ERROR;
        }
        catch (CryptographicException)
        {
            return PTLS_ALERT_DECRYPT_ERROR;
        }
        catch (Exception error)
        {
            return SetupError(error);
        }
        finally
        {
            try
            {
                ReleaseState(ref handle);
            }
            catch (Exception error)
            {
                CallbackScope.Capture(error);
            }
        }
    }
}