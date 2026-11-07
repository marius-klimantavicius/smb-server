using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Managed.Security;
using static Managed.Security.PicoTls;
using static Managed.Transport.MsQuic;

namespace Managed.Transport.Hosting;

public sealed unsafe partial class MsQuicHost
{
    private static int TlsVerifyCertificate(st_ptls_verify_certificate_t* self, st_ptls_t* tls, byte* name, delegate*<void*, ushort, st_ptls_iovec_t, st_ptls_iovec_t, int>* signature, void** signatureContext, st_ptls_iovec_t* certificates, ulong count)
    {
        if (signature == null || signatureContext == null)
            return PTLS_ALERT_ILLEGAL_PARAMETER;

        *signature = null;
        *signatureContext = null;
        var transfer = false;
        try
        {
            var owner = TlsOwner(tls);
            if (count == 0 && owner.Server && owner.Security.Credentials.ApplicationValidation)
            {
                // An empty client Certificate must reach the callback too: it may explicitly
                // approve RemoteCertificateNotAvailable. MsQuic gates completion while pending.
                return owner.Security.Callbacks.CertificateReceived(owner.Connection, null, null, 0, Status.CertificateMissing) != 0 ? 0 : 116;
            }

            var verifier = owner.Security.Credentials.Verifier!.Callback;
            var status = verifier->cb(verifier, tls, name, signature, signatureContext, certificates, count);
            // Deferred application approval cannot bypass explicit trust/name checks.
            if (status != 0 && (owner.Security.CredentialFlags & 0x20) == 0)
                return status;

            if (count is 0 or > PTLS_MAX_CERTS_IN_CONTEXT || certificates == null)
                return status == 0 ? PTLS_ALERT_BAD_CERTIFICATE : status;

            using var memory = new TlsMemory();
            var chain = new X509Certificate2Collection();
            try
            {
                var total = 0;
                for (var i = 0; i < (int)count; i++)
                {
                    if (certificates[i].len > BclCryptoProvider.MaximumCertificateBytes || certificates[i].@base == null)
                        return PTLS_ALERT_BAD_CERTIFICATE;

                    total = checked(total + (int)certificates[i].len);
                    if (total > BclCryptoProvider.MaximumCertificateBytes) return PTLS_ALERT_BAD_CERTIFICATE;

                    chain.Add(X509CertificateLoader.LoadCertificate(new ReadOnlySpan<byte>(certificates[i].@base, (int)certificates[i].len)));
                }

                var encodedChain = chain.Export(X509ContentType.Pkcs7) ?? throw new CryptographicException("Certificate chain export failed");
                var certificate = new QUIC_BUFFER { Length = (uint)certificates[0].len, Buffer = certificates[0].@base };
                var portableChain = new QUIC_BUFFER { Length = (uint)encodedChain.Length, Buffer = memory.Copy(encodedChain) };
                var deferredStatus = status switch
                {
                    0 => Status.Success,
                    PTLS_ALERT_CERTIFICATE_EXPIRED => Status.CertificateExpired,
                    PTLS_ALERT_UNKNOWN_CA => Status.CertificateUntrustedRoot,
                    PTLS_ALERT_CERTIFICATE_REQUIRED => Status.CertificateMissing,
                    >= 0 and <= 255 => Status.TlsAlert((byte)status),
                    _ => Status.TlsError,
                };

                var accepted = owner.Security.Callbacks.CertificateReceived(owner.Connection, &certificate, &portableChain, 0, deferredStatus);
                if (status != 0)
                    return status;

                if (accepted == 0)
                    return PTLS_ALERT_BAD_CERTIFICATE;

                transfer = true;
                return 0;
            }
            finally
            {
                foreach (var certificate in chain) certificate.Dispose();
            }
        }
        catch (Exception error)
        {
            CallbackScope.Capture(error);
            return PTLS_ERROR_LIBRARY;
        }
        finally
        {
            if (!transfer && signature != null! && signatureContext != null! && *signature != null && *signatureContext != null)
            {
                var cleanup = *signature;
                var context = *signatureContext;
                *signature = null;
                *signatureContext = null;
                cleanup(context, 0, default, default);
            }
        }
    }
}