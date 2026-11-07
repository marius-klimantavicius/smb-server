using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Managed.Net.Quic;

internal static class CertificateValidation
{
    internal static SslPolicyErrors BuildChainAndVerifyProperties(X509Chain chain,
        X509Certificate2 certificate, bool checkName, string targetHost)
    {
        SslPolicyErrors errors = chain.Build(certificate)
            ? SslPolicyErrors.None : SslPolicyErrors.RemoteCertificateChainErrors;
        if (checkName && (string.IsNullOrEmpty(targetHost) ||
            !certificate.MatchesHostname(targetHost, allowWildcards: true, allowCommonName: true)))
            errors |= SslPolicyErrors.RemoteCertificateNameMismatch;
        return errors;
    }
}
