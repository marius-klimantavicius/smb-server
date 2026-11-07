using static Managed.Transport.MsQuic;

namespace Managed.Transport.Hosting;

// Host-friendly aliases for the constants emitted from the selected C platform.
internal static class Status
{
    internal const uint Success = QUIC_STATUS_SUCCESS;
    internal const uint Pending = QUIC_STATUS_PENDING;
    internal const uint Continue = QUIC_STATUS_CONTINUE;
    internal const uint OutOfMemory = QUIC_STATUS_OUT_OF_MEMORY;
    internal const uint InvalidParameter = QUIC_STATUS_INVALID_PARAMETER;
    internal const uint InvalidState = QUIC_STATUS_INVALID_STATE;
    internal const uint NotSupported = QUIC_STATUS_NOT_SUPPORTED;
    internal const uint NotFound = QUIC_STATUS_NOT_FOUND;
    internal const uint BufferTooSmall = QUIC_STATUS_BUFFER_TOO_SMALL;
    internal const uint HandshakeFailure = QUIC_STATUS_HANDSHAKE_FAILURE;
    internal const uint Aborted = QUIC_STATUS_ABORTED;
    internal const uint AddressInUse = QUIC_STATUS_ADDRESS_IN_USE;
    internal const uint InvalidAddress = QUIC_STATUS_INVALID_ADDRESS;
    internal const uint ConnectionTimeout = QUIC_STATUS_CONNECTION_TIMEOUT;
    internal const uint ConnectionIdle = QUIC_STATUS_CONNECTION_IDLE;
    internal const uint InternalError = QUIC_STATUS_INTERNAL_ERROR;
    internal const uint ConnectionRefused = QUIC_STATUS_CONNECTION_REFUSED;
    internal const uint ProtocolError = QUIC_STATUS_PROTOCOL_ERROR;
    internal const uint VersionNegotiationError = QUIC_STATUS_VER_NEG_ERROR;
    internal const uint Unreachable = QUIC_STATUS_UNREACHABLE;
    internal const uint TlsError = QUIC_STATUS_TLS_ERROR;
    internal const uint UserCanceled = QUIC_STATUS_USER_CANCELED;
    internal const uint AlpnNegotiationFailure = QUIC_STATUS_ALPN_NEG_FAILURE;
    internal const uint StreamLimitReached = QUIC_STATUS_STREAM_LIMIT_REACHED;
    internal const uint AlpnInUse = QUIC_STATUS_ALPN_IN_USE;
    internal const uint AddressNotAvailable = QUIC_STATUS_ADDRESS_NOT_AVAILABLE;
    internal const uint CertificateExpired = QUIC_STATUS_CERT_EXPIRED;
    internal const uint CertificateUntrustedRoot = QUIC_STATUS_CERT_UNTRUSTED_ROOT;
    internal const uint CertificateMissing = QUIC_STATUS_CERT_NO_CERT;
    internal const uint TlsErrorBase = TLS_ERROR_BASE, CertificateErrorBase = CERT_ERROR_BASE;
    internal static uint TlsAlert(byte alert) => TlsErrorBase + alert;
    internal static bool Failed(uint status) => unchecked((int)status) > 0;
}
