namespace Smb.Protocol.Enums;

public enum NegotiateContextType : ushort
{
    PreauthIntegrityCapabilities = 1,
    EncryptionCapabilities = 2,
    CompressionCapabilities = 3,
    NetnameNegotiateContextId = 5,
    TransportCapabilities = 6,
    RdmaTransformCapabilities = 7,
    SigningCapabilities = 8,
}
