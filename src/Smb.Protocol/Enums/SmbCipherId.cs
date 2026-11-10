namespace Smb.Protocol.Enums;

public enum SmbCipherId : ushort
{
    None,
    Aes128Ccm,
    Aes128Gcm,
    Aes256Ccm,
    Aes256Gcm,
}
