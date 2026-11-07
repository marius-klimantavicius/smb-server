namespace Smb.Protocol.Enums;

public enum SmbSigningAlgorithmId : ushort
{
	HmacSha256,
	AesCmac,
	AesGmac,
}
