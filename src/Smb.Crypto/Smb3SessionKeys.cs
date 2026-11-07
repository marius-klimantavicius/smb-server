namespace Smb.Crypto;

public sealed class Smb3SessionKeys
{
	public required byte[] SigningKey { get; init; }

	public required byte[] EncryptionKey { get; init; }

	public required byte[] DecryptionKey { get; init; }

	public required byte[] ApplicationKey { get; init; }
}
