using System;
using Smb.Protocol.Enums;

namespace Smb.Crypto;

public static class Smb3KeyDerivation
{
    private static ReadOnlySpan<byte> Label30Signing => "SMB2AESCMAC\0"u8;
    private static ReadOnlySpan<byte> Context30Signing => "SmbSign\0"u8;
    private static ReadOnlySpan<byte> Label30App => "SMB2APP\0"u8;
    private static ReadOnlySpan<byte> Context30App => "SmbRpc\0"u8;
    private static ReadOnlySpan<byte> Label30Cipher => "SMB2AESCCM\0"u8;
    private static ReadOnlySpan<byte> Context30ServerOut => "ServerOut\0"u8;
    private static ReadOnlySpan<byte> Context30ServerIn => "ServerIn \0"u8;
    private static ReadOnlySpan<byte> Label311Signing => "SMBSigningKey\0"u8;
    private static ReadOnlySpan<byte> Label311App => "SMBAppKey\0"u8;
    private static ReadOnlySpan<byte> Label311S2C => "SMBS2CCipherKey\0"u8;
    private static ReadOnlySpan<byte> Label311C2S => "SMBC2SCipherKey\0"u8;

    public static Smb3SessionKeys Derive(SmbDialect dialect, SmbCipherId cipherId, ReadOnlySpan<byte> sessionKey, ReadOnlySpan<byte> fullSessionKey, ReadOnlySpan<byte> preauthHash)
    {
        if (!dialect.IsSmb3OrLater())
        {
            throw new ArgumentException("Key derivation only exists for SMB 3.x.", nameof(dialect));
        }

        var flag = dialect == SmbDialect.Smb311;
        var flag2 = cipherId - 3 <= SmbCipherId.Aes128Ccm;
        var outputBytes = (flag2 ? 32 : 16);
        byte[] signingKey;
        byte[] applicationKey;
        byte[] encryptionKey;
        byte[] decryptionKey;
        if (flag)
        {
            signingKey = Sp800108CounterKdf.DeriveKey(sessionKey, Label311Signing, preauthHash, 16);
            applicationKey = Sp800108CounterKdf.DeriveKey(sessionKey, Label311App, preauthHash, 16);
            encryptionKey = Sp800108CounterKdf.DeriveKey(flag2 ? fullSessionKey : sessionKey, Label311S2C, preauthHash, outputBytes);
            decryptionKey = Sp800108CounterKdf.DeriveKey(flag2 ? fullSessionKey : sessionKey, Label311C2S, preauthHash, outputBytes);
        }
        else
        {
            signingKey = Sp800108CounterKdf.DeriveKey(sessionKey, Label30Signing, Context30Signing, 16);
            applicationKey = Sp800108CounterKdf.DeriveKey(sessionKey, Label30App, Context30App, 16);
            encryptionKey = Sp800108CounterKdf.DeriveKey(sessionKey, Label30Cipher, Context30ServerOut, 16);
            decryptionKey = Sp800108CounterKdf.DeriveKey(sessionKey, Label30Cipher, Context30ServerIn, 16);
        }

        return new Smb3SessionKeys
        {
            SigningKey = signingKey,
            EncryptionKey = encryptionKey,
            DecryptionKey = decryptionKey,
            ApplicationKey = applicationKey,
        };
    }
}
