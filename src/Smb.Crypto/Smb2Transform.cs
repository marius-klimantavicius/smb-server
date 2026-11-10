using System;
using System.Security.Cryptography;
using Smb.Protocol.Constants;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;

namespace Smb.Crypto;

public static class Smb2Transform
{
    private const int SignatureFieldOffset = 4;

    public static int NonceLength(SmbCipherId cipher)
    {
        switch (cipher)
        {
            case SmbCipherId.Aes128Gcm:
            case SmbCipherId.Aes256Gcm:
                return 12;
            case SmbCipherId.Aes128Ccm:
            case SmbCipherId.Aes256Ccm:
                return 11;
            default:
                throw new ArgumentOutOfRangeException(nameof(cipher));
        }
    }

    public static byte[] Encrypt(SmbCipherId cipher, ReadOnlySpan<byte> encryptionKey, ulong sessionId, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext)
    {
        var num = NonceLength(cipher);
        if (nonce.Length != num)
        {
            throw new ArgumentException($"Nonce for {cipher} must be {num} bytes.", nameof(nonce));
        }

        var array = new byte[52 + plaintext.Length];
        var transformHeader = new TransformHeader
        {
            OriginalMessageSize = (uint)plaintext.Length,
            Flags = 1,
            SessionId = sessionId,
        };
        nonce.CopyTo(transformHeader.Nonce);
        transformHeader.Write(array);
        var span = array.AsSpan(20, 32);
        var ciphertext = array.AsSpan(52, plaintext.Length);
        var tag = array.AsSpan(SignatureFieldOffset, 16);
        EncryptAead(cipher, encryptionKey, nonce, plaintext, ciphertext, tag, span);
        return array;
    }

    public static byte[] Decrypt(SmbCipherId cipher, ReadOnlySpan<byte> decryptionKey, ReadOnlySpan<byte> frame)
    {
        if (frame.Length < 52)
        {
            throw new ArgumentException("Frame too short for TRANSFORM_HEADER.", nameof(frame));
        }

        if (!SmbProtocolIds.IsTransform(frame))
        {
            throw new ArgumentException("Not a transform frame (ProtocolId ≠ FD 53 4D 42).", nameof(frame));
        }

        var transformHeader = TransformHeader.Read(frame);
        ReadOnlySpan<byte> nonce = MemoryExtensions.AsSpan(length: NonceLength(cipher), array: transformHeader.Nonce, start: 0);
        var aad = frame.Slice(20, 32);
        var ciphertext = frame.Slice(52);
        ReadOnlySpan<byte> tag = transformHeader.Signature;
        var array = new byte[ciphertext.Length];
        DecryptAead(cipher, decryptionKey, nonce, ciphertext, tag, array, aad);
        if (transformHeader.OriginalMessageSize != array.Length)
        {
            throw new CryptographicException("OriginalMessageSize does not match the plaintext length.");
        }

        return array;
    }

    private static void EncryptAead(SmbCipherId cipher, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag, ReadOnlySpan<byte> aad)
    {
        switch (cipher)
        {
            case SmbCipherId.Aes128Gcm:
            case SmbCipherId.Aes256Gcm:
            {
                using var aesGcm = new AesGcm(key.ToArray(), 16);
                aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
                break;
            }
            case SmbCipherId.Aes128Ccm:
            case SmbCipherId.Aes256Ccm:
            {
                using var aesCcm = new AesCcm(key.ToArray());
                aesCcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
                break;
            }
            default:
                throw new ArgumentOutOfRangeException(nameof(cipher));
        }
    }

    private static void DecryptAead(SmbCipherId cipher, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext, ReadOnlySpan<byte> aad)
    {
        switch (cipher)
        {
            case SmbCipherId.Aes128Gcm:
            case SmbCipherId.Aes256Gcm:
            {
                using var aesGcm = new AesGcm(key.ToArray(), 16);
                aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, aad);
                break;
            }
            case SmbCipherId.Aes128Ccm:
            case SmbCipherId.Aes256Ccm:
            {
                using var aesCcm = new AesCcm(key.ToArray());
                aesCcm.Decrypt(nonce, ciphertext, tag, plaintext, aad);
                break;
            }
            default:
                throw new ArgumentOutOfRangeException(nameof(cipher));
        }
    }
}
