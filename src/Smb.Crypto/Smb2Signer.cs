using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using Smb.Protocol.Enums;

namespace Smb.Crypto;

public static class Smb2Signer
{
    public const int SignatureOffset = 48;

    public const int SignatureLength = 16;

    public static SmbSigningAlgorithmId ResolveAlgorithm(SmbDialect dialect, SmbSigningAlgorithmId negotiated) => dialect switch
    {
        SmbDialect.Smb202 => SmbSigningAlgorithmId.HmacSha256,
        SmbDialect.Smb210 => SmbSigningAlgorithmId.HmacSha256,
        SmbDialect.Smb300 => SmbSigningAlgorithmId.AesCmac,
        SmbDialect.Smb302 => SmbSigningAlgorithmId.AesCmac,
        SmbDialect.Smb311 => negotiated,
        _ => throw new ArgumentOutOfRangeException(nameof(dialect), dialect, "No signing for this dialect.")
    };

    public static byte[] ComputeSignature(SmbSigningAlgorithmId algorithm, ReadOnlySpan<byte> signingKey, ReadOnlySpan<byte> message, ulong messageId, bool isServer, bool isCancel) => algorithm switch
    {
        SmbSigningAlgorithmId.HmacSha256 => HmacSha256First16(signingKey, message),
        SmbSigningAlgorithmId.AesCmac => AesCmac.Compute(signingKey, message),
        SmbSigningAlgorithmId.AesGmac => AesGmac(signingKey, message, messageId, isServer, isCancel),
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
    };

    public static void SignInPlace(SmbSigningAlgorithmId algorithm, ReadOnlySpan<byte> signingKey, Span<byte> message, ulong messageId, bool isServer, bool isCancel)
    {
        message.Slice(SignatureOffset, SignatureLength).Clear();
        ComputeSignature(algorithm, signingKey, message, messageId, isServer, isCancel).AsSpan(0, SignatureLength).CopyTo(message.Slice(SignatureOffset, SignatureLength));
    }

    public static bool Verify(SmbSigningAlgorithmId algorithm, ReadOnlySpan<byte> signingKey, ReadOnlySpan<byte> message, ulong messageId, bool isServer, bool isCancel)
    {
        if (message.Length < 64)
        {
            return false;
        }

        Span<byte> span = stackalloc byte[SignatureLength];
        message.Slice(SignatureOffset, SignatureLength).CopyTo(span);
        var array = message.ToArray();
        array.AsSpan(SignatureOffset, SignatureLength).Clear();
        var array2 = ComputeSignature(algorithm, signingKey, array, messageId, isServer, isCancel);
        return CryptographicOperations.FixedTimeEquals(span, array2.AsSpan(0, SignatureLength));
    }

    private static byte[] HmacSha256First16(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message)
    {
        Span<byte> destination = stackalloc byte[32];
        using var hMACSHA = new HMACSHA256(key.ToArray());
        hMACSHA.TryComputeHash(message, destination, out _);
        return destination.Slice(0, SignatureLength).ToArray();
    }

    private static byte[] AesGmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, ulong messageId, bool isServer, bool isCancel)
    {
        Span<byte> span = stackalloc byte[12];
        BinaryPrimitives.WriteUInt64LittleEndian(span.Slice(0, 8), messageId);
        var num = 0u;
        if (isServer)
        {
            num |= 1;
        }

        if (isCancel)
        {
            num |= 2;
        }

        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(8), num);
        var array = new byte[SignatureLength];
        using var aesGcm = new AesGcm(key.ToArray(), SignatureLength);
        aesGcm.Encrypt(span, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, array, message);
        return array;
    }
}
