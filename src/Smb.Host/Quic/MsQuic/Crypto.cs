using System;
using static Managed.Transport.MsQuic;
using System.Buffers;
using System.Security.Cryptography;

namespace Managed.Transport.Hosting;

public sealed unsafe partial class MsQuicHost
{
    private static void RegisterCrypto(ref MSQUIC_HOST_TABLE table)
    {
        table.CxPlatKeyCreate = &PacketKeyCreate;
        table.CxPlatKeyFree = &PacketKeyFree;
        table.CxPlatEncrypt = &PacketEncrypt;
        table.CxPlatDecrypt = &PacketDecrypt;
        table.CxPlatHpKeyCreate = &HeaderKeyCreate;
        table.CxPlatHpKeyFree = &HeaderKeyFree;
        table.CxPlatHpComputeMask = &HeaderMask;
        table.CxPlatHashCreate = &PacketHashCreate;
        table.CxPlatHashFree = &PacketHashFree;
        table.CxPlatHashCompute = &PacketHashCompute;
        table.CxPlatKbKdfDerive = &PacketKbKdf;
    }

    private sealed class PacketCipher : IDisposable
    {
        internal readonly object Gate = new object();
        internal readonly AesGcm Cipher;
        internal bool Disposed;
        internal PacketCipher(ReadOnlySpan<byte> key) => Cipher = new AesGcm(key, 16);

        public void Dispose()
        {
            lock (Gate)
            {
                if (Disposed) return;

                Disposed = true;
                Cipher.Dispose();
            }
        }
    }

    private sealed class HeaderCipher : IDisposable
    {
        internal readonly object Gate = new object();
        internal readonly Aes Cipher;
        internal bool Disposed;

        internal HeaderCipher(ReadOnlySpan<byte> key)
        {
            Cipher = Aes.Create();
            byte[]? material = null;
            try
            {
                material = key.ToArray();
                Cipher.Key = material;
            }
            catch
            {
                Cipher.Dispose();
                throw;
            }
            finally
            {
                if (material != null)
                    CryptographicOperations.ZeroMemory(material);
            }
        }

        public void Dispose()
        {
            lock (Gate)
            {
                if (Disposed)
                    return;

                Disposed = true;
                Cipher.Dispose();
            }
        }
    }

    private sealed class PacketHash : IDisposable
    {
        internal readonly object Gate = new object();
        internal readonly byte[] Key;
        internal readonly int Length;
        internal bool Disposed;

        internal PacketHash(int length, ReadOnlySpan<byte> key)
        {
            Length = length;
            Key = key.ToArray();
        }

        public void Dispose()
        {
            lock (Gate)
            {
                if (Disposed)
                    return;

                Disposed = true;
                CryptographicOperations.ZeroMemory(Key);
            }
        }
    }

    // Validate the host's supported algorithms before calling the upstream
    // helper: its default case is a fatal C assertion, not a status return.
    private static int PacketKeyLength(CXPLAT_AEAD_TYPE type) => type is CXPLAT_AEAD_TYPE.CXPLAT_AEAD_AES_128_GCM or CXPLAT_AEAD_TYPE.CXPLAT_AEAD_AES_256_GCM ? CxPlatKeyLength(type) : 0;
    private static bool PacketReadable(void* pointer, uint length) => length <= int.MaxValue && (length == 0 || pointer != null);

    private static uint PacketFailure(Exception error) => error switch
    {
        OutOfMemoryException => Status.OutOfMemory,
        PlatformNotSupportedException => Status.NotSupported,
        CryptographicException => Status.TlsError,
        ArgumentException => Status.InvalidParameter,
        _ => InternalServerError(error),
    };

    private static uint InternalServerError(Exception error)
    {
        FatalInvariant("Unexpected packet crypto failure: " + error);
        return Status.InternalError;
    }

    private static uint PacketKeyCreate(void* context, CXPLAT_AEAD_TYPE type, byte* material, CXPLAT_KEY** output)
    {
        if (output == null)
            return Status.InvalidParameter;

        *output = null;

        var length = PacketKeyLength(type);
        if (length == 0 || !AesGcm.IsSupported)
            return Status.NotSupported;
        if (material == null)
            return Status.InvalidParameter;

        PacketCipher? owner = null;
        try
        {
            owner = new PacketCipher(new ReadOnlySpan<byte>(material, length));
            *output = (CXPLAT_KEY*)FromContext(context).AddResource(owner);
            owner = null;
            return Status.Success;
        }
        catch (Exception error)
        {
            return PacketFailure(error);
        }
        finally
        {
            owner?.Dispose();
        }
    }

    private static void PacketKeyFree(void* context, CXPLAT_KEY* key)
    {
        if (key != null)
            FromContext(context).ReleaseResource<PacketCipher>(key);
    }

    private static uint PacketEncrypt(void* context, CXPLAT_KEY* key, byte* iv, ushort aadLength, byte* aad, ushort bufferLength, byte* buffer) => PacketAead(context, key, iv, aadLength, aad, bufferLength, buffer, true);

    private static uint PacketDecrypt(void* context, CXPLAT_KEY* key, byte* iv, ushort aadLength, byte* aad, ushort bufferLength, byte* buffer) => PacketAead(context, key, iv, aadLength, aad, bufferLength, buffer, false);

    private static uint PacketAead(void* context, CXPLAT_KEY* key, byte* iv, ushort aadLength, byte* aad, ushort bufferLength, byte* buffer, bool encrypt)
    {
        if (key == null || iv == null || buffer == null || bufferLength < 16 || !PacketReadable(aad, aadLength))
            return Status.InvalidParameter;

        byte[]? rented = null;
        try
        {
            var owner = FromContext(context).Resource<PacketCipher>(key);
            var length = bufferLength - 16;
            rented = ArrayPool<byte>.Shared.Rent(bufferLength);
            var result = rented.AsSpan(0, bufferLength);
            var input = new ReadOnlySpan<byte>(buffer, bufferLength);
            var nonce = new ReadOnlySpan<byte>(iv, 12);
            var associated = new ReadOnlySpan<byte>(aad, aadLength);

            lock (owner.Gate)
            {
                if (owner.Disposed)
                    FatalInvariant("Packet key released while in use");

                if (encrypt)
                    owner.Cipher.Encrypt(nonce, input[..length], result[..length], result[length..], associated);
                else
                    owner.Cipher.Decrypt(nonce, input[..length], input[length..], result[..length], associated);
            }

            // Failed authentication never exposes plaintext or changes the caller's buffer.
            result[..(encrypt ? bufferLength : length)].CopyTo(new Span<byte>(buffer, bufferLength));
            return Status.Success;
        }
        catch (Exception error)
        {
            return PacketFailure(error);
        }
        finally
        {
            if (rented != null)
                ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }
    }

    private static uint HeaderKeyCreate(void* context, CXPLAT_AEAD_TYPE type, byte* material, CXPLAT_HP_KEY** output)
    {
        if (output == null)
            return Status.InvalidParameter;

        *output = null;
        var length = PacketKeyLength(type);
        if (length == 0)
            return Status.NotSupported;
        if (material == null)
            return Status.InvalidParameter;

        HeaderCipher? owner = null;
        try
        {
            owner = new HeaderCipher(new ReadOnlySpan<byte>(material, length));
            *output = (CXPLAT_HP_KEY*)FromContext(context).AddResource(owner);
            owner = null;
            return Status.Success;
        }
        catch (Exception error)
        {
            return PacketFailure(error);
        }
        finally
        {
            owner?.Dispose();
        }
    }

    private static void HeaderKeyFree(void* context, CXPLAT_HP_KEY* key)
    {
        if (key != null)
            FromContext(context).ReleaseResource<HeaderCipher>(key);
    }

    private static uint HeaderMask(void* context, CXPLAT_HP_KEY* key, byte count, byte* samples, byte* masks)
    {
        var length = count * 16;
        if (key == null || !PacketReadable(samples, (uint)length) || !PacketReadable(masks, (uint)length))
            return Status.InvalidParameter;

        byte[]? rented = null;
        try
        {
            var owner = FromContext(context).Resource<HeaderCipher>(key);
            rented = ArrayPool<byte>.Shared.Rent(Math.Max(1, length));
            lock (owner.Gate)
            {
                if (owner.Disposed)
                    FatalInvariant("Header key released while in use");

                if (length != 0)
                {
                    var written = owner.Cipher.EncryptEcb(new ReadOnlySpan<byte>(samples, length), rented.AsSpan(0, length), PaddingMode.None);
                    if (written != length)
                        FatalInvariant("AES header mask length mismatch");

                    rented.AsSpan(0, length).CopyTo(new Span<byte>(masks, length));
                }
            }

            return Status.Success;
        }
        catch (Exception error)
        {
            return PacketFailure(error);
        }
        finally
        {
            if (rented != null)
                ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }
    }

    private static uint PacketHashCreate(void* context, CXPLAT_HASH_TYPE type, byte* salt, uint saltLength, CXPLAT_HASH** output)
    {
        if (output == null)
            return Status.InvalidParameter;

        *output = null;
        var algorithm = type switch
        {
            CXPLAT_HASH_TYPE.CXPLAT_HASH_SHA256 => HashAlgorithmName.SHA256,
            CXPLAT_HASH_TYPE.CXPLAT_HASH_SHA384 => HashAlgorithmName.SHA384,
            CXPLAT_HASH_TYPE.CXPLAT_HASH_SHA512 => HashAlgorithmName.SHA512,
            _ => default,
        };

        if (algorithm.Name == null)
            return Status.NotSupported;

        int length = CxPlatHashLength(type);
        if (!PacketReadable(salt, saltLength))
            return Status.InvalidParameter;

        PacketHash? owner = null;
        try
        {
            owner = new PacketHash(length, new ReadOnlySpan<byte>(salt, (int)saltLength));
            *output = (CXPLAT_HASH*)FromContext(context).AddResource(owner);
            owner = null;
            return Status.Success;
        }
        catch (Exception error)
        {
            return PacketFailure(error);
        }
        finally
        {
            owner?.Dispose();
        }
    }

    private static void PacketHashFree(void* context, CXPLAT_HASH* hash)
    {
        if (hash != null)
            FromContext(context).ReleaseResource<PacketHash>(hash);
    }

    private static uint PacketHashCompute(void* context, CXPLAT_HASH* hash, byte* input, uint inputLength, uint outputLength, byte* output)
    {
        if (hash == null || !PacketReadable(input, inputLength) || output == null)
            return Status.InvalidParameter;

        Span<byte> result = stackalloc byte[64];
        try
        {
            var owner = FromContext(context).Resource<PacketHash>(hash);
            if (outputLength != owner.Length)
                return Status.InvalidParameter;

            var data = new ReadOnlySpan<byte>(input, (int)inputLength);
            lock (owner.Gate)
            {
                if (owner.Disposed)
                    FatalInvariant("Packet hash released while in use");

                var written = owner.Length switch
                {
                    32 => HMACSHA256.HashData(owner.Key, data, result),
                    48 => HMACSHA384.HashData(owner.Key, data, result),
                    64 => HMACSHA512.HashData(owner.Key, data, result),
                    _ => 0,
                };

                if (written != owner.Length)
                    FatalInvariant("Packet hash output length mismatch");
                result[..written].CopyTo(new Span<byte>(output, written));
            }

            return Status.Success;
        }
        catch (Exception error)
        {
            return PacketFailure(error);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(result);
        }
    }

    private static uint PacketKbKdf(void* context, byte* secret, uint secretLength, byte* label, byte* kdfContext, uint contextLength, uint outputLength, byte* output)
    {
        if (!PacketReadable(secret, secretLength) || !PacketReadable(kdfContext, contextLength) || !PacketReadable(output, outputLength) || label == null || outputLength == 0)
            return Status.InvalidParameter;

        byte[]? result = null;
        try
        {
            _ = FromContext(context);
            // Matches the pinned native provider's strnlen(Label, 255) contract.
            var labelLength = 0;
            while (labelLength < 255 && label[labelLength] != 0)
                labelLength++;

            result = new byte[(int)outputLength];
            SP800108HmacCounterKdf.DeriveBytes(new ReadOnlySpan<byte>(secret, (int)secretLength), HashAlgorithmName.SHA256, new ReadOnlySpan<byte>(label, labelLength), new ReadOnlySpan<byte>(kdfContext, (int)contextLength), result);
            result.CopyTo(new Span<byte>(output, (int)outputLength));
            return Status.Success;
        }
        catch (Exception error)
        {
            return PacketFailure(error);
        }
        finally
        {
            if (result != null)
                CryptographicOperations.ZeroMemory(result);
        }
    }
}