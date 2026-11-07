using System;
using System.Runtime.CompilerServices;
using static Managed.Security.PicoTls;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;

namespace Managed.Security;

/// <summary>BCL provider for the actual translated picotls ABI. Algorithm tables
/// intentionally live for the process lifetime; per-context state must be freed
/// through the corresponding translated picotls lifecycle. No native imports.</summary>
public static unsafe partial class BclCryptoProvider
{
    // One callback/gather is bounded to 16 MiB (TLS records are much smaller).
    public const int MaximumSymmetricInput = 16 * 1024 * 1024;
    public const int MaximumSymmetricVectors = 1024;

    private static int _liveManagedContexts;
    public static int LiveManagedContexts => Volatile.Read(ref _liveManagedContexts);

    [StructLayout(LayoutKind.Sequential)]
    private struct HashContext
    {
        public st_ptls_hash_context_t Header;
        public nint Handle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CipherContext
    {
        public st_ptls_cipher_context_t Header;
        public nint Handle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct AeadContext
    {
        public st_ptls_aead_context_t Header;
        public nint Handle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SymmetricTables
    {
        public st_ptls_hash_context_t FailedClone;
        public st_ptls_hash_algorithm_t Sha256, Sha384;
        public st_ptls_cipher_algorithm_t Ecb128, Ctr128, Ecb256, Ctr256;
        public st_ptls_aead_algorithm_t Gcm128, Gcm256;
        public st_ptls_cipher_suite_t Suite128, Suite256;
        public st_ptls_cipher_suite_t* First;
        public st_ptls_cipher_suite_t* Second;
        public st_ptls_cipher_suite_t* End;
    }

    private static readonly Lock _symmetricGate = new Lock();
    private static SymmetricTables* _symmetric;

    public static st_ptls_hash_algorithm_t* HashSha256
    {
        get
        {
            InitializeSymmetric();
            return &_symmetric->Sha256;
        }
    }

    public static st_ptls_hash_algorithm_t* HashSha384
    {
        get
        {
            InitializeSymmetric();
            return &_symmetric->Sha384;
        }
    }

    public static st_ptls_cipher_algorithm_t* Aes128Ecb
    {
        get
        {
            InitializeSymmetric();
            return &_symmetric->Ecb128;
        }
    }

    public static st_ptls_cipher_algorithm_t* Aes256Ecb
    {
        get
        {
            InitializeSymmetric();
            return &_symmetric->Ecb256;
        }
    }

    public static st_ptls_cipher_algorithm_t* Aes128Ctr
    {
        get
        {
            InitializeSymmetric();
            return &_symmetric->Ctr128;
        }
    }

    public static st_ptls_cipher_algorithm_t* Aes256Ctr
    {
        get
        {
            InitializeSymmetric();
            return &_symmetric->Ctr256;
        }
    }

    public static st_ptls_aead_algorithm_t* Aes128Gcm
    {
        get
        {
            InitializeSymmetric();
            return &_symmetric->Gcm128;
        }
    }

    public static st_ptls_aead_algorithm_t* Aes256Gcm
    {
        get
        {
            InitializeSymmetric();
            return &_symmetric->Gcm256;
        }
    }

    public static st_ptls_cipher_suite_t** SymmetricCipherSuites
    {
        get
        {
            InitializeSymmetric();
            return &_symmetric->First;
        }
    }

    private static readonly delegate*<st_ptls_hash_context_t*> Sha256CreatePointer = &Sha256Create;
    private static readonly delegate*<st_ptls_hash_context_t*> Sha384CreatePointer = &Sha384Create;
    private static readonly delegate*<st_ptls_hash_context_t*, void*, ulong, void> HashUpdatePointer = &HashUpdate;
    private static readonly delegate*<st_ptls_hash_context_t*, void*, en_ptls_hash_final_mode_t, void> HashFinalPointer = &HashFinal;
    private static readonly delegate*<st_ptls_hash_context_t*, st_ptls_hash_context_t*> HashClonePointer = &HashClone;
    private static readonly delegate*<st_ptls_hash_context_t*, void*, ulong, void> FailedHashUpdatePointer = &FailedHashUpdate;
    private static readonly delegate*<st_ptls_hash_context_t*, void*, en_ptls_hash_final_mode_t, void> FailedHashFinalPointer = &FailedHashFinal;
    private static readonly delegate*<st_ptls_hash_context_t*, st_ptls_hash_context_t*> FailedHashClonePointer = &FailedHashClone;
    private static readonly delegate*<st_ptls_cipher_context_t*, int, void*, int> CipherSetupPointer = &CipherSetup;
    private static readonly delegate*<st_ptls_cipher_context_t*, void> CipherDisposePointer = &CipherDispose;
    private static readonly delegate*<st_ptls_cipher_context_t*, void*, void> CipherInitPointer = &CipherInit;
    private static readonly delegate*<st_ptls_cipher_context_t*, void*, void*, ulong, void> CipherTransformPointer = &CipherTransform;
    private static readonly delegate*<st_ptls_aead_context_t*, int, void*, void*, int> AeadSetupPointer = &AeadSetup;
    private static readonly delegate*<st_ptls_aead_context_t*, void> AeadDisposePointer = &AeadDispose;
    private static readonly delegate*<st_ptls_aead_context_t*, void*, void> AeadGetIvPointer = &AeadGetIv;
    private static readonly delegate*<st_ptls_aead_context_t*, void*, void> AeadSetIvPointer = &AeadSetIv;
    private static readonly delegate*<st_ptls_aead_context_t*, void*, void*, ulong, ulong, void*, ulong, st_ptls_aead_supplementary_encryption_t*, void> AeadEncryptPointer = &AeadEncrypt;
    private static readonly delegate*<st_ptls_aead_context_t*, void*, st_ptls_iovec_t*, ulong, ulong, void*, ulong, void> AeadEncryptVectorPointer = &AeadEncryptVector;
    private static readonly delegate*<st_ptls_aead_context_t*, void*, void*, ulong, ulong, void*, ulong, ulong> AeadDecryptPointer = &AeadDecrypt;

    public static void InitializeSymmetric()
    {
        lock (_symmetricGate)
        {
            if (_symmetric != null)
                return;

            if (!AesGcm.IsSupported)
                throw new PlatformNotSupportedException("AES-GCM is required by the picotls BCL profile.");

            // Probe required BCL capability before publishing any table.
            using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            using var sha384 = IncrementalHash.CreateHash(HashAlgorithmName.SHA384);
            using var clone256 = sha256.Clone();
            using var clone384 = sha384.Clone();
            Span<byte> block = stackalloc byte[16], encrypted = stackalloc byte[16], nonce = stackalloc byte[12];

            Init(16, block, nonce, encrypted);
            Init(32, block, nonce, encrypted);

            var table = (SymmetricTables*)AllocateZeroed(sizeof(SymmetricTables));
            try
            {
                table->FailedClone.update = FailedHashUpdatePointer;
                table->FailedClone.final = FailedHashFinalPointer;
                table->FailedClone.clone_ = FailedHashClonePointer;
                table->Sha256.name = Libc.L("sha256\0"u8);
                table->Sha256.block_size = 64;
                table->Sha256.digest_size = 32;
                table->Sha256.create = Sha256CreatePointer;
                SHA256.HashData([], new Span<byte>(table->Sha256.empty_digest, 32));
                table->Sha384.name = Libc.L("sha384\0"u8);
                table->Sha384.block_size = 128;
                table->Sha384.digest_size = 48;
                table->Sha384.create = Sha384CreatePointer;
                SHA384.HashData([], new Span<byte>(table->Sha384.empty_digest, 48));
                InitializeCipher(&table->Ecb128, 16, false, Libc.L("AES128-ECB\0"u8));
                InitializeCipher(&table->Ctr128, 16, true, Libc.L("AES128-CTR\0"u8));
                InitializeCipher(&table->Ecb256, 32, false, Libc.L("AES256-ECB\0"u8));
                InitializeCipher(&table->Ctr256, 32, true, Libc.L("AES256-CTR\0"u8));
                InitializeAead(&table->Gcm128, &table->Ctr128, &table->Ecb128, Libc.L("AES128-GCM\0"u8));
                InitializeAead(&table->Gcm256, &table->Ctr256, &table->Ecb256, Libc.L("AES256-GCM\0"u8));
                table->Suite128.id = 0x1301;
                table->Suite128.aead = &table->Gcm128;
                table->Suite128.hash = &table->Sha256;
                table->Suite128.name = Libc.L("TLS_AES_128_GCM_SHA256\0"u8);
                table->Suite256.id = 0x1302;
                table->Suite256.aead = &table->Gcm256;
                table->Suite256.hash = &table->Sha384;
                table->Suite256.name = Libc.L("TLS_AES_256_GCM_SHA384\0"u8);
                table->First = &table->Suite128;
                table->Second = &table->Suite256;
                _symmetric = table; // complete immutable table, published under the same reader gate
            }
            catch
            {
                Libc.free(table);
                throw;
            }
        }

        static void Init(int keySize, Span<byte> block, Span<byte> nonce, Span<byte> encrypted)
        {
            var probeKey = new byte[keySize];
            block.Clear();
            nonce.Clear();
            try
            {
                using var aes = Aes.Create();
                aes.Key = probeKey;
                aes.EncryptEcb(block, encrypted, PaddingMode.None);

                using var gcm = new AesGcm(probeKey, 16);
                gcm.Encrypt(nonce, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, encrypted);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(probeKey);
                CryptographicOperations.ZeroMemory(block);
                CryptographicOperations.ZeroMemory(encrypted);
                CryptographicOperations.ZeroMemory(nonce);
            }
        }
    }

    private static void InitializeCipher(st_ptls_cipher_algorithm_t* algorithm, ulong size, bool ctr, byte* name)
    {
        algorithm->name = name;
        algorithm->key_size = size;
        algorithm->block_size = ctr ? 1UL : 16UL;
        algorithm->iv_size = ctr ? 16UL : 0UL;
        algorithm->context_size = (ulong)sizeof(CipherContext);
        algorithm->setup_crypto = CipherSetupPointer;
    }

    private static void InitializeAead(st_ptls_aead_algorithm_t* algorithm, st_ptls_cipher_algorithm_t* ctr, st_ptls_cipher_algorithm_t* ecb, byte* name)
    {
        algorithm->name = name;
        algorithm->confidentiality_limit = 0x2000000;
        algorithm->integrity_limit = 0x40000000000000;
        algorithm->ctr_cipher = ctr;
        algorithm->ecb_cipher = ecb;
        algorithm->key_size = ctr->key_size;
        algorithm->iv_size = 12;
        algorithm->tag_size = 16;
        // tls12, non_temporal, align_bits remain zero. This profile is TLS 1.3 only.
        algorithm->context_size = (ulong)sizeof(AeadContext);
        algorithm->setup_crypto = AeadSetupPointer;
    }

    private static void* AllocateZeroed(int size)
    {
        ProviderFaultInjection.BeforeAllocation();
        var result = Libc.malloc(size);
        if (result == null)
            throw new OutOfMemoryException();

        new Span<byte>(result, size).Clear();
        return result;
    }

    private static int CheckedLength(ulong length, int maximum = MaximumSymmetricInput)
    {
        var value = checked((int)length);
        if (value > maximum)
            throw new ArgumentOutOfRangeException(nameof(length), "Provider input bound exceeded.");

        return value;
    }

    private static ReadOnlySpan<byte> ReadBytes(void* pointer, ulong length, int maximum = MaximumSymmetricInput)
    {
        var count = CheckedLength(length, maximum);
        if (pointer == null && count != 0)
            throw new ArgumentNullException(nameof(pointer));

        return new ReadOnlySpan<byte>(pointer, count);
    }

    private static Span<byte> WriteBytes(void* pointer, ulong length, int maximum = MaximumSymmetricInput + 16)
    {
        var count = CheckedLength(length, maximum);
        if (pointer == null && count != 0)
            throw new ArgumentNullException(nameof(pointer));

        return new Span<byte>(pointer, count);
    }

    private static T State<T>(nint handle) where T : class => handle != 0 ? (T)(GCHandle.FromIntPtr(handle).Target ?? throw new ObjectDisposedException(nameof(T))) : throw new ObjectDisposedException(nameof(T));

    private static nint OwnState(IDisposable state)
    {
        ProviderFaultInjection.BeforeAllocation();
        var handle = GCHandle.ToIntPtr(GCHandle.Alloc(state));
        Interlocked.Increment(ref _liveManagedContexts);
        return handle;
    }

    private static void DisposeState(IDisposable state)
    {
        state.Dispose();
        ProviderFaultInjection.StateDisposed();
    }

    private static void ReleaseState(ref nint token)
    {
        var value = token;
        token = 0;
        if (value == 0)
            return;

        var handle = GCHandle.FromIntPtr(value);
        try
        {
            DisposeState((IDisposable)handle.Target!);
        }
        finally
        {
            handle.Free();
            Interlocked.Decrement(ref _liveManagedContexts);
        }
    }

    private static bool BeginCallback()
    {
        CallbackScope.RequireActive();
        return !CallbackScope.HasFailure;
    }

    private static int SetupError(Exception exception)
    {
        CallbackScope.Capture(exception);
        return exception is OutOfMemoryException ? PTLS_ERROR_NO_MEMORY : PTLS_ERROR_LIBRARY;
    }

    private static st_ptls_hash_context_t* Sha256Create() => CreateHash(HashAlgorithmName.SHA256);
    private static st_ptls_hash_context_t* Sha384Create() => CreateHash(HashAlgorithmName.SHA384);

    private static st_ptls_hash_context_t* CreateHash(HashAlgorithmName algorithm)
    {
        try
        {
            return BeginCallback() ? OwnHash(IncrementalHash.CreateHash(algorithm)) : null;
        }
        catch (Exception ex)
        {
            CallbackScope.Capture(ex);
            return null;
        }
    }

    private static st_ptls_hash_context_t* OwnHash(IncrementalHash hash)
    {
        HashContext* context = null;
        try
        {
            context = (HashContext*)AllocateZeroed(sizeof(HashContext));
            context->Handle = OwnState(hash);
            context->Header.update = HashUpdatePointer;
            context->Header.final = HashFinalPointer;
            context->Header.clone_ = HashClonePointer;
            return &context->Header;
        }
        catch
        {
            try
            {
                if (context != null && context->Handle != 0)
                    ReleaseState(ref context->Handle);
                else
                    DisposeState(hash);
            }
            finally
            {
                if (context != null)
                    Libc.free(context);
            }

            throw;
        }
    }

    private static void HashUpdate(st_ptls_hash_context_t* context, void* input, ulong length)
    {
        try
        {
            if (BeginCallback())
                State<IncrementalHash>(((HashContext*)context)->Handle).AppendData(ReadBytes(input, length));
        }
        catch (Exception ex)
        {
            CallbackScope.Capture(ex);
        }
    }

    private static st_ptls_hash_context_t* HashClone(st_ptls_hash_context_t* context)
    {
        try
        {
            if (BeginCallback())
                return OwnHash(State<IncrementalHash>(((HashContext*)context)->Handle).Clone());
        }
        catch (Exception ex)
        {
            ProviderFaultInjection.HashCloneFailed();
            CallbackScope.Capture(ex);
        }

        // The pinned core's send_session_ticket restores an unchecked clone
        // result as its owned transcript, and key_schedule_free dereferences it.
        // A failed clone therefore needs a non-null, safely disposable poison
        // context. It owns no key/state/handle, never produces a digest, and
        // cannot be used successfully even if a raw caller opens a fresh scope.
        return &_symmetric->FailedClone;
    }

    private static void RequireHashFailure()
    {
        try
        {
            CallbackScope.RequireActive();
            if (!CallbackScope.HasFailure)
                CallbackScope.Capture(new InvalidOperationException("A failed hash clone cannot be used for cryptographic operations."));
        }
        catch (Exception error)
        {
            CallbackScope.Capture(error);
        }
    }

    private static void FailedHashUpdate(st_ptls_hash_context_t* context, void* input, ulong length) => RequireHashFailure();

    private static void FailedHashFinal(st_ptls_hash_context_t* context, void* output, en_ptls_hash_final_mode_t mode)
    {
        RequireHashFailure();
        // Output capacity is not part of this callback ABI. Do not guess the
        // digest size or touch output. FREE never releases process-lifetime data.
    }

    private static st_ptls_hash_context_t* FailedHashClone(st_ptls_hash_context_t* context)
    {
        RequireHashFailure();
        return context;
    }

    private static void HashFinal(st_ptls_hash_context_t* context, void* output, en_ptls_hash_final_mode_t mode)
    {
        var owner = (HashContext*)context;
        Span<byte> digest = stackalloc byte[64];
        try
        {
            var run = BeginCallback();
            if ((int)mode is < 0 or > 2)
                throw new ArgumentOutOfRangeException(nameof(mode));

            if (run)
            {
                var hash = State<IncrementalHash>(owner->Handle);
                if (output != null || (int)mode == 1)
                {
                    var length = (int)mode == 1 ? hash.GetHashAndReset(digest) : hash.GetCurrentHash(digest);
                    if (output != null)
                        digest[..length].CopyTo(WriteBytes(output, (ulong)length));
                }
            }
        }
        catch (Exception ex)
        {
            CallbackScope.Capture(ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(digest);
            if ((int)mode == 0 && owner != null)
            {
                try
                {
                    ReleaseState(ref owner->Handle);
                }
                catch (Exception ex)
                {
                    CallbackScope.Capture(ex);
                }
                finally
                {
                    Libc.free(owner);
                }
            }
        }
    }

    private sealed class CipherState : IDisposable
    {
        [InlineArray(16)]
        internal struct BlockBuffer
        {
            private byte _element0;
        }

        internal readonly Aes Aes;
        internal readonly bool CounterMode, Encryption;
        internal BlockBuffer Counter, Stream;
        internal int Offset = 16;
        internal bool Initialized;

        internal CipherState(ReadOnlySpan<byte> key, bool ctr, bool encryption)
        {
            Aes = Aes.Create();
            CounterMode = ctr;
            Encryption = encryption;
            byte[]? copy = null;
            try
            {
                copy = key.ToArray();
                Aes.Key = copy;
            }
            catch
            {
                Aes.Dispose();
                throw;
            }
            finally
            {
                if (copy != null) CryptographicOperations.ZeroMemory(copy);
            }

            Initialized = !ctr;
        }

        public void Dispose()
        {
            try
            {
                Aes.Dispose();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(Counter);
                CryptographicOperations.ZeroMemory(Stream);
                Initialized = false;
            }
        }
    }

    private static int CipherSetup(st_ptls_cipher_context_t* context, int encryption, void* key)
    {
        CipherState? state = null;
        var owner = (CipherContext*)context;
        if (owner != null)
            owner->Handle = 0; // core explicitly leaves the tail uninitialized

        try
        {
            if (!BeginCallback())
                return PTLS_ERROR_LIBRARY;

            if (context == null || context->algo == null)
                throw new ArgumentNullException(nameof(context));
            if (encryption is not (0 or 1) || context->algo->key_size is not (16 or 32) || context->algo->iv_size is not (0 or 16))
                throw new ArgumentException("Unsupported AES cipher parameters.");

            state = new CipherState(ReadBytes(key, context->algo->key_size), context->algo->iv_size != 0, encryption != 0);
            owner->Handle = OwnState(state);
            state = null;
            context->do_dispose = CipherDisposePointer;
            context->do_init = CipherInitPointer;
            context->do_transform = CipherTransformPointer;
            return 0;
        }
        catch (Exception ex)
        {
            var error = SetupError(ex);
            try
            {
                if (state != null)
                    DisposeState(state);
            }
            catch (Exception cleanup)
            {
                CallbackScope.Capture(cleanup);
            }

            try
            {
                if (owner != null)
                    ReleaseState(ref owner->Handle);
            }
            catch (Exception cleanup)
            {
                CallbackScope.Capture(cleanup);
            }

            return error;
        }
    }

    private static void CipherDispose(st_ptls_cipher_context_t* context)
    {
        try
        {
            if (context != null)
                ReleaseState(ref ((CipherContext*)context)->Handle);
        }
        catch (Exception ex)
        {
            CallbackScope.Capture(ex);
        }
    }

    private static void CipherInit(st_ptls_cipher_context_t* context, void* iv)
    {
        try
        {
            if (!BeginCallback())
                return;

            var state = State<CipherState>(((CipherContext*)context)->Handle);
            if (state.CounterMode)
                ReadBytes(iv, 16).CopyTo(state.Counter);

            CryptographicOperations.ZeroMemory(state.Stream);
            state.Offset = 16;
            state.Initialized = true;
        }
        catch (Exception ex)
        {
            CallbackScope.Capture(ex);
        }
    }

    private static void CipherTransform(st_ptls_cipher_context_t* context, void* output, void* input, ulong length)
    {
        byte[]? scratch = null;
        Span<byte> destination = default;
        try
        {
            if (!BeginCallback())
                return;

            var source = ReadBytes(input, length);
            destination = WriteBytes(output, length);
            var state = State<CipherState>(((CipherContext*)context)->Handle);
            if (!state.Initialized)
                throw new InvalidOperationException("AES CTR must be initialized with an IV.");

            // Stage output to support every input/output overlap without allowing
            // partial provider failure to leave ciphertext presented as complete.
            scratch = new byte[source.Length];
            if (!state.CounterMode)
            {
                if ((source.Length & 15) != 0)
                    throw new ArgumentException("AES ECB requires complete blocks.");

                if (state.Encryption)
                    state.Aes.EncryptEcb(source, scratch, PaddingMode.None);
                else
                    state.Aes.DecryptEcb(source, scratch, PaddingMode.None);
            }
            else
            {
                for (var i = 0; i < source.Length; i++)
                {
                    if (state.Offset == 16)
                    {
                        state.Aes.EncryptEcb(state.Counter, state.Stream, PaddingMode.None);
                        for (var j = 15; j >= 0 && ++state.Counter[j] == 0; j--) { } // There is mutation: ++state.Counter[j]

                        state.Offset = 0;
                    }

                    scratch[i] = (byte)(source[i] ^ state.Stream[state.Offset++]);
                }
            }

            scratch.CopyTo(destination);
        }
        catch (Exception ex)
        {
            CryptographicOperations.ZeroMemory(destination);
            CallbackScope.Capture(ex);
        }
        finally
        {
            if (scratch != null)
                CryptographicOperations.ZeroMemory(scratch);
        }
    }

    private sealed class AeadState : IDisposable
    {
        [InlineArray(12)]
        internal struct IvBuffer
        {
            private byte _element0;

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public readonly void CopyTo(Span<byte> target)
            {
                var self = (ReadOnlySpan<byte>)this;
                self.CopyTo(target);
            }
        }

        internal readonly AesGcm Cipher;
        internal readonly bool Encryption;
        internal IvBuffer Iv;

        internal AeadState(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, bool encryption)
        {
            Cipher = new AesGcm(key, 16);
            iv.CopyTo(Iv);
            Encryption = encryption;
        }

        public void Dispose()
        {
            try
            {
                Cipher.Dispose();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(Iv);
            }
        }

        internal void Nonce(ulong sequence, Span<byte> nonce)
        {
            Iv.CopyTo(nonce);
            for (var i = 0; i < 8; i++)
            {
                nonce[11 - i] ^= (byte)sequence;
                sequence >>= 8;
            }
        }
    }

    private static int AeadSetup(st_ptls_aead_context_t* context, int encryption, void* key, void* iv)
    {
        AeadState? state = null;
        var owner = (AeadContext*)context;
        if (owner != null)
            owner->Handle = 0;

        try
        {
            if (!BeginCallback())
                return PTLS_ERROR_LIBRARY;

            if (context == null || context->algo == null)
                throw new ArgumentNullException(nameof(context));
            if (encryption is not (0 or 1) || context->algo->key_size is not (16 or 32) || context->algo->iv_size != 12 || context->algo->tag_size != 16)
                throw new ArgumentException("Unsupported AES GCM parameters.");

            state = new AeadState(ReadBytes(key, context->algo->key_size), ReadBytes(iv, 12), encryption != 0);
            owner->Handle = OwnState(state);
            state = null;
            context->dispose_crypto = AeadDisposePointer;
            context->do_get_iv = AeadGetIvPointer;
            context->do_set_iv = AeadSetIvPointer;
            context->do_encrypt_init = null;
            context->do_encrypt_update = null;
            context->do_encrypt_final = null;
            context->do_encrypt = AeadEncryptPointer;
            context->do_encrypt_v = AeadEncryptVectorPointer;
            context->do_decrypt = AeadDecryptPointer;
            return 0;
        }
        catch (Exception ex)
        {
            var error = SetupError(ex);
            try
            {
                if (state != null)
                    DisposeState(state);
            }
            catch (Exception cleanup)
            {
                CallbackScope.Capture(cleanup);
            }

            try
            {
                if (owner != null)
                    ReleaseState(ref owner->Handle);
            }
            catch (Exception cleanup)
            {
                CallbackScope.Capture(cleanup);
            }

            return error;
        }
    }

    private static void AeadDispose(st_ptls_aead_context_t* context)
    {
        try
        {
            if (context != null)
                ReleaseState(ref ((AeadContext*)context)->Handle);
        }
        catch (Exception ex)
        {
            CallbackScope.Capture(ex);
        }
    }

    private static void AeadGetIv(st_ptls_aead_context_t* context, void* iv)
    {
        try
        {
            if (BeginCallback())
                State<AeadState>(((AeadContext*)context)->Handle).Iv.CopyTo(WriteBytes(iv, 12));
        }
        catch (Exception ex)
        {
            CallbackScope.Capture(ex);
        }
    }

    private static void AeadSetIv(st_ptls_aead_context_t* context, void* iv)
    {
        try
        {
            if (BeginCallback())
                ReadBytes(iv, 12).CopyTo(State<AeadState>(((AeadContext*)context)->Handle).Iv);
        }
        catch (Exception ex)
        {
            CallbackScope.Capture(ex);
        }
    }

    private static void EncryptBlock(st_ptls_aead_context_t* context, Span<byte> output, ReadOnlySpan<byte> input, ulong sequence, ReadOnlySpan<byte> aad)
    {
        var state = State<AeadState>(((AeadContext*)context)->Handle);
        if (!state.Encryption)
            throw new InvalidOperationException("AEAD context was created for decryption.");

        Span<byte> nonce = stackalloc byte[12];
        var scratch = new byte[checked(input.Length + 16)];
        try
        {
            state.Nonce(sequence, nonce);
            state.Cipher.Encrypt(nonce, input, scratch.AsSpan(0, input.Length), scratch.AsSpan(input.Length, 16), aad);
            scratch.CopyTo(output);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(scratch);
        }
    }

    private static void AeadEncrypt(st_ptls_aead_context_t* context, void* output, void* input, ulong length, ulong sequence, void* aad, ulong aadLength, st_ptls_aead_supplementary_encryption_t* supplementary)
    {
        Span<byte> destination = default;
        try
        {
            if (!BeginCallback())
                return;

            var source = ReadBytes(input, length);
            destination = WriteBytes(output, checked(length + 16));
            EncryptBlock(context, destination, source, sequence, ReadBytes(aad, aadLength));
            if (supplementary != null)
            {
                if (supplementary->ctx == null || supplementary->ctx->do_init == null || supplementary->ctx->do_transform == null)
                    throw new ArgumentException("Incomplete supplementary cipher.");

                // The input may point inside destination: read only after AEAD.
                supplementary->ctx->do_init(supplementary->ctx, supplementary->input);

                new Span<byte>(supplementary->output, 16).Clear();
                supplementary->ctx->do_transform(supplementary->ctx, supplementary->output, supplementary->output, 16);

                if (CallbackScope.HasFailure)
                    destination.Clear();
            }
        }
        catch (Exception ex)
        {
            CryptographicOperations.ZeroMemory(destination);
            if (supplementary != null)
                new Span<byte>(supplementary->output, 16).Clear();

            CallbackScope.Capture(ex);
        }
    }

    private static void AeadEncryptVector(st_ptls_aead_context_t* context, void* output, st_ptls_iovec_t* input, ulong count, ulong sequence, void* aad, ulong aadLength)
    {
        byte[]? gathered = null;
        Span<byte> destination = default;
        try
        {
            if (!BeginCallback())
                return;

            var vectors = CheckedLength(count, MaximumSymmetricVectors);
            if (input == null && vectors != 0)
                throw new ArgumentNullException(nameof(input));

            var total = 0;
            for (var i = 0; i < vectors; i++)
                total = CheckedLength(checked((ulong)total + (ulong)ReadBytes(input[i].@base, input[i].len).Length));

            gathered = new byte[total];
            var offset = 0;
            for (var i = 0; i < vectors; i++)
            {
                var source = ReadBytes(input[i].@base, input[i].len);
                source.CopyTo(gathered.AsSpan(offset));
                offset += source.Length;
            }

            destination = WriteBytes(output, checked((ulong)total + 16));
            EncryptBlock(context, destination, gathered, sequence, ReadBytes(aad, aadLength));
        }
        catch (Exception ex)
        {
            CryptographicOperations.ZeroMemory(destination);
            CallbackScope.Capture(ex);
        }
        finally
        {
            if (gathered != null)
                CryptographicOperations.ZeroMemory(gathered);
        }
    }

    private static ulong AeadDecrypt(st_ptls_aead_context_t* context, void* output, void* input, ulong length, ulong sequence, void* aad, ulong aadLength)
    {
        byte[]? scratch = null;
        Span<byte> destination = default;
        Span<byte> nonce = stackalloc byte[12];
        try
        {
            if (!BeginCallback())
                return ulong.MaxValue;
            if (length < 16)
                return ulong.MaxValue;

            var source = ReadBytes(input, length, MaximumSymmetricInput + 16);
            var plaintextLength = source.Length - 16;
            destination = WriteBytes(output, (ulong)plaintextLength);
            var state = State<AeadState>(((AeadContext*)context)->Handle);
            if (state.Encryption)
                throw new InvalidOperationException("AEAD context was created for encryption.");

            state.Nonce(sequence, nonce);
            scratch = new byte[plaintextLength];
            try
            {
                state.Cipher.Decrypt(nonce, source[..plaintextLength], source[plaintextLength..], scratch, ReadBytes(aad, aadLength));
            }
            catch (AuthenticationTagMismatchException)
            {
                CryptographicOperations.ZeroMemory(destination);
                return ulong.MaxValue;
            }

            scratch.CopyTo(destination);
            return (ulong)plaintextLength;
        }
        catch (Exception ex)
        {
            CryptographicOperations.ZeroMemory(destination);
            CallbackScope.Capture(ex);
            return ulong.MaxValue;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
            if (scratch != null) CryptographicOperations.ZeroMemory(scratch);
        }
    }
}