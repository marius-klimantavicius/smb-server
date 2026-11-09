using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;
using Microsoft.Win32.SafeHandles;
using static Managed.Database.Sqlite;

namespace Managed.Database;

// OS services only: SQLite itself and all VFS callbacks remain managed code.
// All handles for this VFS must be opened/closed here. In particular, do not
// dispose FileHandle.Handle: Darwin POSIX locks require deferred descriptor close.
internal static unsafe partial class HostPlatform
{
    private const long PendingByte = 0x40000000;
    private const long ReservedByte = PendingByte + 1;
    private const long SharedFirst = PendingByte + 2;
    private const long SharedSize = 510;

    private static readonly Lock Gate = new Lock();

#if HOST_VFS_PLATFORM_TESTS
    // Compiled only by the isolated descriptor-lifetime regression fixture.
    internal static Func<SafeFileHandle, long, long, int, int>? RangeOperationForTests;
#endif

    private static readonly Dictionary<(uint Device, ulong Inode), InodeState> Inodes = new Dictionary<(uint Device, ulong Inode), InodeState>();

    internal sealed class InodeState
    {
        internal readonly List<FileHandle> Files = new List<FileHandle>();
        internal readonly List<SafeFileHandle> Deferred = new List<SafeFileHandle>();
        internal bool HasOrphanLocks;
        internal bool HasLocks => Files.Exists(f => f.HasLocks);
    }

    internal sealed class FileHandle : IDisposable
    {
        private readonly bool _writable;
        private readonly InodeState? _inode;
        private readonly (uint Device, ulong Inode) _identity;
        private bool _shared, _reserved, _pending, _exclusive, _disposed, _externalLocks;
        private bool _gateRead, _reservedProbe, _sharedOverlay, _ioFailed;

        internal bool HasLocks => _shared || _reserved || _pending || _exclusive || _gateRead || _reservedProbe || _sharedOverlay || _externalLocks;

        public int LockLevel => _exclusive ? 4 : _pending ? 3 : _reserved ? 2 : _shared ? 1 : 0;
        public SafeFileHandle Handle { get; }

        internal void RetainExternalLocks()
        {
            lock (Gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                _externalLocks = true;
            }
        }

        private int FailUnlock()
        {
            _ioFailed = true;
            return SQLITE_IOERR_UNLOCK;
        }

        private int FailReadLock()
        {
            _ioFailed = true;
            return SQLITE_IOERR_RDLOCK;
        }

        internal FileHandle(SafeFileHandle handle,
            bool writable,
            InodeState? inode,
            (uint Device, ulong Inode) identity)
        {
            Handle = handle;
            _writable = writable;
            _inode = inode;
            _identity = identity;
        }

        public int Lock(int level)
        {
            lock (Gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                if (_ioFailed || (_inode is not null && (_inode.HasOrphanLocks || _inode.Files.Exists(f => f._ioFailed))) || level is not (1 or 2 or 4))
                    return SQLITE_IOERR_LOCK;

                if (LockLevel >= level)
                    return 0;

                if (level > 1 && !_writable)
                    return SQLITE_IOERR_LOCK;

                if (level > 1 && !_shared)
                    return SQLITE_IOERR_LOCK;

                if (level == 1)
                {
                    // POSIX process locks cannot distinguish our own descriptors.
                    // Reuse the inode's read lock, but never admit readers past PENDING.
                    if (_inode is not null && _inode.Files.Exists(f => f != this && f._pending))
                        return SQLITE_BUSY;

                    if (_inode is not null && _inode.Files.Exists(f => f != this && f._shared))
                    {
                        _shared = true;
                        return 0;
                    }

                    var rc = SetRange(Handle, PendingByte, 1, 0);
                    if (rc != 0)
                        return rc;

                    _gateRead = true;
                    rc = SetRange(Handle, SharedFirst, SharedSize, 0);
                    if (rc == 0)
                        _shared = true;

                    var release = SetRange(Handle, PendingByte, 1, 2);

                    // A failed temporary read-gate release is not a WRITE PENDING lock.
                    if (release != 0)
                        return FailUnlock();

                    _gateRead = false;
                    return rc;
                }

                if (_inode is not null && _inode.Files.Exists(f => f != this && f.LockLevel > 1))
                    return SQLITE_BUSY;

                if (level == 2)
                {
                    var rc = SetRange(Handle, ReservedByte, 1, 1);
                    if (rc == 0)
                        _reserved = true;

                    return rc;
                }

                if (!_pending)
                {
                    var rc = SetRange(Handle, PendingByte, 1, 1);
                    if (rc != 0)
                        return rc;

                    _pending = true;
                }

                // Retain PENDING on BUSY. This is part of SQLite's lock protocol.
                if (_inode is not null && _inode.Files.Exists(f => f != this && f._shared))
                    return SQLITE_BUSY;

                if (OperatingSystem.IsWindows())
                {
                    if (SetRange(Handle, SharedFirst, SharedSize, 2) != 0)
                        return FailUnlock();

                    _shared = false;
                }

                var result = SetRange(Handle, SharedFirst, SharedSize, 1);
                if (result == 0)
                {
                    _shared = true;
                    _exclusive = true;
                }
                else if (OperatingSystem.IsWindows())
                {
                    // PENDING still excludes newcomers while restoring our reader lock.
                    if (SetRange(Handle, SharedFirst, SharedSize, 0) != 0)
                        return FailReadLock();

                    _shared = true;
                }

                return result;
            }
        }

        public int Unlock(int level)
        {
            lock (Gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);

                if (level is not (0 or 1))
                    return SQLITE_IOERR_UNLOCK;

                if (_ioFailed && level == 1)
                    return SQLITE_IOERR_UNLOCK;

                if (LockLevel <= level && !_ioFailed)
                    return 0;

                if (_exclusive && level == 1)
                {
                    // Windows permits a shared lock overlapping this handle's
                    // exclusive lock; the next unlock removes the exclusive first.
                    // POSIX converts the lock atomically.
                    if (SetRange(Handle, SharedFirst, SharedSize, 0) != 0)
                        return FailReadLock();

                    if (OperatingSystem.IsWindows())
                    {
                        _sharedOverlay = true;
                        if (SetRange(Handle, SharedFirst, SharedSize, 2) != 0)
                            return FailUnlock();

                        _sharedOverlay = false;
                    }

                    _exclusive = false;
                }

                if (level == 0 && _shared)
                {
                    if (_sharedOverlay)
                    {
                        if (SetRange(Handle, SharedFirst, SharedSize, 2) != 0)
                            return FailUnlock();

                        _sharedOverlay = _exclusive = false;
                    }

                    var lastReader = _inode is null || !_inode.Files.Exists(f => f != this && f._shared);
                    if (lastReader && SetRange(Handle, SharedFirst, SharedSize, 2) != 0)
                        return FailUnlock();

                    _shared = _exclusive = false;
                }

                if (_reserved)
                {
                    if (SetRange(Handle, ReservedByte, 1, 2) != 0)
                        return FailUnlock();

                    _reserved = false;
                }

                if (_pending)
                {
                    if (SetRange(Handle, PendingByte, 1, 2) != 0)
                        return FailUnlock();

                    _pending = false;
                }

                if (_gateRead)
                {
                    if (SetRange(Handle, PendingByte, 1, 2) != 0)
                        return FailUnlock();

                    _gateRead = false;
                }

                if (_reservedProbe)
                {
                    if (SetRange(Handle, ReservedByte, 1, 2) != 0)
                        return FailUnlock();

                    _reservedProbe = false;
                }

                _ioFailed = false;
                DrainDeferred(_inode);
                return 0;
            }
        }

        public int CheckReserved(out bool held)
        {
            lock (Gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                if (_ioFailed || _inode?.HasOrphanLocks == true)
                {
                    held = false;
                    return SQLITE_IOERR_CHECKRESERVEDLOCK;
                }

                held = LockLevel >= 2 || (_inode is not null && _inode.Files.Exists(f => f.LockLevel >= 2));
                if (held) return 0;

                if (OperatingSystem.IsWindows())
                {
                    // Shared probe works with a read-only HANDLE and conflicts with
                    // the writer's exclusive RESERVED byte.
                    var rc = SetRange(Handle, ReservedByte, 1, 0);
                    if (rc == SQLITE_BUSY)
                    {
                        held = true;
                        return 0;
                    }

                    if (rc != 0)
                        return SQLITE_IOERR_CHECKRESERVEDLOCK;

                    _reservedProbe = true;
                    if (SetRange(Handle, ReservedByte, 1, 2) != 0)
                    {
                        _ioFailed = true;
                        return SQLITE_IOERR_CHECKRESERVEDLOCK;
                    }

                    _reservedProbe = false;
                    return 0;
                }

                return QueryReserved(Handle, out held);
            }
        }

        public void Dispose()
        {
            lock (Gate)
            {
                if (_disposed) return;

                var rc = Unlock(0);
                if (_inode is not null)
                {
                    // xClose releases its managed context even on IOERR_CLOSE, so
                    // this lease can never be retried. Transfer ownership of the
                    // descriptor to the inode until peers no longer need its locks.
                    _inode.Files.Remove(this);
                    if (_inode.HasLocks)
                    {
                        _inode.Deferred.Add(Handle);
                        // Failed unlocks may leave process-owned bytes behind. Do
                        // not admit new locks until closing the deferred descriptor
                        // can safely release those bytes along with the last reader.
                        _inode.HasOrphanLocks |= rc != 0;
                    }
                    else
                    {
                        Handle.Dispose();
                        DrainDeferred(_inode);
                    }

                    if (_inode.Files.Count == 0 && _inode.Deferred.Count == 0)
                        Inodes.Remove(_identity);
                }
                else
                {
                    Handle.Dispose(); // OFD/Windows close releases this handle's locks only.
                }

                _disposed = true;
                if (rc != 0)
                    throw new IOException("Unable to release SQLite file locks before closing.");
            }
        }
    }

    public static FileHandle Open(string path, FileMode mode, FileAccess access, FileOptions options, bool noFollow = false, bool shareDelete = true)
    {
        EnsureSupported();

        if (access == FileAccess.Write)
            throw new ArgumentException("SQLite requires readable file handles.", nameof(access));

        if ((options & (FileOptions.Asynchronous | FileOptions.Encrypted)) != 0)
            throw new ArgumentException("VFS requires synchronous, unencrypted handles.", nameof(options));

        lock (Gate)
        {
            var handle = OperatingSystem.IsWindows()
                ? OpenWindows(path, mode, access, options, noFollow, shareDelete)
                : OpenUnix(path, mode, access, options, noFollow);

            FileHandle? result = null;
            try
            {
                InodeState? inode = null;
                (uint Device, ulong Inode) identity = default;

                if (OperatingSystem.IsMacOS())
                {
                    identity = DarwinIdentity(handle);
                    if (!Inodes.TryGetValue(identity, out inode)) Inodes.Add(identity, inode = new InodeState());
                }

                result = new FileHandle(handle, access == FileAccess.ReadWrite, inode, identity);
                inode?.Files.Add(result);
                if (!OperatingSystem.IsWindows() && (options & FileOptions.DeleteOnClose) != 0 && unlink(path) != 0)
                    throw NativeError("unlink temporary file", path);

                return result;
            }
            catch
            {
                // Identity failure is exceptional; do not close a Darwin descriptor
                // while it might alias a locked inode whose identity we cannot read.
                if (result is not null)
                {
                    result.Dispose();
                }
                else if (OperatingSystem.IsMacOS() && Inodes.Count != 0)
                {
                    UnknownDarwinHandles.Add(handle);
                    DrainDeferred(null);
                }
                else
                {
                    handle.Dispose();
                }

                throw;
            }
        }
    }

    // Only used if fstat fails after a successful Darwin open. Keep the safe handle
    // rooted until no registered inode is locked; then closing is safe again.
    private static readonly List<SafeFileHandle> UnknownDarwinHandles = new List<SafeFileHandle>();

    private static void DrainDeferred(InodeState? inode)
    {
        if (inode is not null && !inode.HasLocks)
        {
            foreach (var handle in inode.Deferred) handle.Dispose();
            inode.Deferred.Clear();
            inode.HasOrphanLocks = false;
        }

        if (OperatingSystem.IsMacOS() && !System.Linq.Enumerable.Any(Inodes.Values, i => i.HasLocks))
        {
            foreach (var handle in UnknownDarwinHandles) handle.Dispose();
            UnknownDarwinHandles.Clear();
        }
    }

    public static void Sync(SafeFileHandle handle, bool full)
    {
        EnsureSupported();
        if (full && OperatingSystem.IsMacOS())
        {
            // F_FULLFSYNC asks the drive to flush its volatile write cache.
            int rc;
            do
            {
                rc = DarwinFcntl(handle, 51, null);
            } while (rc < 0 && Marshal.GetLastPInvokeError() == 4);

            if (rc == 0)
                return;

            // Match SQLite full_fsync: unsupported full-cache flush falls back
            // to the filesystem's normal fsync contract below.
        }

        RandomAccess.FlushToDisk(handle);
    }

    public static void SyncDirectory(string directory)
    {
        EnsureSupported();
        // SQLite's native Windows VFS has no directory-fsync primitive either.
        // File contents are flushed with FlushFileBuffers via RandomAccess above.
        if (OperatingSystem.IsWindows())
            return;

        var flags = OperatingSystem.IsMacOS() ? 0x1000000 | 0x100000 : 0x80000 | 0x10000;
        var fd = UnixOpen(directory, flags, 0);
        if (fd < 0)
            throw NativeError("open directory");

        using var handle = new SafeFileHandle(fd, true);
        int rc;
        do
        {
            rc = fsync(handle);
        } while (rc < 0 && Marshal.GetLastPInvokeError() == 4);

        if (rc < 0)
            throw NativeError("fsync directory");
    }

    public static bool Access(string path, int sqliteAccessMode)
    {
        EnsureSupported();

        if (sqliteAccessMode is < 0 or > 2)
            throw new ArgumentOutOfRangeException(nameof(sqliteAccessMode));

        if (!OperatingSystem.IsWindows())
            return access(path, sqliteAccessMode == 0 ? 0 : sqliteAccessMode == 1 ? 6 : 4) == 0;

        var attributes = GetFileAttributesW(path);

        // Like SQLite's winAccess: attributes are a preflight, CreateFile remains
        // authoritative for ACLs. No incidental open/close is needed here.
        if (attributes == uint.MaxValue)
        {
            var error = Marshal.GetLastPInvokeError();
            if (error is 2 or 3)
                return false;

            throw NativeError("GetFileAttributes", path);
        }

        return sqliteAccessMode != 1 || (attributes & 1) == 0;
    }

    private static void EnsureSupported()
    {
        if ((!OperatingSystem.IsLinux() && !OperatingSystem.IsWindows() && !OperatingSystem.IsMacOS()) ||
            RuntimeInformation.ProcessArchitecture is not (Architecture.X64 or Architecture.Arm64))
            throw new PlatformNotSupportedException("Host VFS supports Linux, Windows and macOS on x64/arm64.");
    }

    private static SafeFileHandle OpenUnix(string path, FileMode mode, FileAccess accessMode, FileOptions options, bool noFollow)
    {
        var mac = OperatingSystem.IsMacOS();
        var flags = (accessMode == FileAccess.Read ? 0 : 2) | (mac ? 0x1000000 : 0x80000);
        int create = mac ? 0x200 : 0x40, exclusive = mac ? 0x800 : 0x80, truncate = mac ? 0x400 : 0x200;
        flags |= mode switch
        {
            FileMode.Open => 0, FileMode.OpenOrCreate => create,
            FileMode.CreateNew => create | exclusive, FileMode.Create => create | truncate,
            FileMode.Truncate => truncate, _ => throw new ArgumentOutOfRangeException(nameof(mode))
        };

        if (noFollow)
            flags |= mac ? 0x100 : 0x20000;

        if ((options & FileOptions.WriteThrough) != 0)
            flags |= mac ? 0x80 : 0x101000;

        var fd = UnixOpen(path, flags, 0x1b6); // 0666, filtered by process umask.
        if (fd < 0)
            throw NativeError("open", path);

        return new SafeFileHandle(fd, true);
    }

    private static SafeFileHandle OpenWindows(string path, FileMode mode, FileAccess accessMode, FileOptions options, bool noFollow, bool shareDelete)
    {
        uint disposition = mode switch
        {
            FileMode.CreateNew => 1,
            FileMode.Create => 2,
            FileMode.Open => 3,
            FileMode.OpenOrCreate => 4,
            FileMode.Truncate => 5,
            _ => throw new ArgumentOutOfRangeException(nameof(mode))
        };

        var flags = 0x80 | (noFollow ? 0x200000u : 0);
        if ((options & FileOptions.DeleteOnClose) != 0)
            flags |= 0x04000000;

        if ((options & FileOptions.WriteThrough) != 0)
            flags |= 0x80000000;

        if ((options & FileOptions.RandomAccess) != 0)
            flags |= 0x10000000;

        var desiredAccess = accessMode == FileAccess.Read ? 0x80000000u : 0xc0000000u;

        if ((options & FileOptions.DeleteOnClose) != 0)
            desiredAccess |= 0x00010000; // DELETE

        var handle = CreateFileW(path, desiredAccess, (uint)(1 | 2 | (shareDelete ? 4 : 0)), 0, disposition, flags, 0);
        if (handle.IsInvalid)
        {
            var error = NativeError("CreateFile", path);
            handle.Dispose();
            throw error;
        }

        if (noFollow)
        {
            if (!GetFileInformationByHandle(handle, out var info))
            {
                var error = NativeError("GetFileInformationByHandle", path);
                handle.Dispose();
                throw error;
            }

            if ((info.Attributes & 0x400) != 0)
            {
                handle.Dispose();
                throw new IOException("SQLITE_OPEN_NOFOLLOW rejects reparse points.");
            }
        }

        return handle;
    }

    internal readonly record struct FileIdentity(ulong Device, ulong Low, ulong High);

    internal static FileIdentity Identity(SafeFileHandle handle)
    {
        EnsureSupported();
        if (OperatingSystem.IsWindows())
        {
            if (!GetFileInformationByHandleEx(handle, 18, out var info, 24))
                throw NativeError("GetFileInformationByHandleEx(FileIdInfo)");

            return new FileIdentity(info.Volume, info.Low, info.High);
        }

        if (OperatingSystem.IsMacOS())
        {
            var identity = DarwinIdentity(handle);
            return new FileIdentity(identity.Device, identity.Inode, 0);
        }

        LinuxStat stat;
        if (fstatLinux(handle, &stat) != 0)
            throw NativeError("fstat");

        return new FileIdentity(stat.Device, stat.Inode, 0);
    }

    internal static int LockRange(SafeFileHandle handle, long start, long length, int kind)
    {
        lock (Gate)
            return SetRange(handle, start, length, kind);
    }

    // Query a desired write lock without changing ownership: 0 shared conflict,
    // 1 exclusive conflict, 2 no conflict. Unix DMS initialization needs this
    // distinction to avoid trusting a crashed initializer's stale wal-index.
    internal static int QueryRange(SafeFileHandle handle, long start, long length, out int kind)
    {
        lock (Gate)
        {
            kind = 2;
            int rc;
            if (OperatingSystem.IsMacOS())
            {
                var range = new DarwinFlock { Start = start, Length = length, Type = 3 };
                do
                {
                    rc = DarwinFcntl(handle, 7, &range);
                } while (rc < 0 && Marshal.GetLastPInvokeError() == 4);

                if (rc == 0)
                    kind = range.Type == 1 ? 0 : range.Type == 3 ? 1 : 2;
            }
            else if (OperatingSystem.IsLinux())
            {
                var range = new LinuxFlock { Start = start, Length = length, Type = 1 };
                do
                {
                    rc = fcntl(handle, 36, &range);
                } while (rc < 0 && Marshal.GetLastPInvokeError() == 4);

                if (rc == 0) kind = range.Type;
            }
            else
            {
                throw new PlatformNotSupportedException("Windows has no fcntl lock query.");
            }

            return rc == 0 ? 0 : SQLITE_IOERR_LOCK;
        }
    }

    // kind: 0 read/shared, 1 write/exclusive, 2 unlock. Calls never block.
    private static int SetRange(SafeFileHandle handle, long start, long length, int kind)
    {
#if HOST_VFS_PLATFORM_TESTS
        if (RangeOperationForTests is not null)
            return RangeOperationForTests(handle, start, length, kind);
#endif
        if (OperatingSystem.IsWindows())
        {
            var overlap = new Overlapped { Offset = (uint)start, OffsetHigh = (uint)(start >> 32) };
            var ok = kind == 2
                ? UnlockFileEx(handle, 0, (uint)length, 0, ref overlap)
                : LockFileEx(handle, (uint)(1 | (kind == 1 ? 2 : 0)), 0, (uint)length, 0, ref overlap);
            if (ok)
                return 0;

            var error = Marshal.GetLastPInvokeError();
            return kind != 2 && error is 32 or 33 ? SQLITE_BUSY : kind == 2 ? SQLITE_IOERR_UNLOCK : SQLITE_IOERR_LOCK;
        }

        int rc;
        do
        {
            if (OperatingSystem.IsMacOS())
            {
                var range = new DarwinFlock { Start = start, Length = length, Type = (short)(kind == 0 ? 1 : kind == 1 ? 3 : 2) };
                rc = DarwinFcntl(handle, 8, &range); // F_SETLK
            }
            else
            {
                var range = new LinuxFlock { Start = start, Length = length, Type = (short)kind };
                rc = fcntl(handle, 37, &range); // F_OFD_SETLK, l_pid must be zero.
            }
        } while (rc < 0 && Marshal.GetLastPInvokeError() == 4);

        if (rc == 0)
            return 0;

        var errno = Marshal.GetLastPInvokeError();
        return kind != 2 && errno is 11 or 13 or 35 ? SQLITE_BUSY : kind == 2 ? SQLITE_IOERR_UNLOCK : SQLITE_IOERR_LOCK;
    }

    private static int QueryReserved(SafeFileHandle handle, out bool held)
    {
        held = false;
        int rc;
        if (OperatingSystem.IsMacOS())
        {
            var range = new DarwinFlock { Start = ReservedByte, Length = 1, Type = 3 };
            do
            {
                rc = DarwinFcntl(handle, 7, &range);
            } while (rc < 0 && Marshal.GetLastPInvokeError() == 4);

            if (rc == 0) held = range.Type != 2;
        }
        else
        {
            var range = new LinuxFlock { Start = ReservedByte, Length = 1, Type = 1 };
            do
            {
                rc = fcntl(handle, 36, &range);
            } while (rc < 0 && Marshal.GetLastPInvokeError() == 4);

            if (rc == 0) held = range.Type != 2;
        }

        return rc == 0 ? 0 : SQLITE_IOERR_CHECKRESERVEDLOCK;
    }

    private static (uint Device, ulong Inode) DarwinIdentity(SafeFileHandle handle)
    {
        DarwinStat stat;
        var rc = RuntimeInformation.ProcessArchitecture == Architecture.Arm64
            ? fstatDarwinArm64(handle, &stat)
            : fstatDarwin(handle, &stat);
        if (rc != 0)
            throw NativeError("fstat");

        return (stat.Device, stat.Inode);
    }

    private static IOException NativeError(string operation, string? path = null)
    {
        var error = Marshal.GetLastPInvokeError();
        return new IOException($"{operation}{(path is null ? "" : " '" + path + "'")}: {new Win32Exception(error).Message} (OS error {error}).", error);
    }

    // Darwin arm64 variadic arguments are stack-passed. Six register placeholders
    // put open's mode / fcntl's third argument at the first stack argument slot.
    private static int UnixOpen(string path, int flags, uint mode)
    {
        int fd;
        do
        {
            fd = OperatingSystem.IsMacOS() && RuntimeInformation.ProcessArchitecture == Architecture.Arm64
                ? openDarwinArm64(path, flags, 0, 0, 0, 0, 0, 0, mode)
                : open(path, flags, mode);
        } while (fd < 0 && Marshal.GetLastPInvokeError() == 4);

        return fd;
    }

    private static int DarwinFcntl(SafeFileHandle handle, int command, void* argument) =>
        RuntimeInformation.ProcessArchitecture == Architecture.Arm64
            ? fcntlDarwinArm64(handle, command, 0, 0, 0, 0, 0, 0, argument)
            : fcntl(handle, command, argument);

    // Linux x64 and arm64 stat both begin with 64-bit dev/ino. Reserve enough
    // space for either libc layout; only the common leading fields are read.
    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct LinuxStat
    {
        [FieldOffset(0)] internal ulong Device;
        [FieldOffset(8)] internal ulong Inode;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WindowsFileId
    {
        internal ulong Volume, Low, High;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LinuxFlock
    {
        internal short Type, Whence;
        internal long Start, Length;
        internal int Pid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DarwinFlock
    {
        internal long Start, Length;
        internal int Pid;
        internal short Type, Whence;
    }

    [StructLayout(LayoutKind.Explicit, Size = 144)]
    private struct DarwinStat
    {
        [FieldOffset(0)] internal uint Device;
        [FieldOffset(8)] internal ulong Inode;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Overlapped
    {
        internal nuint Internal, InternalHigh;
        internal uint Offset, OffsetHigh;
        internal nint Event;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WindowsFileInformation
    {
        internal uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh;
        internal uint VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }

    [System.Runtime.CompilerServices.SkipLocalsInitAttribute]
    private static int open(string path, int flags, uint mode)
    {
        int __lastError;
        var __retVal = 0;
        // Setup - Perform required setup.
        scoped var __path_native__marshaller = new Utf8StringMarshaller.ManagedToUnmanagedIn();
        try
        {
            // Marshal - Convert managed data to native data.
            __path_native__marshaller.FromManaged(path, stackalloc byte[Utf8StringMarshaller.ManagedToUnmanagedIn.BufferSize]);
            {
                // PinnedMarshal - Convert managed data to native data that requires the managed data to be pinned.
                var __path_native = __path_native__marshaller.ToUnmanaged();
                Marshal.SetLastSystemError(0);
                __retVal = __PInvoke(__path_native, flags, mode);
                __lastError = Marshal.GetLastSystemError();
            }
        }
        finally
        {
            // CleanupCallerAllocated - Perform cleanup of caller allocated resources.
            __path_native__marshaller.Free();
        }

        Marshal.SetLastPInvokeError(__lastError);
        return __retVal;

        // Local P/Invoke
        [DllImport("libc", EntryPoint = "open", ExactSpelling = true)]
        static extern int __PInvoke(byte* __path_native, int __flags_native, uint __mode_native);
    }

    [System.Runtime.CompilerServices.SkipLocalsInitAttribute]
    private static int openDarwinArm64(string path, int flags, nint p1, nint p2, nint p3, nint p4, nint p5, nint p6, uint mode)
    {
        int __lastError;
        var __retVal = 0;
        // Setup - Perform required setup.
        scoped var __path_native__marshaller = new Utf8StringMarshaller.ManagedToUnmanagedIn();
        try
        {
            // Marshal - Convert managed data to native data.
            __path_native__marshaller.FromManaged(path, stackalloc byte[Utf8StringMarshaller.ManagedToUnmanagedIn.BufferSize]);
            {
                // PinnedMarshal - Convert managed data to native data that requires the managed data to be pinned.
                var __path_native = __path_native__marshaller.ToUnmanaged();
                Marshal.SetLastSystemError(0);
                __retVal = __PInvoke(__path_native, flags, p1, p2, p3, p4, p5, p6, mode);
                __lastError = Marshal.GetLastSystemError();
            }
        }
        finally
        {
            // CleanupCallerAllocated - Perform cleanup of caller allocated resources.
            __path_native__marshaller.Free();
        }

        Marshal.SetLastPInvokeError(__lastError);
        return __retVal;

        // Local P/Invoke
        [DllImport("libc", EntryPoint = "open", ExactSpelling = true)]
        static extern int __PInvoke(byte* __path_native, int __flags_native, nint __p1_native, nint __p2_native, nint __p3_native, nint __p4_native, nint __p5_native, nint __p6_native, uint __mode_native);
    }

    [System.Runtime.CompilerServices.SkipLocalsInitAttribute]
    private static int fcntl(SafeFileHandle handle, int command, void* argument)
    {
        int __lastError;
        var __retVal = 0;
        // Setup - Perform required setup.
        var __handle_native__marshaller = new SafeHandleMarshaller<SafeFileHandle>.ManagedToUnmanagedIn();
        try
        {
            // Marshal - Convert managed data to native data.
            __handle_native__marshaller.FromManaged(handle);
            {
                // PinnedMarshal - Convert managed data to native data that requires the managed data to be pinned.
                var __handle_native = __handle_native__marshaller.ToUnmanaged();
                Marshal.SetLastSystemError(0);
                __retVal = __PInvoke(__handle_native, command, argument);
                __lastError = Marshal.GetLastSystemError();
            }
        }
        finally
        {
            // CleanupCallerAllocated - Perform cleanup of caller allocated resources.
            __handle_native__marshaller.Free();
        }

        Marshal.SetLastPInvokeError(__lastError);
        return __retVal;

        // Local P/Invoke
        [DllImport("libc", EntryPoint = "fcntl", ExactSpelling = true)]
        static extern int __PInvoke(nint __handle_native, int __command_native, void* __argument_native);
    }

    [System.Runtime.CompilerServices.SkipLocalsInitAttribute]
    private static int fcntlDarwinArm64(SafeFileHandle handle, int command, nint p1, nint p2, nint p3, nint p4, nint p5, nint p6, void* argument)
    {
        int __lastError;
        var __retVal = 0;
        // Setup - Perform required setup.
        var __handle_native__marshaller = new SafeHandleMarshaller<SafeFileHandle>.ManagedToUnmanagedIn();
        try
        {
            // Marshal - Convert managed data to native data.
            __handle_native__marshaller.FromManaged(handle);
            {
                // PinnedMarshal - Convert managed data to native data that requires the managed data to be pinned.
                var __handle_native = __handle_native__marshaller.ToUnmanaged();
                Marshal.SetLastSystemError(0);
                __retVal = __PInvoke(__handle_native, command, p1, p2, p3, p4, p5, p6, argument);
                __lastError = Marshal.GetLastSystemError();
            }
        }
        finally
        {
            // CleanupCallerAllocated - Perform cleanup of caller allocated resources.
            __handle_native__marshaller.Free();
        }

        Marshal.SetLastPInvokeError(__lastError);
        return __retVal;

        // Local P/Invoke
        [DllImport("libc", EntryPoint = "fcntl", ExactSpelling = true)]
        static extern int __PInvoke(nint __handle_native, int __command_native, nint __p1_native, nint __p2_native, nint __p3_native, nint __p4_native, nint __p5_native, nint __p6_native, void* __argument_native);
    }

    [System.Runtime.CompilerServices.SkipLocalsInitAttribute]
    private static int fsync(SafeFileHandle handle)
    {
        int __lastError;
        var __retVal = 0;
        // Setup - Perform required setup.
        var __handle_native__marshaller = new SafeHandleMarshaller<SafeFileHandle>.ManagedToUnmanagedIn();
        try
        {
            // Marshal - Convert managed data to native data.
            __handle_native__marshaller.FromManaged(handle);
            {
                // PinnedMarshal - Convert managed data to native data that requires the managed data to be pinned.
                var __handle_native = __handle_native__marshaller.ToUnmanaged();
                Marshal.SetLastSystemError(0);
                __retVal = __PInvoke(__handle_native);
                __lastError = Marshal.GetLastSystemError();
            }
        }
        finally
        {
            // CleanupCallerAllocated - Perform cleanup of caller allocated resources.
            __handle_native__marshaller.Free();
        }

        Marshal.SetLastPInvokeError(__lastError);
        return __retVal;

        // Local P/Invoke
        [DllImport("libc", EntryPoint = "fsync", ExactSpelling = true)]
        static extern int __PInvoke(nint __handle_native);
    }

    [System.Runtime.CompilerServices.SkipLocalsInitAttribute]
    private static int unlink(string path)
    {
        int __lastError;
        var __retVal = 0;
        // Setup - Perform required setup.
        scoped var __path_native__marshaller = new Utf8StringMarshaller.ManagedToUnmanagedIn();
        try
        {
            // Marshal - Convert managed data to native data.
            __path_native__marshaller.FromManaged(path, stackalloc byte[Utf8StringMarshaller.ManagedToUnmanagedIn.BufferSize]);
            {
                // PinnedMarshal - Convert managed data to native data that requires the managed data to be pinned.
                var __path_native = __path_native__marshaller.ToUnmanaged();
                Marshal.SetLastSystemError(0);
                __retVal = __PInvoke(__path_native);
                __lastError = Marshal.GetLastSystemError();
            }
        }
        finally
        {
            // CleanupCallerAllocated - Perform cleanup of caller allocated resources.
            __path_native__marshaller.Free();
        }

        Marshal.SetLastPInvokeError(__lastError);
        return __retVal;

        // Local P/Invoke
        [DllImport("libc", EntryPoint = "unlink", ExactSpelling = true)]
        static extern int __PInvoke(byte* __path_native);
    }

    [System.Runtime.CompilerServices.SkipLocalsInitAttribute]
    private static int access(string path, int mode)
    {
        int __lastError;
        var __retVal = 0;
        // Setup - Perform required setup.
        scoped var __path_native__marshaller = new Utf8StringMarshaller.ManagedToUnmanagedIn();
        try
        {
            // Marshal - Convert managed data to native data.
            __path_native__marshaller.FromManaged(path, stackalloc byte[Utf8StringMarshaller.ManagedToUnmanagedIn.BufferSize]);
            {
                // PinnedMarshal - Convert managed data to native data that requires the managed data to be pinned.
                var __path_native = __path_native__marshaller.ToUnmanaged();
                Marshal.SetLastSystemError(0);
                __retVal = __PInvoke(__path_native, mode);
                __lastError = Marshal.GetLastSystemError();
            }
        }
        finally
        {
            // CleanupCallerAllocated - Perform cleanup of caller allocated resources.
            __path_native__marshaller.Free();
        }

        Marshal.SetLastPInvokeError(__lastError);
        return __retVal;

        // Local P/Invoke
        [DllImport("libc", EntryPoint = "access", ExactSpelling = true)]
        static extern int __PInvoke(byte* __path_native, int __mode_native);
    }

    [System.Runtime.CompilerServices.SkipLocalsInitAttribute]
    private static int fstatLinux(SafeFileHandle handle, LinuxStat* stat)
    {
        int __lastError;
        var __retVal = 0;
        // Setup - Perform required setup.
        var __handle_native__marshaller = new SafeHandleMarshaller<SafeFileHandle>.ManagedToUnmanagedIn();
        try
        {
            // Marshal - Convert managed data to native data.
            __handle_native__marshaller.FromManaged(handle);
            {
                // PinnedMarshal - Convert managed data to native data that requires the managed data to be pinned.
                var __handle_native = __handle_native__marshaller.ToUnmanaged();
                Marshal.SetLastSystemError(0);
                __retVal = __PInvoke(__handle_native, stat);
                __lastError = Marshal.GetLastSystemError();
            }
        }
        finally
        {
            // CleanupCallerAllocated - Perform cleanup of caller allocated resources.
            __handle_native__marshaller.Free();
        }

        Marshal.SetLastPInvokeError(__lastError);
        return __retVal;

        // Local P/Invoke
        [DllImport("libc", EntryPoint = "fstat", ExactSpelling = true)]
        static extern int __PInvoke(nint __handle_native, LinuxStat* __stat_native);
    }

    [System.Runtime.CompilerServices.SkipLocalsInitAttribute]
    private static int fstatDarwin(SafeFileHandle handle, DarwinStat* stat)
    {
        int __lastError;
        var __retVal = 0;
        // Setup - Perform required setup.
        var __handle_native__marshaller = new SafeHandleMarshaller<SafeFileHandle>.ManagedToUnmanagedIn();
        try
        {
            // Marshal - Convert managed data to native data.
            __handle_native__marshaller.FromManaged(handle);
            {
                // PinnedMarshal - Convert managed data to native data that requires the managed data to be pinned.
                var __handle_native = __handle_native__marshaller.ToUnmanaged();
                Marshal.SetLastSystemError(0);
                __retVal = __PInvoke(__handle_native, stat);
                __lastError = Marshal.GetLastSystemError();
            }
        }
        finally
        {
            // CleanupCallerAllocated - Perform cleanup of caller allocated resources.
            __handle_native__marshaller.Free();
        }

        Marshal.SetLastPInvokeError(__lastError);
        return __retVal;

        // Local P/Invoke
        [DllImport("libc", EntryPoint = "fstat$INODE64", ExactSpelling = true)]
        static extern int __PInvoke(nint __handle_native, DarwinStat* __stat_native);
    }

    [System.Runtime.CompilerServices.SkipLocalsInitAttribute]
    private static int fstatDarwinArm64(SafeFileHandle handle, DarwinStat* stat)
    {
        int __lastError;
        var __retVal = 0;
        // Setup - Perform required setup.
        var __handle_native__marshaller = new SafeHandleMarshaller<SafeFileHandle>.ManagedToUnmanagedIn();
        try
        {
            // Marshal - Convert managed data to native data.
            __handle_native__marshaller.FromManaged(handle);
            {
                // PinnedMarshal - Convert managed data to native data that requires the managed data to be pinned.
                var __handle_native = __handle_native__marshaller.ToUnmanaged();
                Marshal.SetLastSystemError(0);
                __retVal = __PInvoke(__handle_native, stat);
                __lastError = Marshal.GetLastSystemError();
            }
        }
        finally
        {
            // CleanupCallerAllocated - Perform cleanup of caller allocated resources.
            __handle_native__marshaller.Free();
        }

        Marshal.SetLastPInvokeError(__lastError);
        return __retVal;

        // Local P/Invoke
        [DllImport("libc", EntryPoint = "fstat", ExactSpelling = true)]
        static extern int __PInvoke(nint __handle_native, DarwinStat* __stat_native);
    }

    [System.Runtime.CompilerServices.SkipLocalsInitAttribute]
    private static SafeFileHandle CreateFileW(string path, uint access, uint share, nint security, uint disposition, uint flags, nint template)
    {
        int __lastError;
        var __invokeSucceeded = false;
        SafeFileHandle? __retVal = null;
        // Setup - Perform required setup.
        var __retVal_native__marshaller = new SafeHandleMarshaller<SafeFileHandle>.ManagedToUnmanagedOut();
        try
        {
            // Pin - Pin data in preparation for calling the P/Invoke.
            nint __retVal_native = 0;
            fixed (void* __path_native = &Utf16StringMarshaller.GetPinnableReference(path))
            {
                Marshal.SetLastSystemError(0);
                __retVal_native = __PInvoke((ushort*)__path_native, access, share, security, disposition, flags, template);
                __lastError = Marshal.GetLastSystemError();
            }

            __invokeSucceeded = true;
            // UnmarshalCapture - Capture the native data into marshaller instances in case conversion to managed data throws an exception.
            __retVal_native__marshaller.FromUnmanaged(__retVal_native);
            // Unmarshal - Convert native data to managed data.
            __retVal = __retVal_native__marshaller.ToManaged();
        }
        finally
        {
            if (__invokeSucceeded)
            {
                // CleanupCalleeAllocated - Perform cleanup of callee allocated resources.
                __retVal_native__marshaller.Free();
            }
        }

        Marshal.SetLastPInvokeError(__lastError);
        return __retVal;

        // Local P/Invoke
        [DllImport("kernel32", EntryPoint = "CreateFileW", ExactSpelling = true)]
        static extern nint __PInvoke(ushort* __path_native, uint __access_native, uint __share_native, nint __security_native, uint __disposition_native, uint __flags_native, nint __template_native);
    }

    [System.Runtime.CompilerServices.SkipLocalsInitAttribute]
    private static uint GetFileAttributesW(string path)
    {
        int __lastError;
        uint __retVal;
        // Pin - Pin data in preparation for calling the P/Invoke.
        fixed (void* __path_native = &Utf16StringMarshaller.GetPinnableReference(path))
        {
            Marshal.SetLastSystemError(0);
            __retVal = __PInvoke((ushort*)__path_native);
            __lastError = Marshal.GetLastSystemError();
        }

        Marshal.SetLastPInvokeError(__lastError);
        return __retVal;

        // Local P/Invoke
        [DllImport("kernel32", EntryPoint = "GetFileAttributesW", ExactSpelling = true)]
        static extern uint __PInvoke(ushort* __path_native);
    }

    [System.Runtime.CompilerServices.SkipLocalsInitAttribute]
    private static bool GetFileInformationByHandle(SafeFileHandle handle, out WindowsFileInformation information)
    {
        int __lastError;
        information = default;
        var __retVal = false;
        // Setup - Perform required setup.
        var __handle_native__marshaller = new SafeHandleMarshaller<SafeFileHandle>.ManagedToUnmanagedIn();
        try
        {
            // Marshal - Convert managed data to native data.
            __handle_native__marshaller.FromManaged(handle);
            // Pin - Pin data in preparation for calling the P/Invoke.
            var __retVal_native = 0;
            fixed (WindowsFileInformation* __information_native = &information)
            {
                // PinnedMarshal - Convert managed data to native data that requires the managed data to be pinned.
                var __handle_native = __handle_native__marshaller.ToUnmanaged();
                Marshal.SetLastSystemError(0);
                __retVal_native = __PInvoke(__handle_native, __information_native);
                __lastError = Marshal.GetLastSystemError();
            }

            // Unmarshal - Convert native data to managed data.
            __retVal = __retVal_native != 0;
        }
        finally
        {
            // CleanupCallerAllocated - Perform cleanup of caller allocated resources.
            __handle_native__marshaller.Free();
        }

        Marshal.SetLastPInvokeError(__lastError);
        return __retVal;

        // Local P/Invoke
        [DllImport("kernel32", EntryPoint = "GetFileInformationByHandle", ExactSpelling = true)]
        static extern int __PInvoke(nint __handle_native, WindowsFileInformation* __information_native);
    }

    [System.Runtime.CompilerServices.SkipLocalsInitAttribute]
    private static bool GetFileInformationByHandleEx(SafeFileHandle handle, int informationClass, out WindowsFileId information, uint size)
    {
        int __lastError;
        information = default;
        var __retVal = false;
        // Setup - Perform required setup.
        var __handle_native__marshaller = new SafeHandleMarshaller<SafeFileHandle>.ManagedToUnmanagedIn();
        try
        {
            // Marshal - Convert managed data to native data.
            __handle_native__marshaller.FromManaged(handle);
            // Pin - Pin data in preparation for calling the P/Invoke.
            var __retVal_native = 0;
            fixed (WindowsFileId* __information_native = &information)
            {
                // PinnedMarshal - Convert managed data to native data that requires the managed data to be pinned.
                var __handle_native = __handle_native__marshaller.ToUnmanaged();
                Marshal.SetLastSystemError(0);
                __retVal_native = __PInvoke(__handle_native, informationClass, __information_native, size);
                __lastError = Marshal.GetLastSystemError();
            }

            // Unmarshal - Convert native data to managed data.
            __retVal = __retVal_native != 0;
        }
        finally
        {
            // CleanupCallerAllocated - Perform cleanup of caller allocated resources.
            __handle_native__marshaller.Free();
        }

        Marshal.SetLastPInvokeError(__lastError);
        return __retVal;

        // Local P/Invoke
        [DllImport("kernel32", EntryPoint = "GetFileInformationByHandleEx", ExactSpelling = true)]
        static extern int __PInvoke(nint __handle_native, int __informationClass_native, WindowsFileId* __information_native, uint __size_native);
    }

    [System.Runtime.CompilerServices.SkipLocalsInitAttribute]
    private static bool LockFileEx(SafeFileHandle handle, uint flags, uint reserved, uint lengthLow, uint lengthHigh, ref Overlapped overlap)
    {
        int __lastError;
        var __retVal = false;
        // Setup - Perform required setup.
        var __handle_native__marshaller = new SafeHandleMarshaller<SafeFileHandle>.ManagedToUnmanagedIn();
        try
        {
            // Marshal - Convert managed data to native data.
            __handle_native__marshaller.FromManaged(handle);
            // Pin - Pin data in preparation for calling the P/Invoke.
            var __retVal_native = 0;
            fixed (Overlapped* __overlap_native = &overlap)
            {
                // PinnedMarshal - Convert managed data to native data that requires the managed data to be pinned.
                var __handle_native = __handle_native__marshaller.ToUnmanaged();
                Marshal.SetLastSystemError(0);
                __retVal_native = __PInvoke(__handle_native, flags, reserved, lengthLow, lengthHigh, __overlap_native);
                __lastError = Marshal.GetLastSystemError();
            }

            // Unmarshal - Convert native data to managed data.
            __retVal = __retVal_native != 0;
        }
        finally
        {
            // CleanupCallerAllocated - Perform cleanup of caller allocated resources.
            __handle_native__marshaller.Free();
        }

        Marshal.SetLastPInvokeError(__lastError);
        return __retVal;

        // Local P/Invoke
        [DllImport("kernel32", EntryPoint = "LockFileEx", ExactSpelling = true)]
        static extern int __PInvoke(nint __handle_native, uint __flags_native, uint __reserved_native, uint __lengthLow_native, uint __lengthHigh_native, Overlapped* __overlap_native);
    }

    [System.Runtime.CompilerServices.SkipLocalsInitAttribute]
    private static bool UnlockFileEx(SafeFileHandle handle, uint reserved, uint lengthLow, uint lengthHigh, ref Overlapped overlap)
    {
        int __lastError;
        var __retVal = false;
        // Setup - Perform required setup.
        var __handle_native__marshaller = new SafeHandleMarshaller<SafeFileHandle>.ManagedToUnmanagedIn();
        try
        {
            // Marshal - Convert managed data to native data.
            __handle_native__marshaller.FromManaged(handle);
            // Pin - Pin data in preparation for calling the P/Invoke.
            var retValNative = 0;
            fixed (Overlapped* __overlap_native = &overlap)
            {
                // PinnedMarshal - Convert managed data to native data that requires the managed data to be pinned.
                var handleNative = __handle_native__marshaller.ToUnmanaged();
                Marshal.SetLastSystemError(0);
                retValNative = __PInvoke(handleNative, reserved, lengthLow, lengthHigh, __overlap_native);
                __lastError = Marshal.GetLastSystemError();
            }

            // Unmarshal - Convert native data to managed data.
            __retVal = retValNative != 0;
        }
        finally
        {
            // CleanupCallerAllocated - Perform cleanup of caller allocated resources.
            __handle_native__marshaller.Free();
        }

        Marshal.SetLastPInvokeError(__lastError);
        return __retVal;

        // Local P/Invoke
        [DllImport("kernel32", EntryPoint = "UnlockFileEx", ExactSpelling = true)]
        static extern int __PInvoke(nint __handle_native, uint __reserved_native, uint __lengthLow_native, uint __lengthHigh_native, Overlapped* __overlap_native);
    }
}
