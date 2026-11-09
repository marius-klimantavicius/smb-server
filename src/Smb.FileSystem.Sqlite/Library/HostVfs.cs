using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using static Managed.Database.Sqlite;

namespace Managed.Database;

/// <summary>File-backed SQLite rollback-journal and WAL VFS. OS services only; no native SQLite.</summary>
public static unsafe partial class HostVfs
{
    private const int PathBytes = 32768;

    private static readonly Lock RegistrationGate = new Lock();
    private static sqlite3_vfs* _registeredVfs;
    private static sqlite3_io_methods* _registeredMethods;
    private static int _openHandles;

    [ThreadStatic] private static string? _lastError;
    [ThreadStatic] private static int _lastErrorNumber;

    // Each method address is captured once. Copies into unmanaged tables retain
    // identical pointer bits through tiering and collection.
    private static readonly sqlite3_io_methods MethodTable = new sqlite3_io_methods
    {
        iVersion = 3,
        xClose = &Close,
        xRead = &Read,
        xWrite = &Write,
        xTruncate = &Truncate,
        xSync = &Sync,
        xFileSize = &FileSize,
        xLock = &Lock,
        xUnlock = &Unlock,
        xCheckReservedLock = &CheckReserved,
        xFileControl = &FileControl,
        xSectorSize = &SectorSize,
        xDeviceCharacteristics = &DeviceCharacteristics,
        xShmMap = &ShmMap,
        xShmLock = &ShmLock,
        xShmBarrier = &ShmBarrier,
        xShmUnmap = &ShmUnmap,
        xFetch = &Fetch,
        xUnfetch = &Unfetch,
    };

    private static readonly sqlite3_vfs VfsTable = new sqlite3_vfs
    {
        iVersion = 2,
        szOsFile = sizeof(FileRecord),
        mxPathname = PathBytes - 1,
        xOpen = &Open,
        xDelete = &Delete,
        xAccess = &Access,
        xFullPathname = &FullPath,
        xRandomness = &Randomness,
        xSleep = &Sleep,
        xCurrentTime = &CurrentTime,
        xCurrentTimeInt64 = &CurrentTimeInt64,
        xGetLastError = &GetLastError,
    };

    [StructLayout(LayoutKind.Sequential)]
    private struct FileRecord
    {
        public sqlite3_file Base;
        public nint Context;
    }

    private sealed class OpenFile
    {
        public required HostPlatform.FileHandle File;
        public required string Path;
        public bool IsReadOnly;
        public bool NeedsDirectorySync;
        public HostSharedMemory.Connection? SharedMemory;
        public DatabaseMapping? Mapping;
    }

    public static int OpenHandleCount => Volatile.Read(ref _openHandles);

    // Called explicitly by the translated sqlite3_os_init/sqlite3_os_end hooks.
    public static int RegisterVfs()
    {
        try
        {
            lock (RegistrationGate)
            {
                if (_registeredVfs == null)
                {
                    sqlite3_io_methods* methods = null;
                    sqlite3_vfs* vfs = null;
                    byte* name = null;
                    try
                    {
                        methods = (sqlite3_io_methods*)NativeMemory.Alloc((nuint)sizeof(sqlite3_io_methods));
                        vfs = (sqlite3_vfs*)NativeMemory.Alloc((nuint)sizeof(sqlite3_vfs));
                        name = (byte*)NativeMemory.Alloc(11);
                        if (methods == null || vfs == null || name == null) return SQLITE_NOMEM;

                        *methods = MethodTable;
                        *vfs = VfsTable;
                        "dotcc-host\0"u8.CopyTo(new Span<byte>(name, 11));
                        vfs->zName = name;
                        _registeredMethods = methods;
                        _registeredVfs = vfs;
                    }
                    finally
                    {
                        if (_registeredVfs == null)
                        {
                            NativeMemory.Free(methods);
                            NativeMemory.Free(vfs);
                            NativeMemory.Free(name);
                        }
                    }
                }

                return sqlite3_vfs_register(_registeredVfs, 1);
            }
        }
        catch (Exception exception) { return Failure(exception, SQLITE_ERROR); }
    }

    public static int UnregisterVfs()
    {
        lock (RegistrationGate)
        {
            if (OpenHandleCount != 0) return SQLITE_BUSY;

            // Keep the small canonical tables for initialization after shutdown.
            // No live SQLite registration may retain freed callback table memory.
            return _registeredVfs == null ? SQLITE_OK : sqlite3_vfs_unregister(_registeredVfs);
        }
    }

    private static OpenFile State(sqlite3_file* file) => (OpenFile)GCHandle.FromIntPtr(((FileRecord*)file)->Context).Target!;

    private static int Failure(Exception exception, int result)
    {
        _lastError = exception.Message;
        _lastErrorNumber = exception.HResult;
        if (exception is OutOfMemoryException)
            return SQLITE_NOMEM;

        // HRESULT_FROM_WIN32 on Windows and the native errno preserved by Unix IO.
        var code = exception.HResult & 0xffff;
        if (exception is IOException && (OperatingSystem.IsWindows() ? code is 112 or 39 : code == 28))
            return SQLITE_FULL;

        return result;
    }

    private static string Decode(byte* text) => Marshal.PtrToStringUTF8((nint)text) ?? throw new ArgumentNullException(nameof(text));

    private static int Open(sqlite3_vfs* vfs, byte* name, sqlite3_file* file, int flags, int* outputFlags)
    {
        file->pMethods = null;
        ((FileRecord*)file)->Context = 0;
        HostPlatform.FileHandle? handle = null;

        try
        {
            var temporary = name == null;
            var path = temporary
                ? Path.Combine(Path.GetTempPath(), "dotcc-sqlite-" + Guid.NewGuid().ToString("N"))
                : Path.GetFullPath(Decode(name));
            if (Directory.Exists(path))
                return SQLITE_CANTOPEN;

            var readOnly = (flags & SQLITE_OPEN_READONLY) != 0;
            if (readOnly == ((flags & SQLITE_OPEN_READWRITE) != 0))
                return SQLITE_CANTOPEN;

            var delete = temporary || (flags & SQLITE_OPEN_DELETEONCLOSE) != 0;
            var mode = temporary || (flags & (SQLITE_OPEN_CREATE | SQLITE_OPEN_EXCLUSIVE)) == (SQLITE_OPEN_CREATE | SQLITE_OPEN_EXCLUSIVE)
                ? FileMode.CreateNew
                : (flags & SQLITE_OPEN_CREATE) != 0
                    ? FileMode.OpenOrCreate
                    : FileMode.Open;

            if (readOnly && mode != FileMode.Open)
                return SQLITE_CANTOPEN;

            var options = delete ? FileOptions.DeleteOnClose : FileOptions.None;
            try
            {
                handle = HostPlatform.Open(path, mode, readOnly ? FileAccess.Read : FileAccess.ReadWrite, options, (flags & SQLITE_OPEN_NOFOLLOW) != 0);
            }
            catch (Exception exception) when (
                !readOnly
                && !temporary
                && (flags & (SQLITE_OPEN_MAIN_DB | SQLITE_OPEN_WAL)) != 0
                && (flags & SQLITE_OPEN_EXCLUSIVE) == 0
                && exception is IOException or UnauthorizedAccessException)
            {
                // SQLite opens WAL files as READWRITE even for readonly databases,
                // then honors the returned READONLY flag for readable existing files.
                handle = HostPlatform.Open(path, FileMode.Open, FileAccess.Read, options, (flags & SQLITE_OPEN_NOFOLLOW) != 0);
                readOnly = true;
            }

            var state = new OpenFile
            {
                File = handle,
                Path = path,
                IsReadOnly = readOnly,
                NeedsDirectorySync = !delete && !readOnly && (flags & SQLITE_OPEN_CREATE) != 0,
                Mapping = (flags & SQLITE_OPEN_MAIN_DB) != 0
                    ? new DatabaseMapping(handle.Handle)
                    : null,
            };
            var context = GCHandle.Alloc(state);
            ((FileRecord*)file)->Context = GCHandle.ToIntPtr(context);
            file->pMethods = _registeredMethods;
            Interlocked.Increment(ref _openHandles);

            if (outputFlags != null)
                *outputFlags = (flags & ~(SQLITE_OPEN_READONLY | SQLITE_OPEN_READWRITE)) | (readOnly ? SQLITE_OPEN_READONLY : SQLITE_OPEN_READWRITE);

            return SQLITE_OK;
        }
        catch (Exception exception)
        {
            try { handle?.Dispose(); }
            catch
            {
                /* Preserve the original open failure. */
            }

            return Failure(exception, SQLITE_CANTOPEN);
        }
    }

    private static int Close(sqlite3_file* file)
    {
        try
        {
            var state = State(file);
            try { return ShmUnmap(file, 0); }
            finally
            {
                try { state.Mapping?.Dispose(); }
                finally { state.File.Dispose(); }
            }
        }
        catch (Exception exception)
        {
            return Failure(exception, SQLITE_IOERR_CLOSE);
        }
        finally
        {
            GCHandle.FromIntPtr(((FileRecord*)file)->Context).Free();
            ((FileRecord*)file)->Context = 0;
            file->pMethods = null;
            Interlocked.Decrement(ref _openHandles);
        }
    }

    private static bool ValidRange(int count, long offset) => count >= 0 && offset >= 0 && offset <= long.MaxValue - count;

    private static int Read(sqlite3_file* file, void* buffer, int count, long offset)
    {
        try
        {
            if (!ValidRange(count, offset))
                return SQLITE_IOERR_READ;

            var destination = new Span<byte>(buffer, count);
            var total = 0;
            while (total < count)
            {
                var read = RandomAccess.Read(State(file).File.Handle, destination[total..], offset + total);
                if (read == 0)
                {
                    destination[total..].Clear();
                    return SQLITE_IOERR_SHORT_READ;
                }

                total += read;
            }

            return SQLITE_OK;
        }
        catch (Exception exception)
        {
            return Failure(exception, SQLITE_IOERR_READ);
        }
    }

    private static int Write(sqlite3_file* file, void* buffer, int count, long offset)
    {
        try
        {
            if (State(file).IsReadOnly)
                return SQLITE_READONLY;

            if (!ValidRange(count, offset))
                return SQLITE_IOERR_WRITE;

            RandomAccess.Write(State(file).File.Handle, new ReadOnlySpan<byte>(buffer, count), offset);
            return SQLITE_OK;
        }
        catch (Exception exception)
        {
            return Failure(exception, SQLITE_IOERR_WRITE);
        }
    }

    private static int Truncate(sqlite3_file* file, long size)
    {
        try
        {
            if (State(file).IsReadOnly)
                return SQLITE_READONLY;

            if (size < 0)
                return SQLITE_IOERR_TRUNCATE;

            var ready = State(file).Mapping?.BeforeTruncate() ?? SQLITE_OK;
            if (ready != SQLITE_OK)
                return ready;

            RandomAccess.SetLength(State(file).File.Handle, size);
            return SQLITE_OK;
        }
        catch (Exception exception)
        {
            return Failure(exception, SQLITE_IOERR_TRUNCATE);
        }
    }

    private static int Sync(sqlite3_file* file, int flags)
    {
        try
        {
            var state = State(file);
            HostPlatform.Sync(state.File.Handle, (flags & 0xf) == 3);
            if (state.NeedsDirectorySync)
            {
                try
                {
                    HostPlatform.SyncDirectory(Path.GetDirectoryName(state.Path)!);
                }
                catch (Exception exception)
                {
                    return Failure(exception, SQLITE_IOERR_DIR_FSYNC);
                }

                state.NeedsDirectorySync = false;
            }

            return SQLITE_OK;
        }
        catch (Exception exception)
        {
            return Failure(exception, SQLITE_IOERR_FSYNC);
        }
    }

    private static int FileSize(sqlite3_file* file, long* size)
    {
        try
        {
            *size = RandomAccess.GetLength(State(file).File.Handle);
            return SQLITE_OK;
        }
        catch (Exception exception)
        {
            return Failure(exception, SQLITE_IOERR_FSTAT);
        }
    }

    private static int Lock(sqlite3_file* file, int level)
    {
        try
        {
            return State(file).File.Lock(level);
        }
        catch (Exception exception)
        {
            return Failure(exception, SQLITE_IOERR_LOCK);
        }
    }

    private static int Unlock(sqlite3_file* file, int level)
    {
        try
        {
            var state = State(file);
            if (level == 0)
                state.Mapping?.ReleaseIdle();

            return state.File.Unlock(level);
        }
        catch (Exception exception)
        {
            return Failure(exception, SQLITE_IOERR_UNLOCK);
        }
    }

    private static int CheckReserved(sqlite3_file* file, int* result)
    {
        *result = 0;
        try
        {
            var rc = State(file).File.CheckReserved(out var reserved);
            *result = reserved ? 1 : 0;
            return rc;
        }
        catch (Exception exception)
        {
            return Failure(exception, SQLITE_IOERR_CHECKRESERVEDLOCK);
        }
    }

    private static int ShmMap(sqlite3_file* file, int region, int size, int extend, void** output)
    {
        *output = null;
        try
        {
            var state = State(file);
            if (state.SharedMemory == null)
            {
                var opened = HostSharedMemory.Open(state.File, state.Path, out state.SharedMemory);
                if (opened != SQLITE_OK)
                    return opened;
            }

            var result = state.SharedMemory!.Map(region, size, extend != 0, out var address);
            *output = (void*)address;
            return result;
        }
        catch (Exception exception)
        {
            return Failure(exception, SQLITE_IOERR_SHMMAP);
        }
    }

    private static int ShmLock(sqlite3_file* file, int offset, int count, int flags)
    {
        try
        {
            return State(file).SharedMemory?.Lock(offset, count, flags) ?? SQLITE_IOERR_SHMLOCK;
        }
        catch (Exception exception)
        {
            return Failure(exception, SQLITE_IOERR_SHMLOCK);
        }
    }

    private static void ShmBarrier(sqlite3_file* file) => HostSharedMemory.Barrier();

    private static int ShmUnmap(sqlite3_file* file, int delete)
    {
        var state = State(file);
        try
        {
            return state.SharedMemory?.Unmap(delete != 0) ?? SQLITE_OK;
        }
        catch (Exception exception)
        {
            return Failure(exception, SQLITE_IOERR_SEEK);
        }
        finally
        {
            state.SharedMemory = null;
        }
    }

    private static int FileControl(sqlite3_file* file, int operation, void* argument)
    {
        try
        {
            switch (operation)
            {
                case 1:
                    *(int*)argument = State(file).File.LockLevel;
                    return SQLITE_OK; // LOCKSTATE

                case 4:
                    *(int*)argument = _lastErrorNumber;
                    return SQLITE_OK; // LAST_ERRNO

                case 5: return SQLITE_OK; // SIZE_HINT is an optional allocation hint.
                case 18: // MMAP_SIZE: query/set advisory cap, returning previous cap.
                    if (State(file).Mapping is { } mapping) return mapping.Configure((long*)argument);

                    *(long*)argument = 0;
                    return SQLITE_OK;

                default:
                    return SQLITE_NOTFOUND;
            }
        }
        catch (Exception exception)
        {
            return Failure(exception, SQLITE_IOERR);
        }
    }

    private static int SectorSize(sqlite3_file* file) => 4096;
    private static int DeviceCharacteristics(sqlite3_file* file) => 0;

    private static int Delete(sqlite3_vfs* vfs, byte* name, int syncDirectory)
    {
        try
        {
            var path = Path.GetFullPath(Decode(name));
            File.Delete(path);
            if (syncDirectory != 0)
            {
                try
                {
                    HostPlatform.SyncDirectory(Path.GetDirectoryName(path)!);
                }
                catch (Exception exception)
                {
                    return Failure(exception, SQLITE_IOERR_DIR_FSYNC);
                }
            }

            return SQLITE_OK;
        }
        catch (Exception exception)
        {
            return Failure(exception, SQLITE_IOERR_DELETE);
        }
    }

    private static int Access(sqlite3_vfs* vfs, byte* name, int flags, int* result)
    {
        *result = 0;
        try
        {
            *result = HostPlatform.Access(Decode(name), flags) ? 1 : 0;
            return SQLITE_OK;
        }
        catch (Exception exception)
        {
            return Failure(exception, SQLITE_IOERR_ACCESS);
        }
    }

    private static int FullPath(sqlite3_vfs* vfs, byte* name, int count, byte* output)
    {
        try
        {
            var path = CanonicalPath(Decode(name), out var followedLink);
            var size = Encoding.UTF8.GetByteCount(path);
            if (count <= size)
                return SQLITE_CANTOPEN;

            var span = new Span<byte>(output, count);
            Encoding.UTF8.GetBytes(path, span);
            span[size] = 0;
            // The pager turns this into CANTOPEN_SYMLINK for OPEN_NOFOLLOW,
            // otherwise accepts the canonical path for the database and journals.
            return followedLink ? SQLITE_OK_SYMLINK : SQLITE_OK; // SQLITE_OK_SYMLINK
        }
        catch (Exception exception)
        {
            return Failure(exception, SQLITE_CANTOPEN);
        }
    }

    private static string CanonicalPath(string path, out bool followedLink)
    {
        // Resolve each component before '..': collapsing it before following a
        // link can select a different database and therefore a different journal.
        var absolute = Path.IsPathFullyQualified(path) ? path
            : OperatingSystem.IsWindows() ? Path.GetFullPath(path)
            : Path.Combine(Environment.CurrentDirectory, path);
        var root = Path.GetPathRoot(absolute)!;
        var current = root;
        var separators = new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar };
        var components = new Queue<string>(absolute[root.Length..].Split(separators, StringSplitOptions.RemoveEmptyEntries));
        var links = 0;
        followedLink = false;

        while (components.TryDequeue(out var component))
        {
            if (component == ".")
                continue;

            if (component == "..")
            {
                if (current != root) current = Path.GetDirectoryName(current.TrimEnd(separators)) ?? root;
                continue;
            }

            var candidate = Path.Combine(current, component);
            string? target;

            try
            {
                target = new FileInfo(candidate).LinkTarget;
            }
            catch (FileNotFoundException)
            {
                target = null;
            }
            catch (DirectoryNotFoundException)
            {
                target = null;
            }

            if (target == null)
            {
                current = candidate;
                continue;
            }

            if (++links > 40)
                throw new IOException("Too many symbolic links in SQLite database path.");

            followedLink = true;

            var replacement = Path.IsPathFullyQualified(target) ? target : Path.Combine(current, target);
            root = Path.GetPathRoot(replacement)!;
            current = root;
            components = new Queue<string>(replacement[root.Length..].Split(separators, StringSplitOptions.RemoveEmptyEntries).Concat(components));
        }

        return current;
    }

    private static int Randomness(sqlite3_vfs* vfs, int count, byte* output)
    {
        try
        {
            RandomNumberGenerator.Fill(new Span<byte>(output, count));
            return count;
        }
        catch (Exception exception)
        {
            Failure(exception, SQLITE_ERROR);
            return 0;
        }
    }

    private static int Sleep(sqlite3_vfs* vfs, int microseconds)
    {
        try
        {
            if (microseconds <= 0)
                return 0;

            var milliseconds = (int)(((long)microseconds + 999) / 1000);
            Thread.Sleep(milliseconds);
            return (int)Math.Min(int.MaxValue, (long)milliseconds * 1000);
        }
        catch (Exception exception)
        {
            Failure(exception, SQLITE_ERROR);
            return 0;
        }
    }

    private static int CurrentTimeInt64(sqlite3_vfs* vfs, long* result)
    {
        try
        {
            *result = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + 210866760000000L;
            return SQLITE_OK;
        }
        catch (Exception exception) { return Failure(exception, SQLITE_ERROR); }
    }

    private static int CurrentTime(sqlite3_vfs* vfs, double* result)
    {
        long milliseconds = 0;
        var rc = CurrentTimeInt64(vfs, &milliseconds);
        *result = milliseconds / 86400000.0;
        return rc;
    }

    private static int GetLastError(sqlite3_vfs* vfs, int count, byte* output)
    {
        try
        {
            if (count > 0)
            {
                var bytes = Encoding.UTF8.GetBytes(_lastError ?? "");
                var copied = Math.Min(bytes.Length, count - 1);
                bytes.AsSpan(0, copied).CopyTo(new Span<byte>(output, copied));
                output[copied] = 0;
            }

            return _lastErrorNumber;
        }
        catch
        {
            if (count > 0) output[0] = 0;
            return SQLITE_ERROR;
        }
    }
}