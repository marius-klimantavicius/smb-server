using System.IO.MemoryMappedFiles;
using static Managed.Database.Sqlite;

namespace Managed.Database;

// Native-compatible WAL index storage. This maps the actual database-shm file;
// SQLite's translated WAL code owns the index format, recovery and checkpoints.
internal static unsafe class HostSharedMemory
{
    private const long LockBase = 120, DeadMan = 128;

    private static readonly Lock Gate = new Lock();
    private static readonly Dictionary<HostPlatform.FileIdentity, Node> Nodes = new Dictionary<HostPlatform.FileIdentity, Node>();

    private sealed class Mapping : IDisposable
    {
        private bool _isAcquired;

        internal readonly MemoryMappedFile File;
        internal readonly MemoryMappedViewAccessor View;
        internal readonly nint Address;

        internal Mapping(MemoryMappedFile file, long offset, int size, MemoryMappedFileAccess access)
        {
            File = file;
            try
            {
                View = file.CreateViewAccessor(offset, size, access);
                byte* pointer = null;
                View.SafeMemoryMappedViewHandle.AcquirePointer(ref pointer);
                _isAcquired = true;
                Address = (nint)(pointer + View.PointerOffset);
            }
            catch
            {
                try
                {
                    View?.Dispose();
                }
                finally
                {
                    file.Dispose();
                }

                throw;
            }
        }

        public void Dispose()
        {
            try
            {
                if (_isAcquired)
                {
                    View.SafeMemoryMappedViewHandle.ReleasePointer();
                    _isAcquired = false;
                }

                View.Dispose();
            }
            finally
            {
                File.Dispose();
            }
        }
    }

    internal sealed class Node
    {
        private readonly Dictionary<int, Mapping> _mappings = new Dictionary<int, Mapping>();
        private bool _dmsWrite;
        private int _regionSize;

        internal readonly HostPlatform.FileIdentity Identity;
        internal readonly HostPlatform.FileHandle File;
        internal readonly string Path;
        internal readonly bool IsReadOnly;
        internal readonly List<Connection> Connections = new List<Connection>();
        internal readonly int[] Locks = new int[8]; // positive reader count, -1 writer.
        internal bool Initialized, Poisoned;

        internal Node(HostPlatform.FileIdentity identity, HostPlatform.FileHandle file, string path, bool isReadOnly)
        {
            Identity = identity;
            File = file;
            Path = path;
            IsReadOnly = isReadOnly;
            // Raw shm locks are outside the rollback-lock state machine. Tell the
            // Darwin descriptor registry that incidental alias closes must defer.
            File.RetainExternalLocks();
        }

        internal int Initialize()
        {
            if (Initialized)
                return SQLITE_OK;

            if (Poisoned)
                return SQLITE_IOERR_SHMLOCK;

            int rc;
            if (OperatingSystem.IsWindows())
            {
                rc = HostPlatform.LockRange(File.Handle, DeadMan, 1, 1);
                if (rc == 0)
                    _dmsWrite = true;
                else if (rc != SQLITE_BUSY)
                    return SQLITE_IOERR_SHMLOCK;
            }
            else
            {
                rc = HostPlatform.QueryRange(File.Handle, DeadMan, 1, out var conflict);
                if (rc != 0)
                    return SQLITE_IOERR_SHMLOCK;

                // Never accept a read lock after observing an initializing writer:
                // it could die before invalidating a stale wal-index.
                if (conflict == 1)
                    return SQLITE_BUSY;

                if (conflict == 2)
                {
                    if (IsReadOnly)
                        return SQLITE_READONLY_CANTINIT;

                    rc = HostPlatform.LockRange(File.Handle, DeadMan, 1, 1);
                    if (rc != 0)
                        return rc == SQLITE_BUSY ? SQLITE_BUSY : SQLITE_IOERR_SHMLOCK;

                    _dmsWrite = true;
                }
            }

            if (_dmsWrite)
            {
                try
                {
                    if (IsReadOnly)
                    {
                        rc = SQLITE_READONLY_CANTINIT;
                    }
                    else
                    {
                        RandomAccess.SetLength(File.Handle, OperatingSystem.IsWindows() ? 0 : 3);
                        rc = 0;
                    }
                }
                catch
                {
                    rc = SQLITE_IOERR_SHMOPEN;
                }

                if (rc != 0)
                {
                    if (HostPlatform.LockRange(File.Handle, DeadMan, 1, 2) != 0)
                        Poisoned = true;
                    else
                        _dmsWrite = false;

                    return rc;
                }
            }

            rc = HostPlatform.LockRange(File.Handle, DeadMan, 1, 0);
            if (rc != 0)
                return rc == SQLITE_BUSY ? SQLITE_BUSY : SQLITE_IOERR_SHMLOCK;

            if (_dmsWrite && OperatingSystem.IsWindows())
            {
                // Shared over this handle's exclusive lock, then unlock exclusive
                // first: no unprotected gap while handing off initialized storage.
                if (HostPlatform.LockRange(File.Handle, DeadMan, 1, 2) != 0)
                {
                    Poisoned = true;
                    return SQLITE_IOERR_SHMLOCK;
                }
            }

            _dmsWrite = false;
            Initialized = true;
            return 0;
        }

        internal int Map(int region, int size, bool extend, out nint address)
        {
            address = 0;
            if (region < 0 || size <= 0 || size % 4096 != 0 || (_regionSize != 0 && _regionSize != size)) return SQLITE_IOERR_SHMMAP;
            if (Poisoned) return SQLITE_IOERR_SHMLOCK;

            var rc = Initialize();
            if (rc != 0) return rc;

            _regionSize = size;
            if (_mappings.TryGetValue(region, out var existing))
            {
                address = existing.Address;
                return IsReadOnly ? SQLITE_READONLY : 0;
            }

            long required;
            try
            {
                required = checked(((long)region + 1) * size);
                if (!OperatingSystem.IsWindows())
                {
                    var alignment = Math.Max(Environment.SystemPageSize, size);
                    required = checked((required + alignment - 1) / alignment * alignment);
                }
            }
            catch (OverflowException)
            {
                return SQLITE_IOERR_SHMSIZE;
            }

            long length;
            try
            {
                length = RandomAccess.GetLength(File.Handle);
            }
            catch
            {
                return SQLITE_IOERR_SHMSIZE;
            }

            if (length < required && !extend)
                return IsReadOnly ? SQLITE_READONLY : 0;

            if (length < required && IsReadOnly)
                return SQLITE_READONLY;

            if (length < required && !OperatingSystem.IsWindows())
            {
                try
                {
                    // Match Unix SQLite's physical allocation probe, avoiding
                    // sparse-only growth that can fault on later mapped access.
                    ReadOnlySpan<byte> zero = stackalloc byte[] { 0 };
                    for (var page = length / 4096; page < required / 4096; page++)
                        RandomAccess.Write(File.Handle, zero, checked(page * 4096 + 4095));
                }
                catch
                {
                    return SQLITE_IOERR_SHMSIZE;
                }
            }

            var access = IsReadOnly ? MemoryMappedFileAccess.Read : MemoryMappedFileAccess.ReadWrite;
            try
            {
                MemoryMappedFile? file = null;
                // Windows CreateFileMapping can extend a backing file while old
                // mappings remain alive; SetEndOfFile cannot safely do that.
                // On Unix capacity 0 snapshots the explicitly grown file length.
                for (var attempt = 0; attempt < 3; attempt++)
                {
                    var capacity = OperatingSystem.IsWindows() ? Math.Max(RandomAccess.GetLength(File.Handle), required) : 0;
                    try
                    {
                        file = MemoryMappedFile.CreateFromFile(File.Handle, null, capacity, access, HandleInheritability.None, leaveOpen: true);
                        break;
                    }
                    catch (ArgumentOutOfRangeException) when (OperatingSystem.IsWindows() && attempt < 2)
                    {
                        /* Another process grew the file between the two size reads. */
                    }
                }

                var mapping = new Mapping(file!, checked((long)region * size), size, access);
                try
                {
                    _mappings.Add(region, mapping);
                }
                catch
                {
                    mapping.Dispose();
                    throw;
                }

                address = mapping.Address;
                return IsReadOnly ? SQLITE_READONLY : 0;
            }
            catch (OutOfMemoryException)
            {
                return SQLITE_NOMEM;
            }
            catch
            {
                return SQLITE_IOERR_SHMMAP;
            }
        }

        internal int Purge(bool deleteFile)
        {
            var rc = 0;
            // Unix unlinks while DMS is still held. Windows native shm handles
            // deliberately deny share-delete; close our handles before deletion.
            if (deleteFile && !OperatingSystem.IsWindows())
            {
                try
                {
                    System.IO.File.Delete(Path);
                }
                catch
                {
                    rc = SQLITE_IOERR_SHMOPEN;
                }
            }

            foreach (var mapping in _mappings.Values)
            {
                try
                {
                    mapping.Dispose();
                }
                catch
                {
                    rc = SQLITE_IOERR_SHMMAP;
                }
            }

            _mappings.Clear();
            try
            {
                File.Dispose();
            }
            catch
            {
                rc = SQLITE_IOERR_SHMOPEN;
            }

            _dmsWrite = false;
            if (deleteFile && OperatingSystem.IsWindows())
            {
                // Another process may still own a non-delete-sharing handle.
                // Like native winShmPurge, deletion is best effort.
                try
                {
                    System.IO.File.Delete(Path);
                }
                catch (IOException)
                {
                    /* empty */
                }
                catch (UnauthorizedAccessException)
                {
                    /* empty */
                }
            }

            return rc;
        }
    }

    internal sealed class Connection
    {
        private readonly Node node;

        private int _sharedMask, _exclusiveMask;

        // Eight slots bound the number of disjoint ranges. Allocate the full
        // capacity before this connection can acquire any kernel lock.
        private readonly List<(int Offset, int Count)> _exclusiveRanges = new List<(int Offset, int Count)>(8);
        private bool _disposed;
        internal Connection(Node node) { this.node = node; }

        public int Map(int region, int regionSize, bool extend, out nint address)
        {
            lock (Gate)
            {
                address = 0;
                if (_disposed)
                    return SQLITE_IOERR_SHMMAP;

                return node.Map(region, regionSize, extend, out address);
            }
        }

        public int Lock(int offset, int count, int flags)
        {
            lock (Gate)
            {
                if (_disposed || offset < 0 || count < 1 || offset > 8 - count || flags is not (5 or 6 or 9 or 10) || (count != 1 && (flags & 8) == 0))
                    return SQLITE_IOERR_SHMLOCK;

                bool unlock = (flags & 1) != 0, exclusive = (flags & 8) != 0;
                // A read-only node without DMS can still take reader slots while
                // SQLite uses its private recovery index (READONLY_CANTINIT).
                if (!unlock && node.Poisoned)
                    return SQLITE_IOERR_SHMLOCK;

                var mask = ((1 << count) - 1) << offset;
                if (unlock) return UnlockRange(offset, count, exclusive, mask);
                if (((_sharedMask | _exclusiveMask) & mask) != 0)
                    return !exclusive && (_sharedMask & mask) == mask ? 0 : SQLITE_BUSY;

                for (var i = offset; i < offset + count; i++)
                {
                    if (exclusive ? node.Locks[i] != 0 : node.Locks[i] < 0)
                        return SQLITE_BUSY;
                }

                var rc = 0;
                if (exclusive || node.Locks[offset] == 0)
                    rc = HostPlatform.LockRange(node.File.Handle, LockBase + offset, count, exclusive ? 1 : 0);

                if (rc != 0)
                    return rc == SQLITE_BUSY ? SQLITE_BUSY : SQLITE_IOERR_SHMLOCK;

                if (exclusive)
                {
                    _exclusiveMask |= mask;
                    _exclusiveRanges.Add((offset, count));

                    for (var i = offset; i < offset + count; i++)
                        node.Locks[i] = -1;
                }
                else
                {
                    _sharedMask |= mask;
                    node.Locks[offset]++;
                }

                return 0;
            }
        }

        private int UnlockRange(int offset, int count, bool exclusive, int mask)
        {
            var owned = exclusive ? _exclusiveMask : _sharedMask;
            if ((owned & mask) == 0)
                return 0;
            if ((owned & mask) != mask)
                return SQLITE_IOERR_SHMLOCK;
            if (exclusive && OperatingSystem.IsWindows() && !_exclusiveRanges.Contains((offset, count)))
                return SQLITE_IOERR_SHMLOCK;

            if (!exclusive && node.Locks[offset] > 1)
            {
                node.Locks[offset]--;
                _sharedMask &= ~mask;
                return 0;
            }

            var rc = HostPlatform.LockRange(node.File.Handle, LockBase + offset, count, 2);
            if (rc != 0)
            {
                node.Poisoned = true;
                return SQLITE_IOERR_SHMLOCK;
            }

            if (exclusive)
            {
                _exclusiveMask &= ~mask;
                // SQLite unlocks its exclusive ranges as acquired. Unix permits
                // subranges too; retain any un-released pieces for xShmUnmap.
                for (var i = _exclusiveRanges.Count - 1; i >= 0; i--)
                {
                    var range = _exclusiveRanges[i];
                    var end = range.Offset + range.Count;
                    if (range.Offset >= offset + count || end <= offset)
                        continue;

                    _exclusiveRanges.RemoveAt(i);
                    if (range.Offset < offset)
                        _exclusiveRanges.Add((range.Offset, offset - range.Offset));

                    if (end > offset + count)
                        _exclusiveRanges.Add((offset + count, end - offset - count));
                }

                for (var i = offset; i < offset + count; i++)
                    node.Locks[i] = 0;
            }
            else
            {
                _sharedMask &= ~mask;
                node.Locks[offset] = 0;
            }

            return 0;
        }

        public int Unmap(bool deleteFile)
        {
            lock (Gate)
            {
                if (_disposed) return 0;

                var rc = 0;
                try
                {
                    // No snapshot/allocation in cleanup: a failed range remains a
                    // poisoned orphan in node.Locks until final descriptor close.
                    while (_exclusiveRanges.Count != 0)
                    {
                        var range = _exclusiveRanges[^1];
                        var mask = ((1 << range.Count) - 1) << range.Offset;
                        if (UnlockRange(range.Offset, range.Count, true, mask) != 0)
                        {
                            rc = SQLITE_IOERR_SHMLOCK;
                            _exclusiveRanges.RemoveAt(_exclusiveRanges.Count - 1);
                        }
                    }

                    for (var i = 0; i < 8; i++)
                    {
                        if ((_sharedMask & (1 << i)) != 0 && UnlockRange(i, 1, false, 1 << i) != 0)
                            rc = SQLITE_IOERR_SHMLOCK;
                    }
                }
                catch
                {
                    node.Poisoned = true;
                    rc = SQLITE_IOERR_SHMLOCK;
                }
                finally
                {
                    // Never keep a connection rooted after xClose discards its
                    // context, including exceptional cleanup failures.
                    node.Connections.Remove(this);
                    _disposed = true;

                    if (node.Connections.Count == 0)
                    {
                        Nodes.Remove(node.Identity);
                        try
                        {
                            var close = node.Purge(deleteFile);
                            if (close != 0) rc = close;
                        }
                        catch
                        {
                            rc = SQLITE_IOERR_SHMOPEN;
                        }
                    }
                }

                return rc;
            }
        }
    }

    public static int Open(HostPlatform.FileHandle database, string canonicalDatabasePath, out Connection? connection)
    {
        lock (Gate)
        {
            connection = null;
            HostPlatform.FileHandle? file = null;
            Node? created = null;
            try
            {
                var identity = HostPlatform.Identity(database.Handle);
                if (!Nodes.TryGetValue(identity, out var node))
                {
                    var path = canonicalDatabasePath + "-shm";
                    var readOnly = false;
                    try
                    {
                        file = HostPlatform.Open(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileOptions.None, noFollow: true, shareDelete: false);
                    }
                    catch (Exception error) when (error is IOException or UnauthorizedAccessException)
                    {
                        file = HostPlatform.Open(path, FileMode.Open, FileAccess.Read, FileOptions.None, noFollow: true, shareDelete: false);
                        readOnly = true;
                    }

                    node = created = new Node(identity, file, path, readOnly);
                    Nodes.Add(identity, node);
                }

                var lease = new Connection(node);
                node.Connections.Add(lease);
                connection = lease;
                return 0;
            }
            catch (Exception error)
            {
                if (created is not null) Nodes.Remove(created.Identity);
                try
                {
                    file?.Dispose();
                }
                catch
                {
                    /* empty */
                }

                return error is OutOfMemoryException ? SQLITE_NOMEM : SQLITE_IOERR_SHMOPEN;
            }
        }
    }

    public static void Barrier() => Thread.MemoryBarrier();
}