using System.IO.MemoryMappedFiles;
using Microsoft.Win32.SafeHandles;
using static Managed.Database.Sqlite;

namespace Managed.Database;

public static unsafe partial class HostVfs
{
    private static long _mappedReads;
    private static int _mappedViews, _mappedReferences;

    public static long MappedReadCount => Interlocked.Read(ref _mappedReads);
    public static int MappedViewCount => Volatile.Read(ref _mappedViews);
    public static int MappedReferenceCount => Volatile.Read(ref _mappedReferences);

    // Owns a read-only view of an existing descriptor. No extra file open/close:
    // on POSIX that could interfere with process-owned database byte locks.
    private sealed class DatabaseMapping(SafeFileHandle handle) : IDisposable
    {
        private readonly Lock _gate = new Lock();
        private readonly Dictionary<long, int> _borrowed = new Dictionary<long, int>();
        private MemoryMappedFile? _file;
        private MemoryMappedViewAccessor? _view;
        private byte* _address;
        private long _length;
        private long _limit = Math.Max(0, Globals.sqlite3Config.szMmap);
        private int _references;

        private void Unmap()
        {
            if (_view == null)
                return;

            var previousView = _view;
            var previousFile = _file;

            _view = null;
            _file = null;
            _address = null;
            _length = 0;

            try
            {
                previousView.SafeMemoryMappedViewHandle.ReleasePointer();
                previousView.Dispose();
            }
            finally
            {
                previousFile!.Dispose();
                Interlocked.Decrement(ref _mappedViews);
            }
        }

        public int Configure(long* value)
        {
            lock (_gate)
            {
                var requested = *value;
                *value = _limit;

                // Match SQLite's native VFS: negative queries only; a live borrow
                // prevents a limit change that could invalidate its address.
                if (requested >= 0 && _references == 0)
                {
                    requested = Math.Min(requested, Math.Max(0, Globals.sqlite3Config.mxMmap));
                    if (requested != _limit)
                    {
                        Unmap();
                        _limit = requested;
                    }
                }

                return SQLITE_OK;
            }
        }

        private bool Map(long size)
        {
            MemoryMappedFile? nextFile = null;
            MemoryMappedViewAccessor? nextView = null;
            var acquired = false;
            try
            {
                nextFile = MemoryMappedFile.CreateFromFile(handle, null, 0, MemoryMappedFileAccess.Read, HandleInheritability.None, leaveOpen: true);
                nextView = nextFile.CreateViewAccessor(0, size, MemoryMappedFileAccess.Read);
                byte* pointer = null;
                nextView.SafeMemoryMappedViewHandle.AcquirePointer(ref pointer);
                acquired = true;
                _address = pointer + nextView.PointerOffset;
                _file = nextFile;
                _view = nextView;
                _length = size;
                Interlocked.Increment(ref _mappedViews);
                return true;
            }
            catch (Exception exception) when (
                exception is IOException
                    or UnauthorizedAccessException
                    or NotSupportedException
                    or ArgumentException
                    or OutOfMemoryException)
            {
                // Mapping is optional: SQLite will fall back to xRead when the
                // address is null, as its native VFS does for mmap failures.
                if (acquired)
                    nextView!.SafeMemoryMappedViewHandle.ReleasePointer();

                try
                {
                    nextView?.Dispose();
                }
                finally
                {
                    nextFile?.Dispose();
                }

                Failure(exception, SQLITE_IOERR_MMAP);
                return false;
            }
        }

        public int Fetch(long offset, int count, void** output)
        {
            *output = null;
            if (count <= 0 || !ValidRange(count, offset))
                return SQLITE_IOERR_MMAP;

            lock (_gate)
            {
                // SQLite 3.53.4 reserves 256 addressable bytes past a mapped page
                // to tolerate limited overreads of a corrupt page. Never map the
                // final page without that buffer, even if the OS rounds the view.
                var end = offset + count;
                if (end > long.MaxValue - 256 || end + 256 > _limit)
                    return SQLITE_OK;

                var required = end + 256;
                if (_view == null || (required > _length && _references == 0))
                {
                    var size = Math.Min(RandomAccess.GetLength(handle), _limit);
                    if (size < required)
                        return SQLITE_OK;

                    Unmap();
                    if (!Map(size))
                        return SQLITE_OK;
                }

                if (required > _length)
                    return SQLITE_OK;

                _borrowed.TryGetValue(offset, out var existing);
                _borrowed[offset] = checked(existing + 1);
                ++_references;
                Interlocked.Increment(ref _mappedReferences);
                Interlocked.Increment(ref _mappedReads);
                *output = _address + offset;
                return SQLITE_OK;
            }
        }

        public int Unfetch(long offset, void* pointer)
        {
            lock (_gate)
            {
                if (pointer == null)
                {
                    if (_references != 0) return SQLITE_BUSY;

                    Unmap();
                    return SQLITE_OK;
                }

                if (offset < 0 || offset >= _length || pointer != _address + offset || !_borrowed.TryGetValue(offset, out var count))
                    return SQLITE_IOERR_MMAP;

                if (count == 1)
                    _borrowed.Remove(offset);
                else
                    _borrowed[offset] = count - 1;

                --_references;
                Interlocked.Decrement(ref _mappedReferences);

                // Windows prevents truncating files with mapped sections. Release
                // an idle view promptly so another connection/process can VACUUM
                // or checkpoint after the associated SQLite read lock is released.
                if (_references == 0 && OperatingSystem.IsWindows())
                    Unmap();

                return SQLITE_OK;
            }
        }

        public int BeforeTruncate()
        {
            lock (_gate)
            {
                if (_references != 0)
                    return SQLITE_BUSY;

                Unmap();
                return SQLITE_OK;
            }
        }

        public void ReleaseIdle()
        {
            lock (_gate)
            {
                if (_references == 0)
                    Unmap();
            }
        }

        public void Dispose()
        {
            lock (_gate)
            {
                // SQLite closes only after all page borrows have been released.
                // Still reclaim every VFS-owned resource on a raw caller's close.
                Interlocked.Add(ref _mappedReferences, -_references);
                _references = 0;
                _borrowed.Clear();
                Unmap();
            }
        }
    }

    private static int Fetch(sqlite3_file* file, long offset, int count, void** output)
    {
        *output = null;
        try
        {
            return State(file).Mapping?.Fetch(offset, count, output) ?? SQLITE_OK;
        }
        catch (Exception exception)
        {
            return Failure(exception, SQLITE_IOERR_MMAP);
        }
    }

    private static int Unfetch(sqlite3_file* file, long offset, void* pointer)
    {
        try
        {
            return State(file).Mapping?.Unfetch(offset, pointer) ?? SQLITE_OK;
        }
        catch (Exception exception)
        {
            return Failure(exception, SQLITE_IOERR_MMAP);
        }
    }
}