using System;
using System.Threading;
using System.Threading.Tasks;

namespace Smb.FileSystem;

/// <summary>Bounded, forward-only enumeration. A cursor owns backend listing resources
/// until disposed on exhaustion, restart, or close. Concurrent directory mutations are
/// backend-defined; this is not a snapshot or change journal.</summary>
public interface IDirectoryCursor : IDisposable
{
    ValueTask<FileStoreResult<BoundedDirectoryListing>> ReadAsync(int maxEntries, CancellationToken cancellationToken = default);
}

public interface IDirectoryCursorStore
{
    ValueTask<FileStoreResult<IDirectoryCursor>> OpenDirectoryCursorAsync(IFileHandle handle, string pattern, CancellationToken cancellationToken = default);
}
