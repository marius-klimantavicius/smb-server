using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Smb.Server.State;

namespace Smb.Server;

public readonly record struct FileIoRange(SmbOpen Open, ulong Offset, ulong Length, bool ForWrite)
{
    public string IdentityKey => Open.IdentityKey;
}

/// <summary>P6 hook shared by ordinary I/O and copy. Acquire all ranges as one operation
/// (stable identity, deterministic ordering); keep the scope through physical completion.
/// The optional hook composes with the built-in FileCacheCoordinator. It cannot bypass
/// that gate or enable cache grants on a backend lacking the coherence contract.</summary>
public interface IFileIoCoordinator
{
    ValueTask<IDisposable> AcquireAsync(IReadOnlyList<FileIoRange> ranges, CancellationToken cancellationToken = default);
}
