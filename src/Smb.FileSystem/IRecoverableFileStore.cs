using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Smb.Protocol.Enums;

namespace Smb.FileSystem;

/// <summary>Exclusive backend retention across process lifetimes. A retained object must
/// survive pending deletion and name replacement until its token is released. Reopen must
/// validate object identity, never substitute a pathname. One server owns each backend.</summary>
public interface IRecoverableFileStore : ICacheCoherentFileStore
{
    string RecoveryStoreIdentity { get; }
    RecoveryFileState CaptureRecoveryState(IFileHandle handle);
    NtStatus RetainForRecovery(IFileHandle handle, Guid token);
    NtStatus ReleaseRecovery(Guid token);
    IReadOnlyList<Guid> GetRecoveryTokens();
    ValueTask<FileStoreResult<IFileHandle>> ReopenForRecoveryAsync(Guid token, FileIdentity identity,
        FileAccessIntent access, RecoveryFileState? state = null, CancellationToken cancellationToken = default);
}

public sealed record RecoveryFileState(string Path, bool SuppressWriteTimeUpdates);
