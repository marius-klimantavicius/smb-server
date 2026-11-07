using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;

namespace Smb.FileSystem;

public interface ISparseFileStore
{
	ValueTask<NtStatus> SetSparseAsync(IFileHandle handle, bool sparse, CancellationToken cancellationToken = default(CancellationToken));

	ValueTask<NtStatus> SetZeroDataAsync(IFileHandle handle, long offset, long length, CancellationToken cancellationToken = default(CancellationToken));

	ValueTask<FileStoreResult<IReadOnlyList<FsctlMessage.FileRange>>> QueryAllocatedRangesAsync(IFileHandle handle, long offset, long length, CancellationToken cancellationToken = default(CancellationToken));
}
