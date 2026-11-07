using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Smb.FileSystem;

public interface INamedStreamStore
{
	ValueTask<FileStoreResult<IReadOnlyList<StreamInfo>>> QueryStreamsAsync(IFileHandle handle, CancellationToken cancellationToken = default(CancellationToken));

	ValueTask<FileStoreResult<FileCreateResult>> OpenNamedStreamAsync(string basePath, string streamName, FileAccessIntent access, CreateDispositionIntent disposition, CancellationToken cancellationToken = default(CancellationToken));
}
