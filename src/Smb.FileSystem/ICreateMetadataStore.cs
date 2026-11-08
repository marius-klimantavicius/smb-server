using System.Threading;
using System.Threading.Tasks;

namespace Smb.FileSystem;

/// <summary>Validates requested attributes before destructive acquisition and applies creation metadata.</summary>
public interface ICreateMetadataStore
{
	ValueTask<FileStoreResult<FileCreateResult>> CreateWithMetadataAsync(string path, FileAccessIntent access, CreateDispositionIntent disposition, bool directoryRequired, bool nonDirectoryRequired, uint attributes, CancellationToken cancellationToken = default);
}
