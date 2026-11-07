using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Smb.Protocol.Enums;
using Smb.Protocol.Security;

namespace Smb.FileSystem;

public interface IFileStore
{
	ValueTask<FileStoreResult<FileCreateResult>> CreateAsync(string path, FileAccessIntent access, CreateDispositionIntent disposition, bool directoryRequired, bool nonDirectoryRequired, CancellationToken cancellationToken = default(CancellationToken));

	ValueTask<FileStoreResult<int>> ReadAsync(IFileHandle handle, long offset, Memory<byte> buffer, CancellationToken cancellationToken = default(CancellationToken));

	ValueTask<FileStoreResult<int>> WriteAsync(IFileHandle handle, long offset, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default(CancellationToken));

	ValueTask<FileStoreResult<IReadOnlyList<FileEntryInfo>>> QueryDirectoryAsync(IFileHandle handle, string searchPattern, CancellationToken cancellationToken = default(CancellationToken));

	async ValueTask<FileStoreResult<BoundedDirectoryListing>> QueryDirectoryAsync(IFileHandle handle, string searchPattern, int maxEntries, CancellationToken cancellationToken = default(CancellationToken))
	{
		var fileStoreResult = await QueryDirectoryAsync(handle, searchPattern, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
		if (!fileStoreResult.IsSuccess)
		{
			return FileStoreResult<BoundedDirectoryListing>.Fail(fileStoreResult.Status);
		}

		var value = fileStoreResult.Value;
		if (maxEntries > 0 && value.Count > maxEntries)
		{
			var list = new List<FileEntryInfo>(maxEntries);
			for (var i = 0; i < maxEntries; i++)
			{
				list.Add(value[i]);
			}

			return FileStoreResult<BoundedDirectoryListing>.Ok(new BoundedDirectoryListing(list, Truncated: true));
		}

		return FileStoreResult<BoundedDirectoryListing>.Ok(new BoundedDirectoryListing(value, Truncated: false));
	}

	ValueTask<NtStatus> SetEndOfFileAsync(IFileHandle handle, long length, CancellationToken cancellationToken = default(CancellationToken));

	ValueTask<NtStatus> RenameAsync(IFileHandle handle, string newPath, bool replaceIfExists, CancellationToken cancellationToken = default(CancellationToken));

	ValueTask<NtStatus> SetDeleteOnCloseAsync(IFileHandle handle, bool delete, CancellationToken cancellationToken = default(CancellationToken));

	ValueTask<NtStatus> FlushAsync(IFileHandle handle, CancellationToken cancellationToken = default(CancellationToken));

	ValueTask<FileStoreResult<long>> CopyRangeAsync(IFileHandle source, long sourceOffset, IFileHandle destination, long destinationOffset, long length, CancellationToken cancellationToken = default(CancellationToken))
	{
		return new ValueTask<FileStoreResult<long>>(FileStoreResult<long>.Fail(NtStatus.NotSupported));
	}

	ValueTask<FileStoreResult<SecurityDescriptor>> GetSecurityAsync(IFileHandle handle, CancellationToken cancellationToken = default(CancellationToken))
	{
		return new ValueTask<FileStoreResult<SecurityDescriptor>>(FileStoreResult<SecurityDescriptor>.Fail(NtStatus.NotSupported));
	}

	ValueTask<NtStatus> SetSecurityAsync(IFileHandle handle, SecurityDescriptor descriptor, CancellationToken cancellationToken = default(CancellationToken))
	{
		return new ValueTask<NtStatus>(NtStatus.NotSupported);
	}
}
