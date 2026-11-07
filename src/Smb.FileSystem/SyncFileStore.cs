using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Smb.Protocol.Enums;
using Smb.Protocol.Security;

namespace Smb.FileSystem;

public abstract class SyncFileStore : IFileStore
{
	protected abstract FileStoreResult<IFileHandle> Create(string path, FileAccessIntent access, CreateDispositionIntent disposition, bool directoryRequired, bool nonDirectoryRequired, out CreateOutcome createAction);

	protected abstract FileStoreResult<int> Read(IFileHandle handle, long offset, Span<byte> buffer);

	protected abstract FileStoreResult<int> Write(IFileHandle handle, long offset, ReadOnlySpan<byte> data);

	protected abstract FileStoreResult<IReadOnlyList<FileEntryInfo>> QueryDirectory(IFileHandle handle, string searchPattern);

	protected abstract NtStatus SetEndOfFile(IFileHandle handle, long length);

	protected abstract NtStatus Rename(IFileHandle handle, string newPath, bool replaceIfExists);

	protected abstract NtStatus SetDeleteOnClose(IFileHandle handle, bool delete);

	protected abstract NtStatus Flush(IFileHandle handle);

	public virtual ValueTask<FileStoreResult<FileCreateResult>> CreateAsync(string path, FileAccessIntent access, CreateDispositionIntent disposition, bool directoryRequired, bool nonDirectoryRequired, CancellationToken cancellationToken = default(CancellationToken))
	{
		var fileStoreResult = Create(path, access, disposition, directoryRequired, nonDirectoryRequired, out var createAction);
		return new ValueTask<FileStoreResult<FileCreateResult>>(fileStoreResult.IsSuccess ? FileStoreResult<FileCreateResult>.Ok(new FileCreateResult(fileStoreResult.Value, createAction)) : FileStoreResult<FileCreateResult>.Fail(fileStoreResult.Status));
	}

	public virtual ValueTask<FileStoreResult<int>> ReadAsync(IFileHandle handle, long offset, Memory<byte> buffer, CancellationToken cancellationToken = default(CancellationToken))
	{
		return new ValueTask<FileStoreResult<int>>(Read(handle, offset, buffer.Span));
	}

	public virtual ValueTask<FileStoreResult<int>> WriteAsync(IFileHandle handle, long offset, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default(CancellationToken))
	{
		return new ValueTask<FileStoreResult<int>>(Write(handle, offset, data.Span));
	}

	public virtual ValueTask<FileStoreResult<IReadOnlyList<FileEntryInfo>>> QueryDirectoryAsync(IFileHandle handle, string searchPattern, CancellationToken cancellationToken = default(CancellationToken))
	{
		return new ValueTask<FileStoreResult<IReadOnlyList<FileEntryInfo>>>(QueryDirectory(handle, searchPattern));
	}

	protected virtual FileStoreResult<BoundedDirectoryListing> QueryDirectory(IFileHandle handle, string searchPattern, int maxEntries)
	{
		var fileStoreResult = QueryDirectory(handle, searchPattern);
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

	public virtual ValueTask<FileStoreResult<BoundedDirectoryListing>> QueryDirectoryAsync(IFileHandle handle, string searchPattern, int maxEntries, CancellationToken cancellationToken = default(CancellationToken))
	{
		return new ValueTask<FileStoreResult<BoundedDirectoryListing>>(QueryDirectory(handle, searchPattern, maxEntries));
	}

	public virtual ValueTask<NtStatus> SetEndOfFileAsync(IFileHandle handle, long length, CancellationToken cancellationToken = default(CancellationToken))
	{
		return new ValueTask<NtStatus>(SetEndOfFile(handle, length));
	}

	public virtual ValueTask<NtStatus> RenameAsync(IFileHandle handle, string newPath, bool replaceIfExists, CancellationToken cancellationToken = default(CancellationToken))
	{
		return new ValueTask<NtStatus>(Rename(handle, newPath, replaceIfExists));
	}

	public virtual ValueTask<NtStatus> SetDeleteOnCloseAsync(IFileHandle handle, bool delete, CancellationToken cancellationToken = default(CancellationToken))
	{
		return new ValueTask<NtStatus>(SetDeleteOnClose(handle, delete));
	}

	public virtual ValueTask<NtStatus> FlushAsync(IFileHandle handle, CancellationToken cancellationToken = default(CancellationToken))
	{
		return new ValueTask<NtStatus>(Flush(handle));
	}

	public virtual ValueTask<FileStoreResult<SecurityDescriptor>> GetSecurityAsync(IFileHandle handle, CancellationToken cancellationToken = default(CancellationToken))
	{
		return new ValueTask<FileStoreResult<SecurityDescriptor>>(FileStoreResult<SecurityDescriptor>.Fail(NtStatus.NotSupported));
	}

	public virtual ValueTask<NtStatus> SetSecurityAsync(IFileHandle handle, SecurityDescriptor descriptor, CancellationToken cancellationToken = default(CancellationToken))
	{
		return new ValueTask<NtStatus>(NtStatus.NotSupported);
	}
}
