using System;
using System.IO;

namespace Smb.FileSystem.Local;

internal sealed class NamedStreamHandle : IFileHandle, IDisposable
{
	private readonly LocalFileStore _store;

	public string BaseFullPath { get; }

	public string StreamName { get; }

	public bool DeleteOnClose { get; set; }

	public string Path => System.IO.Path.GetFileName(BaseFullPath) + ":" + StreamName;

	public bool IsDirectory => false;

	public string? PhysicalPath => BaseFullPath;

	public NamedStreamHandle(LocalFileStore store, string baseFullPath, string streamName)
	{
		_store = store;
		BaseFullPath = baseFullPath;
		StreamName = streamName;
	}

	public FileEntryInfo GetInfo()
	{
		var num = _store.StreamLength(BaseFullPath, StreamName);
		var fi = new FileInfo(BaseFullPath);
		var creationTime = Safe(fi, f => f.CreationTimeUtc);
		var lastAccessTime = Safe(fi, f => f.LastAccessTimeUtc);
		var num2 = Safe(fi, f => f.LastWriteTimeUtc);
		return new FileEntryInfo
		{
			Name = System.IO.Path.GetFileName(BaseFullPath) + ":" + StreamName + ":$DATA",
			Attributes = SmbFileAttributes.Normal,
			EndOfFile = num,
			AllocationSize = (num + 4095) / 4096 * 4096,
			CreationTime = creationTime,
			LastAccessTime = lastAccessTime,
			LastWriteTime = num2,
			ChangeTime = num2,
			IndexNumber = PathId.Of(BaseFullPath + ":" + StreamName),
		};
	}

	private static long Safe(FileInfo fi, Func<FileInfo, DateTime> pick)
	{
		try
		{
			return fi.Exists ? pick(fi).ToFileTimeUtc() : 0;
		}
		catch
		{
			return 0L;
		}
	}

	public void Dispose()
	{
		if (DeleteOnClose)
		{
			_store.StreamRemove(BaseFullPath, StreamName);
		}
	}
}
