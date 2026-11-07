using System;

namespace Smb.FileSystem.Versioning;

internal sealed class SnapshotFileHandle : IFileHandle, IDisposable
{
	private readonly byte[] _content;

	private readonly FileEntryInfo _info;

	public string Path { get; }

	public bool IsDirectory => false;

	public SnapshotFileHandle(string path, byte[] content, FileEntryInfo info)
	{
		Path = path;
		_content = content;
		_info = info;
	}

	public FileEntryInfo GetInfo()
	{
		return _info;
	}

	public FileStoreResult<int> Read(long offset, Span<byte> buffer)
	{
		if (offset < 0 || offset >= _content.Length)
		{
			return FileStoreResult<int>.Ok(0);
		}

		var num = Math.Min(buffer.Length, _content.Length - (int)offset);
		_content.AsSpan((int)offset, num).CopyTo(buffer);
		return FileStoreResult<int>.Ok(num);
	}

	public void Dispose()
	{
	}
}
