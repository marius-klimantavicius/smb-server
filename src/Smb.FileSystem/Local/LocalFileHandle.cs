using System;
using System.IO;
using System.Threading;
using Smb.Protocol.Enums;

namespace Smb.FileSystem.Local;

internal sealed class LocalFileHandle : IFileHandle, IDisposable
{
	private readonly string _root;

	private readonly FileStream? _stream;

	private readonly bool _isDirectory;

	private readonly Lock _io = new Lock();

	public string FullPath { get; private set; }

	public string Path { get; private set; }

	public bool DeleteOnClose { get; set; }

	public bool IsDirectory => _isDirectory;

	public string? PhysicalPath => FullPath;

	public LocalFileHandle(string fullPath, string relativePath, string root, FileStream? stream, bool isDirectory)
	{
		FullPath = fullPath;
		Path = relativePath;
		_root = root;
		_stream = stream;
		_isDirectory = isDirectory;
	}

	public FileStoreResult<int> ReadAt(long offset, Span<byte> buffer)
	{
		if (_stream == null)
		{
			return FileStoreResult<int>.Fail(NtStatus.InvalidParameter);
		}

		lock (_io)
		{
			try
			{
				if (offset >= _stream.Length)
				{
					return FileStoreResult<int>.Ok(0);
				}

				_stream.Seek(offset, SeekOrigin.Begin);
				return FileStoreResult<int>.Ok(_stream.Read(buffer));
			}
			catch (IOException)
			{
				return FileStoreResult<int>.Fail(NtStatus.InvalidParameter);
			}
		}
	}

	public FileStoreResult<int> WriteAt(long offset, ReadOnlySpan<byte> data)
	{
		lock (_io)
		{
			if (_stream == null || !_stream.CanWrite)
			{
				return FileStoreResult<int>.Fail(NtStatus.AccessDenied);
			}

			try
			{
				_stream.Seek(offset, SeekOrigin.Begin);
				_stream.Write(data);
				return FileStoreResult<int>.Ok(data.Length);
			}
			catch (IOException)
			{
				return FileStoreResult<int>.Fail(NtStatus.DiskFull);
			}
		}
	}

	public NtStatus SetLength(long length)
	{
		lock (_io)
		{
			if (_stream == null || !_stream.CanWrite)
			{
				return NtStatus.AccessDenied;
			}

			try
			{
				_stream.SetLength(length);
				return NtStatus.Success;
			}
			catch (IOException)
			{
				return NtStatus.InvalidParameter;
			}
		}
	}

	public NtStatus FlushStream()
	{
		lock (_io)
		{
			try
			{
				_stream?.Flush(flushToDisk: true);
				return NtStatus.Success;
			}
			catch (IOException)
			{
				return NtStatus.InvalidParameter;
			}
		}
	}

	public void Relocate(string newFull, string newRelative)
	{
		FullPath = newFull;
		Path = newRelative;
	}

	public FileEntryInfo GetInfo()
	{
		if (_isDirectory)
		{
			return Build(new DirectoryInfo(FullPath), 0L, isDir: true);
		}

		var fileInfo = new FileInfo(FullPath);
		long size;
		lock (_io)
		{
			if (_stream != null)
			{
				size = _stream.Length;
			}
			else
			{
				size = (fileInfo.Exists ? fileInfo.Length : 0);
			}
		}

		return Build(fileInfo, size, isDir: false);
	}

	private FileEntryInfo Build(FileSystemInfo info, long size, bool isDir)
	{
		return new FileEntryInfo
		{
			Name = System.IO.Path.GetFileName(FullPath),
			Attributes = LocalFileStore.MapAttributes(info.Attributes),
			EndOfFile = size,
			AllocationSize = (isDir ? 0 : ((size + 4095) / 4096 * 4096)),
			CreationTime = Safe(info.CreationTimeUtc),
			LastAccessTime = Safe(info.LastAccessTimeUtc),
			LastWriteTime = Safe(info.LastWriteTimeUtc),
			ChangeTime = Safe(info.LastWriteTimeUtc),
			IndexNumber = PathId.Of(FullPath),
		};
	}

	private static long Safe(DateTime utc)
	{
		try
		{
			return utc.ToFileTimeUtc();
		}
		catch
		{
			return 0L;
		}
	}

	public void Dispose()
	{
		_stream?.Dispose();
		if (!DeleteOnClose)
		{
			return;
		}

		try
		{
			if (_isDirectory)
			{
				Directory.Delete(FullPath, recursive: true);
			}
			else
			{
				File.Delete(FullPath);
			}
		}
		catch
		{
			// ignored
		}
	}
}
