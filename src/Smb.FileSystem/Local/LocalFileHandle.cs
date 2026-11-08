using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;
using Smb.Protocol.Enums;
using Microsoft.Win32.SafeHandles;

namespace Smb.FileSystem.Local;

internal sealed class LocalFileHandle : IFileHandle, IDisposable
{
	private readonly LocalFileStore _store;
	private readonly string _root;

	private readonly FileStream? _stream;

	private readonly bool _isDirectory;

	private readonly Lock _io = new Lock();

	private readonly SafeFileHandle? _directoryHandle;
	private readonly LocalObject _object;
	public FileIdentity? Identity { get; }
	internal SafeFileHandle NativeHandle => _stream?.SafeFileHandle ?? _directoryHandle!;

	public bool DeletePending
	{
		get
		{
			lock (LocalObjects.Gate) return _object.DeletePending;
		}
	}

	internal SemaphoreSlim MutationGate => _object.MutationGate;
	internal bool SuppressLastWriteTimeUpdates;

	private bool _closed;
	private NtStatus _closeStatus;

	public string FullPath { get; private set; }

	public string Path { get; private set; }

	public bool DeleteOnClose { get; set; }

	public bool IsDirectory => _isDirectory;

	public string? PhysicalPath => FullPath;

	public LocalFileHandle(LocalFileStore store, string fullPath, string relativePath, string root, FileStream? stream, bool isDirectory)
	{
		_store = store;
		FullPath = fullPath;
		Path = relativePath;
		_root = root;
		_stream = stream;
		_isDirectory = isDirectory;
		try
		{
			_directoryHandle = isDirectory ? LocalIdentity.OpenDirectory(fullPath) : null;
			Identity = LocalIdentity.Resolve(fullPath, stream?.SafeFileHandle ?? _directoryHandle)!.Value;
			lock (LocalObjects.Gate)
			{
				if (!LocalObjects.Objects.TryGetValue(Identity.Value, out _object))
					LocalObjects.Objects.Add(Identity.Value, _object = new LocalObject());
				if (_object.DeletePending) throw new IOException("Object is delete pending.");

				_object.Handles.Add(this);
			}
		}
		catch
		{
			try { stream?.Dispose(); }
			finally { _directoryHandle?.Dispose(); }
			throw;
		}
	}

	public async ValueTask<FileStoreResult<int>> ReadAtAsync(long offset, Memory<byte> buffer, CancellationToken cancellationToken)
	{
		if (_stream == null) return FileStoreResult<int>.Fail(NtStatus.InvalidParameter);

		try { return FileStoreResult<int>.Ok(await RandomAccess.ReadAsync(_stream.SafeFileHandle, buffer, offset, cancellationToken).ConfigureAwait(false)); }
		catch (IOException) { return FileStoreResult<int>.Fail(NtStatus.InvalidParameter); }
	}

	public async ValueTask<FileStoreResult<int>> WriteAtAsync(long offset, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
	{
		if (_stream == null || !_stream.CanWrite) return FileStoreResult<int>.Fail(NtStatus.AccessDenied);

		await MutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
		DateTime? preserved = null;
		try
		{
			if (SuppressLastWriteTimeUpdates) preserved = File.GetLastWriteTimeUtc(NativeHandle);
			await RandomAccess.WriteAsync(_stream.SafeFileHandle, data, offset, cancellationToken).ConfigureAwait(false);
			return FileStoreResult<int>.Ok(data.Length);
		}
		catch (IOException) { return FileStoreResult<int>.Fail(NtStatus.DiskFull); }
		finally
		{
			try { if (preserved is { } time) File.SetLastWriteTimeUtc(NativeHandle, time); }
			finally { MutationGate.Release(); }
		}
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
		using var mutation = PreserveWriteTime();
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
		using var mutation = PreserveWriteTime();
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

	private IDisposable PreserveWriteTime()
	{
		MutationGate.Wait();
		try { return new WriteTimeScope(this, SuppressLastWriteTimeUpdates ? File.GetLastWriteTimeUtc(NativeHandle) : null); }
		catch { MutationGate.Release(); throw; }
	}

	private sealed class WriteTimeScope(LocalFileHandle owner, DateTime? time) : IDisposable
	{
		public void Dispose()
		{
			try { if (time is { } value) File.SetLastWriteTimeUtc(owner.NativeHandle, value); }
			finally { owner.MutationGate.Release(); }
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
			DeletePending = DeletePending,
			Attributes = _store.GetAttributes(Identity!.Value, File.GetAttributes(_stream?.SafeFileHandle ?? _directoryHandle!)),
			EndOfFile = size,
			AllocationSize = (isDir ? 0 : ((size + 4095) / 4096 * 4096)),
			CreationTime = _store.CreationTime(Identity!.Value, Safe(File.GetCreationTimeUtc(_stream?.SafeFileHandle ?? _directoryHandle!))),
			LastAccessTime = Safe(File.GetLastAccessTimeUtc(_stream?.SafeFileHandle ?? _directoryHandle!)),
			LastWriteTime = Safe(File.GetLastWriteTimeUtc(_stream?.SafeFileHandle ?? _directoryHandle!)),
			ChangeTime = Safe(File.GetLastWriteTimeUtc(_stream?.SafeFileHandle ?? _directoryHandle!)),
			IndexNumber = LocalIdentity.IndexNumber(Identity!.Value),
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

	/// <summary>Validate before marking, without changing the existing flag on failure.</summary>
	public NtStatus SetDeleteOnClose(bool delete)
	{
		lock (LocalObjects.Gate)
		lock (_io)
		{
			if (_closed) return NtStatus.FileClosed;

			try
			{
				if (delete && (File.GetAttributes(NativeHandle) & FileAttributes.ReadOnly) != 0)
					return (NtStatus)0xc0000121;
				if (delete && _isDirectory && Directory.EnumerateFileSystemEntries(FullPath).Any())
					return NtStatus.DirectoryNotEmpty;

				DeleteOnClose = delete;
				_object.DeletePending = delete;
				_object.DeletePath = delete ? FullPath : null;
				return NtStatus.Success;
			}
			catch (UnauthorizedAccessException) { return NtStatus.AccessDenied; }
			catch (DirectoryNotFoundException) { return NtStatus.ObjectNameNotFound; }
			catch (IOException) { return NtStatus.AccessDenied; }
		}
	}

	public ValueTask<NtStatus> CloseAsync() => new ValueTask<NtStatus>(Close());

	// Resource cleanup cannot communicate an NTSTATUS. Explicit CLOSE uses CloseAsync;
	// repeated disposal never repeats pathname deletion or targets a replacement object.
	public void Dispose() => Close();

	private NtStatus Close()
	{
		lock (LocalObjects.Gate)
		lock (_io)
		{
			if (_closed) return _closeStatus;

			_closed = true;
			try
			{
				_object.Handles.Remove(this);
				if (_object.Handles.Count != 0) return _closeStatus = NtStatus.Success;

				LocalObjects.Objects.Remove(Identity!.Value);
				DeleteOnClose = _object.DeletePending;
				var deletePath = _object.DeletePath ?? FullPath;
				// Never delete a pathname now referring to a replacement object.
				if (DeleteOnClose && LocalIdentity.Resolve(deletePath) != Identity) return _closeStatus = NtStatus.ObjectNameNotFound;

				if (DeleteOnClose)
				{
					var lastLink = _isDirectory || LocalIdentity.LinkCount(NativeHandle) == 1;
					if (OperatingSystem.IsWindows()) WindowsLocalIdentity.Delete(deletePath, Identity!.Value);
					else if (_isDirectory) Directory.Delete(deletePath, recursive: false);
					else File.Delete(deletePath);
					if (lastLink) _store.RetireMetadata(Identity!.Value);
				}

				return _closeStatus = NtStatus.Success;
			}
			catch (UnauthorizedAccessException) { return _closeStatus = NtStatus.AccessDenied; }
			catch (DirectoryNotFoundException) { return _closeStatus = NtStatus.ObjectNameNotFound; }
			catch (IOException)
			{
				// The final host operation is nonrecursive; a child arriving after validation
				// is preserved. Inspect only to map the failed host operation's status.
				try
				{
					if (DeleteOnClose && _isDirectory && Directory.EnumerateFileSystemEntries(_object.DeletePath ?? FullPath).Any())
						return _closeStatus = NtStatus.DirectoryNotEmpty;
				}
				catch (IOException) { }
				catch (UnauthorizedAccessException) { }

				return _closeStatus = NtStatus.AccessDenied;
			}
			finally
			{
				try { _stream?.Dispose(); }
				finally { _directoryHandle?.Dispose(); }
			}

		}
	}
}
