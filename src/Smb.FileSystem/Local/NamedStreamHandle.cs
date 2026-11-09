using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Smb.Protocol.Enums;

namespace Smb.FileSystem.Local;

internal sealed class NamedStreamHandle : IFileHandle, IDisposable
{
	private readonly LocalFileStore _store;

	private readonly IFileHandle _base;
	public FileIdentity? Identity { get; }
	public bool DeletePending => Data.DeletePending || _base.DeletePending;
	public bool IsDefaultStream => StreamName.Length == 0;
	public string BaseFullPath => _base.PhysicalPath!;
	internal LocalFileHandle BaseHandle => (LocalFileHandle)_base;

	public string StreamName => Data.Name;

	internal LocalFileStore.StreamData Data { get; }
	private int _closed;
	internal bool IsClosed => Volatile.Read(ref _closed) != 0;

	public string Path => _base.Path + (StreamName.Length == 0 ? "" : ":" + StreamName);

	public bool IsDirectory => false;

	public string? PhysicalPath => BaseFullPath;

	public NamedStreamHandle(LocalFileStore store, string baseFullPath, string streamName)
	{
		_store = store;
		Data = store.GetStreamData(baseFullPath, streamName);
		_base = store.OpenStreamBase(baseFullPath);
		Identity = _base.Identity!.Value with { StreamId = Data.Identity };
	}

	public FileEntryInfo GetInfo()
	{
		var num = _store.StreamLength(Data);
		var info = _base.GetInfo();
		return new FileEntryInfo
		{
			Name = System.IO.Path.GetFileName(BaseFullPath) + ":" + StreamName + ":$DATA",
			Attributes = info.Attributes,
			DeletePending = DeletePending,
			EndOfFile = num,
			AllocationSize = (num + 4095) / 4096 * 4096,
			CreationTime = info.CreationTime,
			LastAccessTime = info.LastAccessTime,
			LastWriteTime = info.LastWriteTime,
			ChangeTime = info.ChangeTime,
			IndexNumber = LocalIdentity.IndexNumber(Identity!.Value),
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

	public ValueTask<NtStatus> CloseAsync()
	{
		if (Interlocked.Exchange(ref _closed, 1) != 0) return new ValueTask<NtStatus>(NtStatus.Success);

		try { _store.CloseStream(Data); }
		finally { _base.Dispose(); }

		return new ValueTask<NtStatus>(NtStatus.Success);
	}

	public void Dispose() => CloseAsync().GetAwaiter().GetResult();
}
