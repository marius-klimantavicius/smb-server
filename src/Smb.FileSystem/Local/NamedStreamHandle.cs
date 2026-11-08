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
	public bool DeletePending => _store.StreamDeletePending(StorageKey);
	public string BaseFullPath => _base.PhysicalPath!;
	internal LocalFileHandle BaseHandle => (LocalFileHandle)_base;

	public string StreamName { get; }

	internal string StorageKey { get; }
	private int _closed;
	internal bool IsClosed => Volatile.Read(ref _closed) != 0;

	public string Path => System.IO.Path.GetFileName(BaseFullPath) + ":" + StreamName;

	public bool IsDirectory => false;

	public string? PhysicalPath => BaseFullPath;

	public NamedStreamHandle(LocalFileStore store, string baseFullPath, string streamName)
	{
		_store = store;
		StorageKey = store.GetStreamKey(baseFullPath, streamName);
		_base = store.CreateAsync(System.IO.Path.GetRelativePath(store.RootPath, baseFullPath), FileAccessIntent.Read, CreateDispositionIntent.Open, false, true).GetAwaiter().GetResult().Value.Handle;
		Identity = _base.Identity!.Value with { StreamId = streamName.ToUpperInvariant() };
		StreamName = streamName;
	}

	public FileEntryInfo GetInfo()
	{
		var num = _store.StreamLength(StorageKey);
		var info = _base.GetInfo();
		return new FileEntryInfo
		{
			Name = System.IO.Path.GetFileName(BaseFullPath) + ":" + StreamName + ":$DATA",
			Attributes = SmbFileAttributes.Normal,
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

		try { _store.CloseStream(StorageKey); }
		finally { _base.Dispose(); }

		return new ValueTask<NtStatus>(NtStatus.Success);
	}

	public void Dispose() => CloseAsync().GetAwaiter().GetResult();
}
