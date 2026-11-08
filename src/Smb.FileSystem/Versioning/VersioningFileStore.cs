using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Smb.Protocol.Enums;

namespace Smb.FileSystem.Versioning;

public sealed class VersioningFileStore : IFileStore, ISnapshotStore, IDirectoryCursorStore
{
	private sealed record FileVersion(DateTime TimeUtc, byte[] Content, FileEntryInfo Original)
	{
		public FileIdentity Identity { get; } = new FileIdentity("snapshot:" + Guid.NewGuid().ToString("N"));

		public FileEntryInfo SnapshotInfo()
		{
			return new FileEntryInfo
			{
				Name = Original.Name,
				Attributes = ((Original.Attributes | SmbFileAttributes.ReadOnly) & ~SmbFileAttributes.Normal),
				EndOfFile = Content.Length,
				AllocationSize = (Content.Length + 4095) / 4096 * 4096,
				CreationTime = Original.CreationTime,
				LastAccessTime = Original.LastAccessTime,
				LastWriteTime = Original.LastWriteTime,
				ChangeTime = Original.ChangeTime,
			};
		}
	}

	private sealed class FileHistory
	{
		private readonly Lock _gate = new Lock();

		private readonly List<FileVersion> _versions = new List<FileVersion>();

		public void Add(FileVersion version, int max)
		{
			lock (_gate)
			{
				_versions.Add(version);
				if (_versions.Count > max)
				{
					_versions.RemoveRange(0, _versions.Count - max);
				}
			}
		}

		public FileVersion? ResolveAtOrAfter(DateTime t)
		{
			var dateTime = FloorToSecond(t);
			lock (_gate)
			{
				foreach (var version in _versions)
				{
					if (FloorToSecond(version.TimeUtc) >= dateTime)
					{
						return version;
					}
				}

				return null;
			}
		}

		public IReadOnlyList<DateTime> Times()
		{
			lock (_gate)
			{
				var list = new List<DateTime>();
				list.AddRange(_versions.Select(v => v.TimeUtc));
				return list.AsReadOnly();
			}
		}

		private static DateTime FloorToSecond(DateTime t)
		{
			var dateTime = ((t.Kind == DateTimeKind.Utc) ? t : t.ToUniversalTime());
			return new DateTime(dateTime.Year, dateTime.Month, dateTime.Day, dateTime.Hour, dateTime.Minute, dateTime.Second, DateTimeKind.Utc);
		}
	}

	private const long MaxCaptureBytes = 67108864L;

	private readonly IFileStore _inner;

	private readonly int _maxVersionsPerFile;

	private readonly ConcurrentDictionary<string, FileHistory> _history = new ConcurrentDictionary<string, FileHistory>(StringComparer.OrdinalIgnoreCase);

	public VersioningFileStore(IFileStore inner, int maxVersionsPerFile = 64)
	{
		_inner = inner ?? throw new ArgumentNullException(nameof(inner));
		_maxVersionsPerFile = Math.Max(1, maxVersionsPerFile);
	}

	public async ValueTask<FileStoreResult<FileCreateResult>> CreateAsync(string path, FileAccessIntent access, CreateDispositionIntent disposition, bool directoryRequired, bool nonDirectoryRequired, CancellationToken cancellationToken = default(CancellationToken))
	{
		if (GmtToken.TrySplitSnapshotPath(path, out var snapshotUtc, out var remainder))
		{
			var flag = access.HasFlag(FileAccessIntent.Write) || access.HasFlag(FileAccessIntent.Delete);
			if (!flag)
			{
				bool flag2;
				switch (disposition)
				{
					case CreateDispositionIntent.Supersede:
					case CreateDispositionIntent.Create:
					case CreateDispositionIntent.Overwrite:
					case CreateDispositionIntent.OverwriteIf:
						flag2 = true;
						break;
					default:
						flag2 = false;
						break;
				}

				flag = flag2;
			}

			if (flag)
			{
				return FileStoreResult<FileCreateResult>.Fail(NtStatus.AccessDenied);
			}

			if (!TryResolveSnapshot(remainder, snapshotUtc, out var content, out var info, out var identity))
			{
				return FileStoreResult<FileCreateResult>.Fail(NtStatus.ObjectNameNotFound);
			}

			return FileStoreResult<FileCreateResult>.Ok(new FileCreateResult(new SnapshotFileHandle(remainder, content, info, identity), CreateOutcome.Opened));
		}

		if (disposition == CreateDispositionIntent.Supersede || (uint)(disposition - 4) <= 1u)
		{
			await CaptureCurrentVersionAsync(path, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
		}

		return await _inner.CreateAsync(path, access, disposition, directoryRequired, nonDirectoryRequired, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
	}

	public ValueTask<FileStoreResult<int>> ReadAsync(IFileHandle handle, long offset, Memory<byte> buffer, CancellationToken cancellationToken = default(CancellationToken))
	{
		if (!(handle is SnapshotFileHandle snapshotFileHandle))
		{
			return _inner.ReadAsync(handle, offset, buffer, cancellationToken);
		}

		return new ValueTask<FileStoreResult<int>>(snapshotFileHandle.Read(offset, buffer.Span));
	}

	public ValueTask<FileStoreResult<int>> ReadWithOptionsAsync(IFileHandle handle, long offset, Memory<byte> buffer, FileIoOptions options, CancellationToken cancellationToken = default)
		=> handle is SnapshotFileHandle ? ReadAsync(handle, offset, buffer, cancellationToken) : _inner.ReadWithOptionsAsync(handle, offset, buffer, options, cancellationToken);

	public ValueTask<FileStoreResult<int>> WriteWithOptionsAsync(IFileHandle handle, long offset, ReadOnlyMemory<byte> data, FileIoOptions options, CancellationToken cancellationToken = default)
		=> handle is SnapshotFileHandle ? WriteAsync(handle, offset, data, cancellationToken) : _inner.WriteWithOptionsAsync(handle, offset, data, options, cancellationToken);

	public ValueTask<FileStoreResult<IDirectoryCursor>> OpenDirectoryCursorAsync(IFileHandle handle, string pattern, CancellationToken cancellationToken = default)
	{
		if (handle is SnapshotFileHandle) return new ValueTask<FileStoreResult<IDirectoryCursor>>(FileStoreResult<IDirectoryCursor>.Fail(NtStatus.InvalidParameter));

		return _inner is IDirectoryCursorStore cursors
			? cursors.OpenDirectoryCursorAsync(handle, pattern, cancellationToken)
			: new ValueTask<FileStoreResult<IDirectoryCursor>>(FileStoreResult<IDirectoryCursor>.Ok(new LegacyCursor(_inner, handle, pattern)));
	}

	private sealed class LegacyCursor(IFileStore store, IFileHandle handle, string pattern) : IDirectoryCursor
	{
		bool ended;

		public async ValueTask<FileStoreResult<BoundedDirectoryListing>> ReadAsync(int maxEntries, CancellationToken cancellationToken = default)
		{
			if (ended) return FileStoreResult<BoundedDirectoryListing>.Ok(new BoundedDirectoryListing(Array.Empty<FileEntryInfo>(), false));

			var result = await store.QueryDirectoryAsync(handle, pattern, maxEntries, cancellationToken).ConfigureAwait(false);
			if (result.IsSuccess && result.Value.Truncated) return FileStoreResult<BoundedDirectoryListing>.Fail(NtStatus.InsufficientResources);

			ended = true;
			return result;
		}

		public void Dispose() => ended = true;
	}

	public ValueTask<FileStoreResult<int>> WriteAsync(IFileHandle handle, long offset, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default(CancellationToken))
	{
		if (!(handle is SnapshotFileHandle))
		{
			return _inner.WriteAsync(handle, offset, data, cancellationToken);
		}

		return new ValueTask<FileStoreResult<int>>(FileStoreResult<int>.Fail(NtStatus.AccessDenied));
	}

	public ValueTask<FileStoreResult<IReadOnlyList<FileEntryInfo>>> QueryDirectoryAsync(IFileHandle handle, string searchPattern, CancellationToken cancellationToken = default(CancellationToken))
	{
		if (!(handle is SnapshotFileHandle))
		{
			return _inner.QueryDirectoryAsync(handle, searchPattern, cancellationToken);
		}

		return new ValueTask<FileStoreResult<IReadOnlyList<FileEntryInfo>>>(FileStoreResult<IReadOnlyList<FileEntryInfo>>.Fail(NtStatus.InvalidParameter));
	}

	public ValueTask<FileStoreResult<BoundedDirectoryListing>> QueryDirectoryAsync(IFileHandle handle, string searchPattern, int maxEntries, CancellationToken cancellationToken = default(CancellationToken))
	{
		if (!(handle is SnapshotFileHandle))
		{
			return _inner.QueryDirectoryAsync(handle, searchPattern, maxEntries, cancellationToken);
		}

		return new ValueTask<FileStoreResult<BoundedDirectoryListing>>(FileStoreResult<BoundedDirectoryListing>.Fail(NtStatus.InvalidParameter));
	}

	public ValueTask<NtStatus> SetEndOfFileAsync(IFileHandle handle, long length, CancellationToken cancellationToken = default(CancellationToken))
	{
		if (!(handle is SnapshotFileHandle))
		{
			return _inner.SetEndOfFileAsync(handle, length, cancellationToken);
		}

		return new ValueTask<NtStatus>(NtStatus.AccessDenied);
	}

	public ValueTask<NtStatus> RenameAsync(IFileHandle handle, string newPath, bool replaceIfExists, CancellationToken cancellationToken = default(CancellationToken))
	{
		if (!(handle is SnapshotFileHandle))
		{
			return _inner.RenameAsync(handle, newPath, replaceIfExists, cancellationToken);
		}

		return new ValueTask<NtStatus>(NtStatus.AccessDenied);
	}

	public async ValueTask<NtStatus> SetDeleteOnCloseAsync(IFileHandle handle, bool delete, CancellationToken cancellationToken = default(CancellationToken))
	{
		if (handle is SnapshotFileHandle)
		{
			return delete ? NtStatus.AccessDenied : NtStatus.Success;
		}

		if (delete && !handle.IsDirectory && !string.IsNullOrEmpty(handle.Path))
		{
			await CaptureCurrentVersionAsync(handle.Path, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
		}

		return await _inner.SetDeleteOnCloseAsync(handle, delete, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
	}

	public ValueTask<NtStatus> FlushAsync(IFileHandle handle, CancellationToken cancellationToken = default(CancellationToken))
	{
		if (!(handle is SnapshotFileHandle))
		{
			return _inner.FlushAsync(handle, cancellationToken);
		}

		return new ValueTask<NtStatus>(NtStatus.Success);
	}

	public IReadOnlyList<DateTime> GetSnapshots(string path)
	{
		var flag = string.IsNullOrEmpty(path);
		if (!flag)
		{
			var flag2 = (path == "\\" || path == "/");
			flag = flag2;
		}

		if (flag)
		{
			return GetAllSnapshots();
		}

		if (!_history.TryGetValue(Normalize(path), out var value))
		{
			return Array.Empty<DateTime>();
		}

		return value.Times();
	}

	public IReadOnlyList<DateTime> GetAllSnapshots()
	{
		var sortedSet = new SortedSet<DateTime>();
		foreach (var value in _history.Values)
		{
			foreach (var item in value.Times())
			{
				sortedSet.Add(item);
			}
		}

		return sortedSet.ToArray();
	}

	private async ValueTask CaptureCurrentVersionAsync(string path, CancellationToken cancellationToken)
	{
		var (flag, content, original) = await TryReadAllAsync(path, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
		if (flag)
		{
			_history.GetOrAdd(Normalize(path), _ => new FileHistory()).Add(new FileVersion(DateTime.UtcNow, content, original), _maxVersionsPerFile);
		}
	}

	private async ValueTask<(bool Ok, byte[] Content, FileEntryInfo? Info)> TryReadAllAsync(string path, CancellationToken cancellationToken)
	{
		var fileStoreResult = await _inner.CreateAsync(path, FileAccessIntent.Read, CreateDispositionIntent.Open, directoryRequired: false, nonDirectoryRequired: true, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
		if (!fileStoreResult.IsSuccess)
		{
			return (false, Array.Empty<byte>(), null);
		}

		var handle = fileStoreResult.Value.Handle;
		(bool, byte[], FileEntryInfo?) result;
		try
		{
			if (handle.IsDirectory)
			{
				result = (false, Array.Empty<byte>(), null);
			}
			else
			{
				var info = await handle.GetInfoAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
				var size = info.EndOfFile;
				if (size < 0 || size > MaxCaptureBytes)
				{
					result = (false, Array.Empty<byte>(), null);
				}
				else
				{
					var buffer = new byte[size];
					var total = 0;
					while (true)
					{
						if (total < size)
						{
							var fileStoreResult2 = await _inner.ReadAsync(handle, total, buffer.AsMemory(total), cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
							if (!fileStoreResult2.IsSuccess)
							{
								result = (false, Array.Empty<byte>(), null);
								break;
							}

							if (fileStoreResult2.Value != 0)
							{
								total += fileStoreResult2.Value;
								continue;
							}
						}

						var item = ((total == size) ? buffer : buffer[..total]);
						result = (true, item, info);
						break;
					}
				}
			}
		}
		finally
		{
			await handle.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);
		}

		return result;
	}

	private bool TryResolveSnapshot(string realPath, DateTime snapAt, out byte[] content, [NotNullWhen(true)] out FileEntryInfo? info, out FileIdentity identity)
	{
		content = Array.Empty<byte>();
		info = null;
		identity = default;
		if (string.IsNullOrEmpty(realPath) || !_history.TryGetValue(Normalize(realPath), out var value))
		{
			return false;
		}

		var fileVersion = value.ResolveAtOrAfter(snapAt);
		if ((object)fileVersion == null)
		{
			return false;
		}

		content = fileVersion.Content;
		info = fileVersion.SnapshotInfo();
		identity = fileVersion.Identity;
		return true;
	}

	private static string Normalize(string? path)
	{
		return (path ?? string.Empty).Replace('/', '\\').Trim('\\');
	}
}
