using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Smb.FileSystem.Security;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Security;

namespace Smb.FileSystem.Local;

public sealed class LocalFileStore : SyncFileStore, IFileStore, INamedStreamStore, IExtendedAttributeStore, IBasicInfoStore, ISharedDeleteFileStore, IDirectoryCursorStore, IVolumeInfoProvider, ICacheCoherentFileStore
{
	private sealed class StreamData
	{
		public required string Name;

		public byte[] Content = Array.Empty<byte>();
		public int Opens;
		public bool DeletePending;
	}

	internal string RootPath => _root;
	private readonly string _root;

	private readonly string _realRoot;

	private readonly bool _readOnly;

	private readonly ISecurityDescriptorStore _securityStore;

	private readonly Lock _adsLock = new Lock();

	private readonly Dictionary<string, StreamData> _streams = new Dictionary<string, StreamData>(StringComparer.Ordinal);

	private readonly Dictionary<string, List<ExtendedAttribute>> _eas = new Dictionary<string, List<ExtendedAttribute>>(StringComparer.Ordinal);

	private const uint SettableAttributes = 8615u;

	public LocalFileStore(string rootDirectory, bool readOnly = true, ISecurityDescriptorStore? securityStore = null)
		: this(rootDirectory, readOnly, securityStore, false)
	{
	}

	public LocalFileStore(string rootDirectory, bool readOnly, ISecurityDescriptorStore? securityStore, bool exclusiveServerAccess)
	{
		HasExclusiveServerAccess = exclusiveServerAccess;
		LocalIdentity.EnsureSupported();
		_root = Path.GetFullPath(rootDirectory);
		Directory.CreateDirectory(_root);
		_realRoot = TryResolveRealPath(_root) ?? _root;
		_readOnly = readOnly;
		_securityStore = securityStore ?? new InMemorySecurityDescriptorStore();
	}

	/// <summary>Deployment assertion: all access, including aliases and alternate streams,
	/// uses one SmbServerState. The caller must prevent direct host/other-server mutation.</summary>
	public bool HasExclusiveServerAccess { get; }

	public VolumeInfo GetVolumeInfo()
	{
		if (OperatingSystem.IsWindows()) return WindowsLocalIdentity.Volume(_root);
		var drive = new DriveInfo(_root);
		return new VolumeInfo("SMBLOCAL", 0, drive.TotalSize, drive.AvailableFreeSpace);
	}

	public ValueTask<FileIdentity?> ResolveIdentityAsync(string path, string streamName = "", CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		if (!TryResolve(path, out var full)) return new ValueTask<FileIdentity?>((FileIdentity?)null);

		var identity = LocalIdentity.Resolve(full);
		return new ValueTask<FileIdentity?>(identity is { } id ? id with { StreamId = streamName.ToUpperInvariant() } : null);
	}

	protected override FileStoreResult<IFileHandle> Create(string path, FileAccessIntent access, CreateDispositionIntent disposition, bool directoryRequired, bool nonDirectoryRequired, out CreateOutcome createAction)
	{
		lock (LocalObjects.Gate) return CreateCore(path, access, disposition, directoryRequired, nonDirectoryRequired, out createAction);
	}

	private FileStoreResult<IFileHandle> CreateCore(string path, FileAccessIntent access, CreateDispositionIntent disposition, bool directoryRequired, bool nonDirectoryRequired, out CreateOutcome createAction)
	{
		createAction = CreateOutcome.Opened;
		if (!TryResolve(path, out var fullPath))
		{
			return FileStoreResult<IFileHandle>.Fail(NtStatus.ObjectNameNotFound);
		}

		var existingIdentity = LocalIdentity.Resolve(fullPath);
		if (existingIdentity is { } eid && LocalObjects.Objects.TryGetValue(eid, out var obj) && obj.DeletePending)
			return FileStoreResult<IFileHandle>.Fail((NtStatus)0xc0000056);

		var flag = access.HasFlag(FileAccessIntent.Write);
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

		var flag3 = flag;
		if (_readOnly & flag3)
		{
			return FileStoreResult<IFileHandle>.Fail(NtStatus.AccessDenied);
		}

		var flag4 = Directory.Exists(fullPath);
		var flag5 = File.Exists(fullPath);
		var flag6 = flag4 | flag5;
		if ((directoryRequired & flag6) && !flag4)
		{
			return FileStoreResult<IFileHandle>.Fail(NtStatus.NotADirectory);
		}

		if (nonDirectoryRequired & flag6 & flag4)
		{
			return FileStoreResult<IFileHandle>.Fail(NtStatus.FileIsADirectory);
		}

		var relative = ((fullPath == _root) ? string.Empty : path);
		if (directoryRequired || (flag6 & flag4))
		{
			var result = CreateDirectoryHandle(fullPath, relative, disposition, flag6, out createAction);
			if (result.IsSuccess && createAction == CreateOutcome.Created)
			{
				ApplyInheritedSecurity(fullPath, isDirectory: true);
			}

			return result;
		}

		var result2 = CreateFileHandle(fullPath, relative, access, disposition, flag6, out createAction);
		if (result2.IsSuccess && createAction == CreateOutcome.Created)
		{
			ApplyInheritedSecurity(fullPath, isDirectory: false);
		}

		return result2;
	}

	private void ApplyInheritedSecurity(string childFull, bool isDirectory)
	{
		var directoryName = Path.GetDirectoryName(childFull);
		if (directoryName == null)
		{
			return;
		}

		var securityDescriptor = _securityStore.TryGet(directoryName);
		if (securityDescriptor != null)
		{
			var securityDescriptor2 = AclInheritance.ComputeInherited(securityDescriptor, isDirectory);
			if (securityDescriptor2 != null)
			{
				_securityStore.Set(childFull, securityDescriptor2);
			}
		}
	}

	private FileStoreResult<IFileHandle> CreateDirectoryHandle(string full, string relative, CreateDispositionIntent disposition, bool exists, out CreateOutcome createAction)
	{
		createAction = CreateOutcome.Opened;
		switch (disposition)
		{
			case CreateDispositionIntent.Open:
			case CreateDispositionIntent.Overwrite:
				if (!exists)
				{
					return FileStoreResult<IFileHandle>.Fail(NtStatus.ObjectNameNotFound);
				}

				createAction = ((disposition != CreateDispositionIntent.Overwrite) ? CreateOutcome.Opened : CreateOutcome.Overwritten);
				break;
			case CreateDispositionIntent.Create:
				if (exists)
				{
					return FileStoreResult<IFileHandle>.Fail(NtStatus.ObjectNameCollision);
				}

				Directory.CreateDirectory(full);
				createAction = CreateOutcome.Created;
				break;
			default:
				if (!exists)
				{
					Directory.CreateDirectory(full);
					createAction = CreateOutcome.Created;
				}
				else
				{
					createAction = ((disposition == CreateDispositionIntent.OpenIf) ? CreateOutcome.Opened : CreateOutcome.Overwritten);
				}

				break;
		}

		return FileStoreResult<IFileHandle>.Ok(new LocalFileHandle(full, relative, _root, null, isDirectory: true));
	}

	private FileStoreResult<IFileHandle> CreateFileHandle(string full, string relative, FileAccessIntent access, CreateDispositionIntent disposition, bool exists, out CreateOutcome createAction)
	{
		createAction = CreateOutcome.Opened;
		var flag = disposition == CreateDispositionIntent.Open || disposition == CreateDispositionIntent.Overwrite;
		if (flag && !exists)
		{
			return FileStoreResult<IFileHandle>.Fail(NtStatus.ObjectNameNotFound);
		}

		if ((disposition == CreateDispositionIntent.Create) & exists)
		{
			return FileStoreResult<IFileHandle>.Fail(NtStatus.ObjectNameCollision);
		}

		var fileMode = disposition switch
		{
			CreateDispositionIntent.Open => FileMode.Open,
			CreateDispositionIntent.Create => FileMode.CreateNew,
			CreateDispositionIntent.OpenIf => FileMode.OpenOrCreate,
			CreateDispositionIntent.Overwrite => FileMode.Truncate,
			CreateDispositionIntent.OverwriteIf => FileMode.Create,
			CreateDispositionIntent.Supersede => FileMode.Create,
			_ => FileMode.Open,
		};
		var access2 = (((!access.HasFlag(FileAccessIntent.Write) && disposition == CreateDispositionIntent.Open) || _readOnly) ? FileAccess.Read : FileAccess.ReadWrite);
		try
		{
			var stream = new FileStream(full, fileMode, access2, FileShare.ReadWrite | FileShare.Delete, 1);
			createAction = disposition switch
			{
				CreateDispositionIntent.Create => CreateOutcome.Created,
				CreateDispositionIntent.Overwrite => CreateOutcome.Overwritten,
				CreateDispositionIntent.OpenIf => exists ? CreateOutcome.Opened : CreateOutcome.Created,
				CreateDispositionIntent.OverwriteIf => exists ? CreateOutcome.Overwritten : CreateOutcome.Created,
				CreateDispositionIntent.Supersede => (!exists) ? CreateOutcome.Created : CreateOutcome.Superseded,
				_ => CreateOutcome.Opened,
			};
			return FileStoreResult<IFileHandle>.Ok(new LocalFileHandle(full, relative, _root, stream, isDirectory: false));
		}
		catch (FileNotFoundException)
		{
			return FileStoreResult<IFileHandle>.Fail(NtStatus.ObjectNameNotFound);
		}
		catch (DirectoryNotFoundException)
		{
			return FileStoreResult<IFileHandle>.Fail(NtStatus.ObjectPathNotFound);
		}
		catch (UnauthorizedAccessException)
		{
			return FileStoreResult<IFileHandle>.Fail(NtStatus.AccessDenied);
		}
		catch (IOException ex4) when (IsSharingViolation(ex4))
		{
			return FileStoreResult<IFileHandle>.Fail(NtStatus.SharingViolation);
		}
		catch (IOException) when (fileMode == FileMode.CreateNew)
		{
			return FileStoreResult<IFileHandle>.Fail(NtStatus.ObjectNameCollision);
		}
		catch (IOException)
		{
			return FileStoreResult<IFileHandle>.Fail(NtStatus.InvalidParameter);
		}
	}

	private static bool IsSharingViolation(IOException ex)
	{
		return (ex.HResult & 0xFFFF) == 32;
	}

	protected override FileStoreResult<int> Read(IFileHandle handle, long offset, Span<byte> buffer)
	{
		if (handle is NamedStreamHandle namedStreamHandle)
		{
			return StreamRead(namedStreamHandle.StorageKey, offset, buffer);
		}

		var localFileHandle = (LocalFileHandle)handle;
		if (localFileHandle.IsDirectory)
		{
			return FileStoreResult<int>.Fail(NtStatus.FileIsADirectory);
		}

		return localFileHandle.ReadAt(offset, buffer);
	}

	public override async ValueTask<FileStoreResult<int>> ReadAsync(IFileHandle handle, long offset, Memory<byte> buffer, CancellationToken cancellationToken = default(CancellationToken))
	{
		if (handle is NamedStreamHandle namedStreamHandle)
		{
			return StreamRead(namedStreamHandle.StorageKey, offset, buffer.Span);
		}

		var localFileHandle = (LocalFileHandle)handle;
		if (localFileHandle.IsDirectory)
		{
			return FileStoreResult<int>.Fail(NtStatus.FileIsADirectory);
		}

		return await localFileHandle.ReadAtAsync(offset, buffer, cancellationToken).ConfigureAwait(false);
	}

	protected override FileStoreResult<int> Write(IFileHandle handle, long offset, ReadOnlySpan<byte> data)
	{
		if (handle is NamedStreamHandle namedStreamHandle)
		{
			return StreamWrite(namedStreamHandle.StorageKey, offset, data);
		}

		if (_readOnly)
		{
			return FileStoreResult<int>.Fail(NtStatus.AccessDenied);
		}

		var localFileHandle = (LocalFileHandle)handle;
		if (localFileHandle.IsDirectory)
		{
			return FileStoreResult<int>.Fail(NtStatus.FileIsADirectory);
		}

		return localFileHandle.WriteAt(offset, data);
	}

	public override async ValueTask<FileStoreResult<int>> WriteAsync(IFileHandle handle, long offset, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default(CancellationToken))
	{
		if (handle is NamedStreamHandle namedStreamHandle)
		{
			return StreamWrite(namedStreamHandle.StorageKey, offset, data.Span);
		}

		if (_readOnly)
		{
			return FileStoreResult<int>.Fail(NtStatus.AccessDenied);
		}

		var localFileHandle = (LocalFileHandle)handle;
		if (localFileHandle.IsDirectory)
		{
			return FileStoreResult<int>.Fail(NtStatus.FileIsADirectory);
		}

		return await localFileHandle.WriteAtAsync(offset, data, cancellationToken).ConfigureAwait(false);
	}

	public async ValueTask<FileStoreResult<int>> WriteWithOptionsAsync(IFileHandle handle, long offset, ReadOnlyMemory<byte> data, FileIoOptions options, CancellationToken cancellationToken = default)
	{
		// Named streams are process-memory objects. Never acknowledge disk durability for them.
		if (options.WriteThrough && handle is NamedStreamHandle) return FileStoreResult<int>.Fail(NtStatus.NotSupported);

		var result = await WriteAsync(handle, offset, data, cancellationToken).ConfigureAwait(false);
		if (!result.IsSuccess || !options.WriteThrough) return result;

		var status = Flush(handle);
		return status == NtStatus.Success ? result : FileStoreResult<int>.Fail(status);
	}

	public ValueTask<FileStoreResult<IDirectoryCursor>> OpenDirectoryCursorAsync(IFileHandle handle, string pattern, CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		if (handle is not LocalFileHandle local || !local.IsDirectory) return new ValueTask<FileStoreResult<IDirectoryCursor>>(FileStoreResult<IDirectoryCursor>.Fail(NtStatus.InvalidParameter));

		return new ValueTask<FileStoreResult<IDirectoryCursor>>(FileStoreResult<IDirectoryCursor>.Ok(new LocalDirectoryCursor(Entries().GetEnumerator())));

		IEnumerable<FileEntryInfo> Entries()
		{
			var directory = new DirectoryInfo(local.FullPath);
			var match = string.IsNullOrEmpty(pattern) ? "*" : pattern;
			// Follow the host's ordinary name comparison; Linux case stays significant.
			if (System.IO.Enumeration.FileSystemName.MatchesSimpleExpression(match, ".", OperatingSystem.IsWindows())) yield return ToEntry(directory, ".");
			if (directory.FullName != _root && System.IO.Enumeration.FileSystemName.MatchesSimpleExpression(match, "..", OperatingSystem.IsWindows())) yield return ToEntry(directory.Parent ?? directory, "..");
			foreach (var entry in directory.EnumerateFileSystemInfos(match, new EnumerationOptions { MatchCasing = MatchCasing.PlatformDefault, AttributesToSkip = 0 }))
				yield return ToEntry(entry, entry.Name);
		}
	}

	private sealed class LocalDirectoryCursor(IEnumerator<FileEntryInfo> entries) : IDirectoryCursor
	{
		bool ended;

		public ValueTask<FileStoreResult<BoundedDirectoryListing>> ReadAsync(int maxEntries, CancellationToken cancellationToken = default)
		{
			var batch = new List<FileEntryInfo>();
			while (!ended && batch.Count < Math.Max(1, maxEntries))
			{
				cancellationToken.ThrowIfCancellationRequested();
				if (entries.MoveNext()) batch.Add(entries.Current);
				else
				{
					ended = true;
					entries.Dispose();
				}
			}

			return new ValueTask<FileStoreResult<BoundedDirectoryListing>>(FileStoreResult<BoundedDirectoryListing>.Ok(new BoundedDirectoryListing(batch, !ended)));
		}

		public void Dispose()
		{
			ended = true;
			entries.Dispose();
		}
	}

	protected override FileStoreResult<IReadOnlyList<FileEntryInfo>> QueryDirectory(IFileHandle handle, string searchPattern)
	{
		var localFileHandle = (LocalFileHandle)handle;
		if (!localFileHandle.IsDirectory)
		{
			return FileStoreResult<IReadOnlyList<FileEntryInfo>>.Fail(NtStatus.InvalidParameter);
		}

		var searchPattern2 = (string.IsNullOrEmpty(searchPattern) ? "*" : searchPattern);
		var list = new List<FileEntryInfo>();
		var directoryInfo = new DirectoryInfo(localFileHandle.FullPath);
		list.Add(ToEntry(directoryInfo, "."));
		if (Path.GetFullPath(localFileHandle.FullPath) != _root)
		{
			list.Add(ToEntry(directoryInfo.Parent ?? directoryInfo, ".."));
		}

		try
		{
			foreach (var item in directoryInfo.EnumerateFileSystemInfos(searchPattern2))
			{
				list.Add(ToEntry(item, item.Name));
			}
		}
		catch (DirectoryNotFoundException)
		{
			return FileStoreResult<IReadOnlyList<FileEntryInfo>>.Fail(NtStatus.ObjectNameNotFound);
		}

		return FileStoreResult<IReadOnlyList<FileEntryInfo>>.Ok(list);
	}

	protected override FileStoreResult<BoundedDirectoryListing> QueryDirectory(IFileHandle handle, string searchPattern, int maxEntries)
	{
		var localFileHandle = (LocalFileHandle)handle;
		if (!localFileHandle.IsDirectory)
		{
			return FileStoreResult<BoundedDirectoryListing>.Fail(NtStatus.InvalidParameter);
		}

		var searchPattern2 = (string.IsNullOrEmpty(searchPattern) ? "*" : searchPattern);
		var list = new List<FileEntryInfo>();
		var directoryInfo = new DirectoryInfo(localFileHandle.FullPath);
		list.Add(ToEntry(directoryInfo, "."));
		if (Path.GetFullPath(localFileHandle.FullPath) != _root)
		{
			list.Add(ToEntry(directoryInfo.Parent ?? directoryInfo, ".."));
		}

		var truncated = false;
		try
		{
			foreach (var item in directoryInfo.EnumerateFileSystemInfos(searchPattern2))
			{
				if (maxEntries > 0 && list.Count >= maxEntries)
				{
					truncated = true;
					break;
				}

				list.Add(ToEntry(item, item.Name));
			}
		}
		catch (DirectoryNotFoundException)
		{
			return FileStoreResult<BoundedDirectoryListing>.Fail(NtStatus.ObjectNameNotFound);
		}

		return FileStoreResult<BoundedDirectoryListing>.Ok(new BoundedDirectoryListing(list, truncated));
	}

	protected override NtStatus SetEndOfFile(IFileHandle handle, long length)
	{
		if (_readOnly)
		{
			return NtStatus.AccessDenied;
		}

		if (handle is NamedStreamHandle namedStreamHandle)
		{
			return StreamSetLength(namedStreamHandle.StorageKey, length);
		}

		return ((LocalFileHandle)handle).SetLength(length);
	}

	protected override NtStatus Rename(IFileHandle handle, string newPath, bool replaceIfExists)
	{
		lock (LocalObjects.Gate) return RenameCore(handle, newPath, replaceIfExists);
	}

	private NtStatus RenameCore(IFileHandle handle, string newPath, bool replaceIfExists)
	{
		if (_readOnly)
		{
			return NtStatus.AccessDenied;
		}

		if (handle is NamedStreamHandle)
		{
			return NtStatus.NotSupported;
		}

		var localFileHandle = (LocalFileHandle)handle;
		if (!TryResolve(newPath, out var fullPath))
		{
			return NtStatus.ObjectPathNotFound;
		}

		try
		{
			var oldFull = localFileHandle.FullPath;
			var destinationId = LocalIdentity.Resolve(fullPath);
			if (localFileHandle.Identity is { } sourceId && LocalObjects.Objects[sourceId].DeletePending)
				return (NtStatus)0xc0000056;

			// Same entry (including a Windows case-only rename) is not an open
			// destination conflict. Other hardlink aliases remain separate entries.
			var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
			var sameEntry = destinationId == localFileHandle.Identity && string.Equals(oldFull, fullPath, comparison);
			if (sameEntry && string.Equals(oldFull, fullPath, StringComparison.Ordinal)) return NtStatus.Success;
			if (!sameEntry && destinationId is { } did && LocalObjects.Objects.TryGetValue(did, out var destination) && destination.Handles.Count > 0)
				return destination.DeletePending ? (NtStatus)0xc0000056 : NtStatus.AccessDenied;
			if (!sameEntry && destinationId != null && !replaceIfExists)
			{
				return NtStatus.ObjectNameCollision;
			}

			if (OperatingSystem.IsWindows())
			{
				WindowsLocalIdentity.Rename(oldFull, fullPath, localFileHandle.Identity!.Value, replaceIfExists);
			}
			else if (localFileHandle.IsDirectory)
			{
				Directory.Move(localFileHandle.FullPath, fullPath);
			}
			else
			{
				File.Move(localFileHandle.FullPath, fullPath, replaceIfExists);
			}

			foreach (var entry in LocalObjects.Objects.Values)
			{
				foreach (var h in entry.Handles)
				{
					if (string.Equals(h.FullPath, oldFull, comparison) || (localFileHandle.IsDirectory && h.FullPath.StartsWith(oldFull + Path.DirectorySeparatorChar, comparison)))
					{
						var relocated = fullPath + h.FullPath.Substring(oldFull.Length);
						h.Relocate(relocated, Path.GetRelativePath(_root, relocated));
					}
				}
				if (entry.DeletePath is { } pendingPath && (string.Equals(pendingPath, oldFull, comparison) ||
					(localFileHandle.IsDirectory && pendingPath.StartsWith(oldFull + Path.DirectorySeparatorChar, comparison))))
					entry.DeletePath = fullPath + pendingPath.Substring(oldFull.Length);
			}

			return NtStatus.Success;
		}
		catch (IOException)
		{
			return NtStatus.AccessDenied;
		}
	}

	public ValueTask<NtStatus> SetBasicInfoAsync(IFileHandle handle, FileBasicInfoUpdate update, CancellationToken cancellationToken = default(CancellationToken))
	{
		if (update.ChangeTime.HasValue) return new ValueTask<NtStatus>(NtStatus.NotSupported);

		if (_readOnly)
		{
			return new ValueTask<NtStatus>(NtStatus.AccessDenied);
		}

		var local = handle is NamedStreamHandle namedStreamHandle ? namedStreamHandle.BaseHandle : (LocalFileHandle)handle;
		try
		{
			using var metadata = OperatingSystem.IsWindows() ? WindowsLocalIdentity.OpenMetadata(local.NativeHandle) : null;
			var native = metadata ?? local.NativeHandle;
			var creationTime = update.CreationTime;
			if (creationTime.HasValue)
			{
				var valueOrDefault = creationTime.GetValueOrDefault();
				File.SetCreationTimeUtc(native, DateTime.FromFileTimeUtc(valueOrDefault));
			}

			creationTime = update.LastAccessTime;
			if (creationTime.HasValue)
			{
				var valueOrDefault2 = creationTime.GetValueOrDefault();
				File.SetLastAccessTimeUtc(native, DateTime.FromFileTimeUtc(valueOrDefault2));
			}

			creationTime = update.LastWriteTime;
			if (creationTime.HasValue)
			{
				var valueOrDefault3 = creationTime.GetValueOrDefault();
				File.SetLastWriteTimeUtc(native, DateTime.FromFileTimeUtc(valueOrDefault3));
			}

			var attributes = update.Attributes;
			if (attributes.HasValue)
			{
				var valueOrDefault4 = attributes.GetValueOrDefault();
				File.SetAttributes(native, (FileAttributes)(valueOrDefault4 & SettableAttributes));
			}

			return new ValueTask<NtStatus>(NtStatus.Success);
		}
		catch (UnauthorizedAccessException)
		{
			return new ValueTask<NtStatus>(NtStatus.AccessDenied);
		}
		catch (ArgumentOutOfRangeException)
		{
			return new ValueTask<NtStatus>(NtStatus.InvalidParameter);
		}
		catch (IOException)
		{
			return new ValueTask<NtStatus>(NtStatus.AccessDenied);
		}
	}

	protected override NtStatus SetDeleteOnClose(IFileHandle handle, bool delete)
	{
		if (_readOnly & delete)
		{
			return NtStatus.AccessDenied;
		}

		if (handle is NamedStreamHandle namedStreamHandle)
		{
			return SetStreamDelete(namedStreamHandle, delete);
		}

		return ((LocalFileHandle)handle).SetDeleteOnClose(delete);
	}

	protected override NtStatus Flush(IFileHandle handle)
	{
		if (!(handle is NamedStreamHandle))
		{
			return ((LocalFileHandle)handle).FlushStream();
		}

		return NtStatus.Success;
	}

	public override ValueTask<FileStoreResult<SecurityDescriptor>> GetSecurityAsync(IFileHandle handle, CancellationToken cancellationToken = default(CancellationToken))
	{
		var key = ((handle is NamedStreamHandle namedStreamHandle) ? namedStreamHandle.BaseFullPath : ((LocalFileHandle)handle).FullPath);
		return new ValueTask<FileStoreResult<SecurityDescriptor>>(FileStoreResult<SecurityDescriptor>.Ok(_securityStore.TryGet(key) ?? DefaultDescriptor()));
	}

	public override ValueTask<NtStatus> SetSecurityAsync(IFileHandle handle, SecurityDescriptor descriptor, CancellationToken cancellationToken = default(CancellationToken))
	{
		if (_readOnly)
		{
			return new ValueTask<NtStatus>(NtStatus.AccessDenied);
		}

		var key = ((handle is NamedStreamHandle namedStreamHandle) ? namedStreamHandle.BaseFullPath : ((LocalFileHandle)handle).FullPath);
		_securityStore.Set(key, descriptor);
		return new ValueTask<NtStatus>(NtStatus.Success);
	}

	public ValueTask<FileStoreResult<FileCreateResult>> OpenNamedStreamAsync(string basePath, string streamName, FileAccessIntent access, CreateDispositionIntent disposition, CancellationToken cancellationToken = default(CancellationToken))
	{
		lock (LocalObjects.Gate) return OpenNamedStreamCore(basePath, streamName, access, disposition, cancellationToken);
	}

	private ValueTask<FileStoreResult<FileCreateResult>> OpenNamedStreamCore(string basePath, string streamName, FileAccessIntent access, CreateDispositionIntent disposition, CancellationToken cancellationToken)
	{
		if (!TryResolve(basePath, out var fullPath))
		{
			return Fail(NtStatus.ObjectNameNotFound);
		}

		var flag = access.HasFlag(FileAccessIntent.Write);
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

		var flag3 = flag;
		if (_readOnly & flag3)
		{
			return Fail(NtStatus.AccessDenied);
		}

		if (!File.Exists(fullPath))
		{
			return Fail(NtStatus.ObjectNameNotFound);
		}

		var baseId = LocalIdentity.Resolve(fullPath)!.Value;
		if (LocalObjects.Objects.TryGetValue(baseId, out var baseObject) && baseObject.DeletePending) return Fail((NtStatus)0xc0000056);

		var key = StreamKey(fullPath, streamName);
		CreateOutcome action;
		lock (_adsLock)
		{
			var flag4 = _streams.ContainsKey(key);
			if (flag4 && _streams[key].DeletePending) return Fail((NtStatus)0xc0000056);

			switch (disposition)
			{
				case CreateDispositionIntent.Open:
					if (!flag4)
					{
						return Fail(NtStatus.ObjectNameNotFound);
					}

					action = CreateOutcome.Opened;
					break;
				case CreateDispositionIntent.Create:
					if (flag4)
					{
						return Fail(NtStatus.ObjectNameCollision);
					}

					ResetStream(key, streamName);
					action = CreateOutcome.Created;
					break;
				case CreateDispositionIntent.Overwrite:
					if (!flag4)
					{
						return Fail(NtStatus.ObjectNameNotFound);
					}

					ResetStream(key, streamName);
					action = CreateOutcome.Overwritten;
					break;
				case CreateDispositionIntent.OpenIf:
					if (!flag4)
					{
						_streams[key] = new StreamData
						{
							Name = streamName,
						};
						action = CreateOutcome.Created;
					}
					else
					{
						action = CreateOutcome.Opened;
					}

					break;
				case CreateDispositionIntent.OverwriteIf:
					action = (flag4 ? CreateOutcome.Overwritten : CreateOutcome.Created);
					ResetStream(key, streamName);
					break;
				default:
					action = ((!flag4) ? CreateOutcome.Created : CreateOutcome.Superseded);
					ResetStream(key, streamName);
					break;
			}
		}

		lock (_adsLock) _streams[key].Opens++;
		try { return new ValueTask<FileStoreResult<FileCreateResult>>(FileStoreResult<FileCreateResult>.Ok(new FileCreateResult(new NamedStreamHandle(this, fullPath, streamName), action))); }
		catch
		{
			CloseStream(key);
			throw;
		}

		static ValueTask<FileStoreResult<FileCreateResult>> Fail(NtStatus s)
		{
			return new ValueTask<FileStoreResult<FileCreateResult>>(FileStoreResult<FileCreateResult>.Fail(s));
		}
	}

	public ValueTask<FileStoreResult<IReadOnlyList<StreamInfo>>> QueryStreamsAsync(IFileHandle handle, CancellationToken cancellationToken = default(CancellationToken))
	{
		var text = ((handle is NamedStreamHandle namedStreamHandle) ? namedStreamHandle.BaseFullPath : ((LocalFileHandle)handle).FullPath);
		var list = new List<StreamInfo>();
		if (File.Exists(text))
		{
			var length = new FileInfo(text).Length;
			list.Add(new StreamInfo(string.Empty, length, AlignUp(length, 4096L)));
		}

		var value = handle.Identity!.Value.ObjectId + "\0";
		lock (_adsLock)
		{
			foreach (var stream in _streams)
			{
				if (stream.Key.StartsWith(value, StringComparison.Ordinal))
				{
					list.Add(new StreamInfo(stream.Value.Name, stream.Value.Content.Length, AlignUp(stream.Value.Content.Length, 4096L)));
				}
			}
		}

		return new ValueTask<FileStoreResult<IReadOnlyList<StreamInfo>>>(FileStoreResult<IReadOnlyList<StreamInfo>>.Ok(list));
	}

	private static string StreamKey(string fullBase, string streamName)
	{
		return LocalIdentity.Resolve(fullBase)!.Value.ObjectId + "\0" + streamName.ToUpperInvariant();
	}

	private void ResetStream(string key, string name)
	{
		if (_streams.TryGetValue(key, out var data)) data.Content = Array.Empty<byte>();
		else _streams.Add(key, new StreamData { Name = name });
	}

	internal string GetStreamKey(string full, string name) => StreamKey(full, name);

	private NtStatus SetStreamDelete(NamedStreamHandle handle, bool delete)
	{
		lock (_adsLock)
		{
			if (handle.IsClosed || !_streams.TryGetValue(handle.StorageKey, out var data)) return NtStatus.FileClosed;

			data.DeletePending = delete;
			return NtStatus.Success;
		}
	}

	internal bool StreamDeletePending(string key)
	{
		lock (_adsLock) return _streams.TryGetValue(key, out var data) && data.DeletePending;
	}

	internal void CloseStream(string key)
	{
		lock (_adsLock)
		{
			if (!_streams.TryGetValue(key, out var data)) return;

			if (--data.Opens == 0 && data.DeletePending) _streams.Remove(key);
		}
	}

	internal FileStoreResult<int> StreamRead(string key, long offset, Span<byte> buffer)
	{
		lock (_adsLock)
		{
			if (!_streams.TryGetValue(key, out var value))
			{
				return FileStoreResult<int>.Fail(NtStatus.FileClosed);
			}

			if (offset < 0 || offset >= value.Content.Length)
			{
				return FileStoreResult<int>.Ok(0);
			}

			var num = (int)Math.Min(buffer.Length, value.Content.Length - offset);
			value.Content.AsSpan((int)offset, num).CopyTo(buffer);
			return FileStoreResult<int>.Ok(num);
		}
	}

	internal FileStoreResult<int> StreamWrite(string key, long offset, ReadOnlySpan<byte> data)
	{
		if (_readOnly)
		{
			return FileStoreResult<int>.Fail(NtStatus.AccessDenied);
		}

		if (offset < 0)
		{
			return FileStoreResult<int>.Fail(NtStatus.InvalidParameter);
		}

		lock (_adsLock)
		{
			if (!_streams.TryGetValue(key, out var value))
			{
				return FileStoreResult<int>.Fail(NtStatus.FileClosed);
			}

			var num = offset + data.Length;
			if (num > value.Content.Length)
			{
				var array = new byte[num];
				value.Content.CopyTo(array, 0);
				value.Content = array;
			}

			data.CopyTo(value.Content.AsSpan((int)offset));
			return FileStoreResult<int>.Ok(data.Length);
		}
	}

	internal NtStatus StreamSetLength(string key, long length)
	{
		if (_readOnly)
		{
			return NtStatus.AccessDenied;
		}

		if (length < 0)
		{
			return NtStatus.InvalidParameter;
		}

		lock (_adsLock)
		{
			if (!_streams.TryGetValue(key, out var value))
			{
				return NtStatus.FileClosed;
			}

			var array = new byte[length];
			Array.Copy(value.Content, array, Math.Min(value.Content.Length, length));
			value.Content = array;
			return NtStatus.Success;
		}
	}

	internal long StreamLength(string key)
	{
		lock (_adsLock)
		{
			return _streams.TryGetValue(key, out var value) ? value.Content.Length : 0;
		}
	}

	internal void StreamRemove(string fullBase, string streamName)
	{
		lock (_adsLock)
		{
			_streams.Remove(StreamKey(fullBase, streamName));
		}
	}

	public ValueTask<FileStoreResult<IReadOnlyList<ExtendedAttribute>>> GetExtendedAttributesAsync(IFileHandle handle, CancellationToken cancellationToken = default(CancellationToken))
	{
		var key = EaKey(handle);
		lock (_adsLock)
		{
			if (_eas.TryGetValue(key, out var value))
			{
				return new ValueTask<FileStoreResult<IReadOnlyList<ExtendedAttribute>>>(FileStoreResult<IReadOnlyList<ExtendedAttribute>>.Ok(value.ToArray()));
			}
		}

		return new ValueTask<FileStoreResult<IReadOnlyList<ExtendedAttribute>>>(FileStoreResult<IReadOnlyList<ExtendedAttribute>>.Ok(Array.Empty<ExtendedAttribute>()));
	}

	public ValueTask<NtStatus> SetExtendedAttributesAsync(IFileHandle handle, IReadOnlyList<ExtendedAttribute> entries, CancellationToken cancellationToken = default(CancellationToken))
	{
		if (_readOnly)
		{
			return new ValueTask<NtStatus>(NtStatus.AccessDenied);
		}

		var key = EaKey(handle);
		lock (_adsLock)
		{
			if (!_eas.TryGetValue(key, out var value))
			{
				value = (_eas[key] = new List<ExtendedAttribute>());
			}

			foreach (var e in entries)
			{
				value.RemoveAll(x => string.Equals(x.Name, e.Name, StringComparison.OrdinalIgnoreCase));
				var value2 = e.Value;
				if (value2 != null && value2.Length > 0)
				{
					value.Add(e);
				}
			}

			if (value.Count == 0)
			{
				_eas.Remove(key);
			}
		}

		return new ValueTask<NtStatus>(NtStatus.Success);
	}

	private static string EaKey(IFileHandle handle) => handle.Identity!.Value.ObjectId;

	private static SecurityDescriptor DefaultDescriptor()
	{
		var dacl = new Acl
		{
			Aces = [Ace.Allow(WellKnownSids.Everyone, 2032127u)],
		};
		return SecurityDescriptor.Create(WellKnownSids.LocalSystem, WellKnownSids.BuiltinUsers, dacl);
	}

	private bool TryResolve(string? relative, out string fullPath)
	{
		fullPath = _root;
		var text = (relative ?? string.Empty).Replace('\\', Path.DirectorySeparatorChar).TrimStart(Path.DirectorySeparatorChar);
		if (text.IndexOfAny(Path.GetInvalidPathChars()) >= 0)
		{
			return false;
		}

		string fullPath2;
		try
		{
			fullPath2 = Path.GetFullPath(Path.Combine(_root, text));
		}
		catch (Exception ex) when (ex is ArgumentException || ex is PathTooLongException || ex is NotSupportedException)
		{
			return false;
		}

		var value = _root.EndsWith(Path.DirectorySeparatorChar) ? _root : _root + Path.DirectorySeparatorChar;
		if (fullPath2 != _root && !fullPath2.StartsWith(value, StringComparison.OrdinalIgnoreCase))
		{
			return false;
		}

		if (!IsWithinRealRoot(fullPath2))
		{
			return false;
		}

		fullPath = fullPath2;
		return true;
	}

	private bool IsWithinRealRoot(string candidate)
	{
		var text = TryResolveRealPath(candidate);
		if (text == null)
		{
			return false;
		}

		if (string.Equals(text, _realRoot, StringComparison.OrdinalIgnoreCase))
		{
			return true;
		}

		var value = (_realRoot.EndsWith(Path.DirectorySeparatorChar) ? _realRoot : (_realRoot + Path.DirectorySeparatorChar));
		return text.StartsWith(value, StringComparison.OrdinalIgnoreCase);
	}

	private static string? TryResolveRealPath(string path)
	{
		try
		{
			var fullPath = Path.GetFullPath(path);
			var text = Path.GetPathRoot(fullPath) ?? string.Empty;
			if (string.IsNullOrEmpty(text))
			{
				return fullPath;
			}

			var text2 = text;
			var array = fullPath.Substring(text.Length).Split([
				Path.DirectorySeparatorChar,
				Path.AltDirectorySeparatorChar,
			], StringSplitOptions.RemoveEmptyEntries);

			foreach (var path2 in array)
			{
				text2 = Path.Combine(text2, path2);
				FileSystemInfo fileSystemInfo;
				if (Directory.Exists(text2))
				{
					fileSystemInfo = new DirectoryInfo(text2);
				}
				else
				{
					fileSystemInfo = File.Exists(text2) ? new FileInfo(text2) : null;
				}

				if (fileSystemInfo != null)
				{
					var fileSystemInfo2 = fileSystemInfo.ResolveLinkTarget(returnFinalTarget: true);
					if (fileSystemInfo2 != null)
					{
						text2 = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(text2) ?? text2, fileSystemInfo2.FullName));
					}
				}
			}

			return Path.GetFullPath(text2);
		}
		catch
		{
			return null;
		}
	}

	private static FileEntryInfo ToEntry(FileSystemInfo info, string name)
	{
		var flag = (info.Attributes & FileAttributes.Directory) != 0;
		var num = (flag ? 0 : ((FileInfo)info).Length);
		return new FileEntryInfo
		{
			Name = name,
			Attributes = MapAttributes(info.Attributes),
			EndOfFile = num,
			AllocationSize = (flag ? 0 : AlignUp(num, 4096L)),
			CreationTime = SafeFileTime(info.CreationTimeUtc),
			LastAccessTime = SafeFileTime(info.LastAccessTimeUtc),
			LastWriteTime = SafeFileTime(info.LastWriteTimeUtc),
			ChangeTime = SafeFileTime(info.LastWriteTimeUtc),
			IndexNumber = LocalIdentity.IndexNumber(LocalIdentity.Resolve(info.FullName) ?? throw new FileNotFoundException("Directory entry disappeared", info.FullName)),
		};
	}

	internal static SmbFileAttributes MapAttributes(FileAttributes a)
	{
		var smbFileAttributes = SmbFileAttributes.None;
		if ((a & FileAttributes.Directory) != 0)
		{
			smbFileAttributes |= SmbFileAttributes.Directory;
		}

		if ((a & FileAttributes.ReadOnly) != 0)
		{
			smbFileAttributes |= SmbFileAttributes.ReadOnly;
		}

		if ((a & FileAttributes.Hidden) != 0)
		{
			smbFileAttributes |= SmbFileAttributes.Hidden;
		}

		if ((a & FileAttributes.System) != 0)
		{
			smbFileAttributes |= SmbFileAttributes.System;
		}

		if ((a & FileAttributes.Archive) != 0)
		{
			smbFileAttributes |= SmbFileAttributes.Archive;
		}

		if (smbFileAttributes == SmbFileAttributes.None)
		{
			smbFileAttributes = SmbFileAttributes.Normal;
		}

		return smbFileAttributes;
	}

	private static long SafeFileTime(DateTime utc)
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

	private static long AlignUp(long value, long alignment)
	{
		return (value + alignment - 1) / alignment * alignment;
	}
}
