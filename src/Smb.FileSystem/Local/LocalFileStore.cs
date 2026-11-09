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

public sealed partial class LocalFileStore : SyncFileStore, IFileStore, INamedStreamStore, IExtendedAttributeStore, IBasicInfoStore, ISharedDeleteFileStore, IDirectoryCursorStore, IVolumeInfoProvider, ICacheCoherentFileStore, ICreateMetadataStore, IAuthorizedCreateStore, IFileNamespaceStore, IStreamRenameStore
{
	internal sealed class StreamData
	{
		public required string Name;
		public readonly string Identity = Guid.NewGuid().ToString("N");

		public byte[] Content = Array.Empty<byte>();
		public int Opens;
		public bool DeletePending;
	}

	internal string RootPath => _root;
	private readonly string _root;

	private readonly string _realRoot;

	private readonly bool _readOnly;

	private readonly ISecurityDescriptorStore _securityStore;

	private static readonly Lock _adsLock = new Lock();

	private readonly StreamTable _streams = new StreamTable();

	private readonly Dictionary<string, List<ExtendedAttribute>> _eas = new Dictionary<string, List<ExtendedAttribute>>(StringComparer.Ordinal);

	private readonly Dictionary<FileIdentity, long> _creationTimes = new Dictionary<FileIdentity, long>();

	private readonly Dictionary<FileIdentity, uint> _dosAttributes = new Dictionary<FileIdentity, uint>();

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
		if (identity is { } baseIdentity)
			lock (_adsLock)
				if (_streams.TryGetValue(StreamKey(full, streamName), out var stream))
					return new ValueTask<FileIdentity?>(baseIdentity with { StreamId = stream.Identity });
		return new ValueTask<FileIdentity?>(identity is { } id ? id with { StreamId = streamName.ToUpperInvariant() } : null);
	}

	public ValueTask<FileStoreResult<FileCreateResult>> CreateAuthorizedAsync(string path, string streamName, FileAccessIntent access, CreateDispositionIntent disposition, bool directoryRequired, bool nonDirectoryRequired, uint attributes, Func<SecurityDescriptor, bool> authorizeExisting, Func<SecurityDescriptor, bool, bool> authorizeParent, Func<FileIdentity?, bool> validateIdentity, CancellationToken cancellationToken = default)
		=> CreateAuthorizedAsync(path, streamName, access, disposition, directoryRequired, nonDirectoryRequired, attributes,
			(descriptor, _) => authorizeExisting(descriptor) ? access : null, authorizeParent, validateIdentity, cancellationToken);

	public ValueTask<FileStoreResult<FileCreateResult>> CreateAuthorizedAsync(string path, string streamName, FileAccessIntent access, CreateDispositionIntent disposition, bool directoryRequired, bool nonDirectoryRequired, uint attributes, Func<SecurityDescriptor, uint, FileAccessIntent?> authorizeExisting, Func<SecurityDescriptor, bool, bool> authorizeParent, Func<FileIdentity?, bool> validateIdentity, CancellationToken cancellationToken = default)
	{
		lock (LocalObjects.Gate)
		{
			cancellationToken.ThrowIfCancellationRequested();
			if (!TryResolve(path, out var full)) return new(FileStoreResult<FileCreateResult>.Fail(NtStatus.ObjectNameNotFound));
			if (!validateIdentity(ResolveIdentityAsync(path, streamName, cancellationToken).Result))
				return new(FileStoreResult<FileCreateResult>.Fail(NtStatus.Retry));
			if (LocalIdentity.Resolve(full) is { } identity)
			{
				// CREATE on an existing ordinary object cannot acquire it at all.
				if (streamName.Length == 0 && disposition == CreateDispositionIntent.Create)
					return new(FileStoreResult<FileCreateResult>.Fail(NtStatus.ObjectNameCollision));
				var supportedAccess = AccessMask.FileAllAccess;
				if (_readOnly)
					supportedAccess &= ~(AccessMask.FileWriteData | AccessMask.FileAppendData | AccessMask.FileWriteEa |
						AccessMask.FileDeleteChild | AccessMask.FileWriteAttributes | AccessMask.Delete | AccessMask.WriteDac | AccessMask.WriteOwner);
				var native = File.GetAttributes(full);
				if ((native & FileAttributes.Directory) == 0 && GetAttributes(identity, native).HasFlag(SmbFileAttributes.ReadOnly))
					supportedAccess &= ~(AccessMask.FileWriteData | AccessMask.FileAppendData | AccessMask.FileDeleteChild);
				var finalAccess = authorizeExisting(StoredSecurity(identity, full) ?? DefaultDescriptor(), supportedAccess);
				if (!finalAccess.HasValue)
					return new(FileStoreResult<FileCreateResult>.Fail(NtStatus.AccessDenied));
				access = finalAccess.Value;
			}
			else if (disposition is not (CreateDispositionIntent.Open or CreateDispositionIntent.Overwrite))
			{
				var parent = Path.GetDirectoryName(full);
				if (parent == null || !Directory.Exists(parent) || LocalIdentity.Resolve(parent) is not { } parentIdentity)
					return new(FileStoreResult<FileCreateResult>.Fail(NtStatus.ObjectPathNotFound));
				if (!authorizeParent(StoredSecurity(parentIdentity, parent) ?? DefaultDescriptor(), directoryRequired))
					return new(FileStoreResult<FileCreateResult>.Fail(NtStatus.AccessDenied));
			}
			// The same gate covers SET_SECURITY, rename, retirement and acquisition.
			// No descriptor/identity snapshot survives an await or cache-break wait.
			cancellationToken.ThrowIfCancellationRequested();
			return streamName.Length == 0
				? CreateWithMetadataAsync(path, access, disposition, directoryRequired, nonDirectoryRequired, attributes, cancellationToken)
				: OpenNamedStreamCore(path, streamName, access, disposition, cancellationToken);
		}
	}

	public ValueTask<FileStoreResult<FileCreateResult>> CreateWithMetadataAsync(string path, FileAccessIntent access, CreateDispositionIntent disposition, bool directoryRequired, bool nonDirectoryRequired, uint attributes, CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		lock (LocalObjects.Gate)
		{
			if (directoryRequired && (attributes & 0x100u) != 0)
				return new(FileStoreResult<FileCreateResult>.Fail(NtStatus.InvalidParameter));
			if (disposition is CreateDispositionIntent.Overwrite or CreateDispositionIntent.OverwriteIf or CreateDispositionIntent.Supersede &&
				TryResolve(path, out var full) && LocalIdentity.Resolve(full) is { } identity)
			{
				var existing = (uint)GetAttributes(identity, File.GetAttributes(full));
				if ((existing & 6u & ~attributes) != 0)
					return new(FileStoreResult<FileCreateResult>.Fail(NtStatus.AccessDenied));
			}
			if (!directoryRequired && TryResolve(path, out var overlayPath) && HasDefaultStream(overlayPath))
                return OpenNamedStreamCore(path, "", access, disposition, cancellationToken);
            var result = CreateCore(path, access, disposition, directoryRequired, nonDirectoryRequired, out var action);
			if (!result.IsSuccess) return new(FileStoreResult<FileCreateResult>.Fail(result.Status));

			if (action is CreateOutcome.Created or CreateOutcome.Overwritten or CreateOutcome.Superseded)
			{
				var handle = (LocalFileHandle)result.Value;
				var status = SetBasicInfoAsync(handle, new FileBasicInfoUpdate { Attributes = (attributes & SettableAttributes) | (handle.IsDirectory ? 0u : 0x20u) }).Result;
				if (status != NtStatus.Success) { handle.Dispose(); return new(FileStoreResult<FileCreateResult>.Fail(status)); }
				if (!handle.IsDirectory) RemoveStreams(handle.Identity!.Value);
			}
			return new(FileStoreResult<FileCreateResult>.Ok(new FileCreateResult(result.Value, action)));
		}
	}

	internal long CreationTime(FileIdentity identity, long native)
	{
		if (OperatingSystem.IsWindows()) return native;
		lock (_adsLock)
		{
			if (_creationTimes.TryGetValue(identity, out var value)) return value;
			_creationTimes.Add(identity, native);
			return native;
		}
	}

	internal SmbFileAttributes GetAttributes(FileIdentity identity, FileAttributes native)
	{
		lock (_adsLock)
		{
			if (!OperatingSystem.IsWindows() && _dosAttributes.TryGetValue(identity with { StreamId = "" }, out var attributes))
			{
				// Native READONLY remains authoritative on data files; directories need a DOS flag.
				var mask = (native & FileAttributes.Directory) != 0 ? SettableAttributes : SettableAttributes & ~1u;
				native = (FileAttributes)(((uint)native & ~mask) | (attributes & mask));
			}
		}
		return MapAttributes(native);
	}

	private void MarkArchive(FileIdentity identity, Microsoft.Win32.SafeHandles.SafeFileHandle native)
	{
		lock (LocalObjects.Gate)
		{
			using var metadata = OperatingSystem.IsWindows() ? WindowsLocalIdentity.OpenMetadata(native) : null;
			var target = metadata ?? native;
			lock (_adsLock)
			{
				var attributes = (uint)GetAttributes(identity, File.GetAttributes(target));
				if (OperatingSystem.IsWindows())
				{
					if ((attributes & 0x20u) == 0) File.SetAttributes(target, (FileAttributes)((attributes | 0x20u) & SettableAttributes));
				}
				else _dosAttributes[identity with { StreamId = "" }] = (attributes | 0x20u) & SettableAttributes;
			}
		}
	}

	private void MarkArchive(IFileHandle handle)
	{
		var local = handle is NamedStreamHandle stream ? stream.BaseHandle : (LocalFileHandle)handle;
		MarkArchive(local.Identity!.Value, local.NativeHandle);
	}

	private void MarkParentArchive(string childPath)
	{
		var parent = Path.GetDirectoryName(childPath);
		if (parent == null) return;
		using var native = LocalIdentity.OpenDirectory(parent);
		if (LocalIdentity.Resolve(parent, native) is { } identity) MarkArchive(identity, native);
	}

	internal void RetireMetadata(FileIdentity identity)
	{
		_securityStore.Remove(SecurityKey(identity));
		lock (_adsLock) { _dosAttributes.Remove(identity with { StreamId = "" }); _creationTimes.Remove(identity with { StreamId = "" }); }
		RemoveStreams(identity);
	}

	private void RemoveStreams(FileIdentity identity)
	{
		lock (_adsLock)
		{
			var prefix = identity.ObjectId + "\0";
			_streams.Observe(prefix);
			foreach (var key in new List<string>(_streams.Keys))
				if (key.StartsWith(prefix, StringComparison.Ordinal)) _streams.Remove(key);
		}
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
		if (_readOnly && !flag6 && disposition == CreateDispositionIntent.OpenIf)
			return FileStoreResult<IFileHandle>.Fail(NtStatus.AccessDenied);
		if (flag6 && disposition == CreateDispositionIntent.Create)
			return FileStoreResult<IFileHandle>.Fail(NtStatus.ObjectNameCollision);
		if (!flag6 && directoryRequired && !Directory.Exists(Path.GetDirectoryName(fullPath)))
			return FileStoreResult<IFileHandle>.Fail(NtStatus.ObjectPathNotFound);
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
				ApplyInheritedSecurity((LocalFileHandle)result.Value);
				MarkParentArchive(fullPath);
			}

			return result;
		}

		var result2 = CreateFileHandle(fullPath, relative, access, disposition, flag6, out createAction);
		if (result2.IsSuccess && createAction == CreateOutcome.Created)
		{
			ApplyInheritedSecurity((LocalFileHandle)result2.Value);
			MarkParentArchive(fullPath);
		}

		return result2;
	}

	private static string SecurityKey(FileIdentity identity) => "local-security:" + (identity with { StreamId = "" }).Key;

	// Path keys were used by earlier versions, including injected stores. Adopt a
	// legacy entry only while that path still names this acquired object, then remove
	// it so a recycled name cannot import the old policy. The supplied store remains
	// the authority; there is no private descriptor cache shadowing it.
	private SecurityDescriptor? StoredSecurity(FileIdentity identity, string path)
	{
		var key = SecurityKey(identity);
		var descriptor = _securityStore.TryGet(key);
		if (descriptor == null && LocalIdentity.Resolve(path) == identity)
		{
			descriptor = _securityStore.TryGet(path);
			if (descriptor != null)
			{
				_securityStore.Set(key, descriptor);
				_securityStore.Remove(path);
			}
		}
		return descriptor;
	}

	private void ApplyInheritedSecurity(LocalFileHandle child)
	{
		var childFull = child.FullPath;
		// A newly created object can reuse a native ID as well as a pathname.
		_securityStore.Remove(SecurityKey(child.Identity!.Value));
		_securityStore.Remove(childFull);
		var directoryName = Path.GetDirectoryName(childFull);
		if (directoryName == null)
		{
			return;
		}

		var parentIdentity = LocalIdentity.Resolve(directoryName);
		var securityDescriptor = parentIdentity is { } id ? StoredSecurity(id, directoryName) : null;
		if (securityDescriptor != null)
		{
			var securityDescriptor2 = AclInheritance.ComputeInherited(securityDescriptor, child.IsDirectory);
			if (securityDescriptor2 != null)
			{
				_securityStore.Set(SecurityKey(child.Identity.Value), securityDescriptor2);
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

		return FileStoreResult<IFileHandle>.Ok(new LocalFileHandle(this, full, relative, _root, null, isDirectory: true));
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
			CreateDispositionIntent.OpenIf => exists ? FileMode.Open : FileMode.OpenOrCreate,
			CreateDispositionIntent.Overwrite => FileMode.Truncate,
			CreateDispositionIntent.OverwriteIf => FileMode.Create,
			CreateDispositionIntent.Supersede => FileMode.Create,
			_ => FileMode.Open,
		};
		var access2 = (((!access.HasFlag(FileAccessIntent.Write) && (disposition == CreateDispositionIntent.Open || disposition == CreateDispositionIntent.OpenIf && exists)) || _readOnly) ? FileAccess.Read : FileAccess.ReadWrite);
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
			return FileStoreResult<IFileHandle>.Ok(new LocalFileHandle(this, full, relative, _root, stream, isDirectory: false));
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
		catch (PathTooLongException)
		{
			return FileStoreResult<IFileHandle>.Fail(NtStatus.ObjectNameInvalid);
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
			return StreamRead(namedStreamHandle.Data, offset, buffer);
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
			return StreamRead(namedStreamHandle.Data, offset, buffer.Span);
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
			return StreamWrite(namedStreamHandle.Data, offset, data);
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
			var streamResult = StreamWrite(namedStreamHandle.Data, offset, data.Span);
			if (streamResult.IsSuccess && streamResult.Value > 0) MarkArchive(handle);
			return streamResult;
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

		var result = await localFileHandle.WriteAtAsync(offset, data, cancellationToken).ConfigureAwait(false);
		if (result.IsSuccess && result.Value > 0) MarkArchive(handle);
		return result;
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

		return new ValueTask<FileStoreResult<IDirectoryCursor>>(FileStoreResult<IDirectoryCursor>.Ok(new LocalDirectoryCursor(this, EnumerateDirectoryEntries(local).GetEnumerator(), DirectoryPattern(pattern))));
	}

	private IEnumerable<(FileSystemInfo Info, string Name)> EnumerateDirectoryEntries(LocalFileHandle local)
	{
		var directory = new DirectoryInfo(local.FullPath);
		yield return (directory, ".");

		if (directory.FullName != _root) yield return (directory.Parent ?? directory, "..");

		// Enumerate all names; SMB expression semantics must not depend on host globbing.
		foreach (var entry in directory.EnumerateFileSystemInfos("*", new EnumerationOptions { AttributesToSkip = 0 }))
			yield return (entry, entry.Name);
	}

	private static string DirectoryPattern(string pattern) => string.IsNullOrEmpty(pattern) || pattern == "*.*" ? "*" : pattern;

	private static bool MatchesDirectoryPattern(string pattern, string name)
		// Raw SMB expressions retain '?' and DOS wildcards; do not translate Win32 syntax.
		=> System.IO.Enumeration.FileSystemName.MatchesWin32Expression(pattern, name, OperatingSystem.IsWindows());

	private sealed class LocalDirectoryCursor(LocalFileStore store, IEnumerator<(FileSystemInfo Info, string Name)> entries, string pattern) : IDirectoryCursor
	{
		bool ended;

		public ValueTask<FileStoreResult<BoundedDirectoryListing>> ReadAsync(int maxEntries, CancellationToken cancellationToken = default)
		{
			var batch = new List<FileEntryInfo>();
			while (!ended && batch.Count < Math.Max(1, maxEntries))
			{
				cancellationToken.ThrowIfCancellationRequested();
				if (entries.MoveNext())
				{
					var (info, name) = entries.Current;
					if (MatchesDirectoryPattern(pattern, name) && store.TryDirectoryEntry(info, name) is { } entry) batch.Add(entry);
				}
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

		var searchPattern2 = DirectoryPattern(searchPattern);
		var list = new List<FileEntryInfo>();

		try
		{
			foreach (var (info, name) in EnumerateDirectoryEntries(localFileHandle))
			{
				if (MatchesDirectoryPattern(searchPattern2, name) && TryDirectoryEntry(info, name) is { } entry) list.Add(entry);
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

		var searchPattern2 = DirectoryPattern(searchPattern);
		var list = new List<FileEntryInfo>();

		var truncated = false;
		try
		{
			foreach (var (info, name) in EnumerateDirectoryEntries(localFileHandle))
			{
				if (!MatchesDirectoryPattern(searchPattern2, name)) continue;

				if (maxEntries > 0 && list.Count >= maxEntries)
				{
					truncated = true;
					break;
				}

				if (TryDirectoryEntry(info, name) is { } entry) list.Add(entry);
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

		var status = handle is NamedStreamHandle namedStreamHandle
			? StreamSetLength(namedStreamHandle.Data, length)
			: ((LocalFileHandle)handle).SetLength(length);
		if (status == NtStatus.Success) MarkArchive(handle);
		return status;
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

		if (handle is NamedStreamHandle named)
		{
            if (newPath.StartsWith(':')) return RenameStreamAsync(handle, newPath, replaceIfExists).Result;
            return named.IsDefaultStream ? RenameCore(named.BaseHandle, newPath, replaceIfExists) : NtStatus.SharingViolation;
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
			var retireDestination = destinationId != null && destinationId != localFileHandle.Identity &&
				(Directory.Exists(fullPath) || LocalIdentity.LinkCount(fullPath) == 1);
			if (destinationId is { } replaced && destinationId != localFileHandle.Identity)
				_ = StoredSecurity(replaced, fullPath);

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
			_securityStore.Remove(fullPath);
			if (retireDestination) RetireMetadata(destinationId!.Value);

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
		// Serialize DOS restriction changes with guarded CREATE grant selection.
		// Take this gate before the per-object mutation gate, as CREATE does.
		if (update.Attributes.HasValue)
			lock (LocalObjects.Gate) return SetBasicInfoCore(handle, update, cancellationToken);
		return SetBasicInfoCore(handle, update, cancellationToken);
	}

	private ValueTask<NtStatus> SetBasicInfoCore(IFileHandle handle, FileBasicInfoUpdate update, CancellationToken cancellationToken)
	{
		if (update.ChangeTime.HasValue) return new ValueTask<NtStatus>(NtStatus.NotSupported);

		if (_readOnly)
		{
			return new ValueTask<NtStatus>(NtStatus.AccessDenied);
		}

		var local = handle is NamedStreamHandle namedStreamHandle ? namedStreamHandle.BaseHandle : (LocalFileHandle)handle;
		if (local.IsDirectory && (update.Attributes.GetValueOrDefault() & 0x100u) != 0) return new(NtStatus.InvalidParameter);
		local.MutationGate.Wait(cancellationToken);
		try
		{
			using var metadata = OperatingSystem.IsWindows() ? WindowsLocalIdentity.OpenMetadata(local.NativeHandle) : null;
			var native = metadata ?? local.NativeHandle;
			var creationTime = update.CreationTime;
			if (creationTime.HasValue)
			{
				var valueOrDefault = creationTime.GetValueOrDefault();
				File.SetCreationTimeUtc(native, DateTime.FromFileTimeUtc(valueOrDefault));
				if (!OperatingSystem.IsWindows()) lock (_adsLock) _creationTimes[local.Identity!.Value] = valueOrDefault;
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
				if (!OperatingSystem.IsWindows())
					lock (_adsLock) _dosAttributes[local.Identity!.Value] = valueOrDefault4 & SettableAttributes;
			}

			if (update.SuppressLastWriteTimeUpdates is { } suppress) local.SuppressLastWriteTimeUpdates = suppress;

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
		finally { local.MutationGate.Release(); }
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
		cancellationToken.ThrowIfCancellationRequested();
		lock (LocalObjects.Gate)
		{
			var local = handle is NamedStreamHandle stream ? stream.BaseHandle : (LocalFileHandle)handle;
			return new(FileStoreResult<SecurityDescriptor>.Ok(StoredSecurity(local.Identity!.Value, local.FullPath) ?? DefaultDescriptor()));
		}
	}

	public override ValueTask<NtStatus> SetSecurityAsync(IFileHandle handle, SecurityDescriptor descriptor, CancellationToken cancellationToken = default(CancellationToken))
	{
		if (_readOnly)
		{
			return new ValueTask<NtStatus>(NtStatus.AccessDenied);
		}

		cancellationToken.ThrowIfCancellationRequested();
		lock (LocalObjects.Gate)
		{
			// Only the existing basic discretionary ACL profile is enforced. Never
			// acknowledge an object/callback/claims ACE that access checks would ignore.
			if (descriptor.Dacl is { } dacl)
				foreach (var ace in dacl.Aces)
					if (ace.Type is not (AceType.AccessAllowed or AceType.AccessDenied) ||
						((ace.Flags & (AceFlags.ObjectInherit | AceFlags.ContainerInherit)) != 0 &&
						 (ace.Sid == WellKnownSids.CreatorOwner || ace.Sid == WellKnownSids.CreatorGroup)))
						return new(NtStatus.NotSupported);

			var local = handle is NamedStreamHandle stream ? stream.BaseHandle : (LocalFileHandle)handle;
			_securityStore.Set(SecurityKey(local.Identity!.Value), MapSecurity(descriptor));
			return new(NtStatus.Success);
		}
	}

	private static SecurityDescriptor MapSecurity(SecurityDescriptor descriptor)
	{
		if (descriptor.Dacl == null) return descriptor;

		var aces = new List<Ace>();
		foreach (var ace in descriptor.Dacl.Aces)
			aces.Add(new Ace { Type = ace.Type, Flags = ace.Flags, Sid = ace.Sid, AccessMask = AccessMask.MapGenericToSpecific(ace.AccessMask) });
		return SecurityDescriptor.Create(descriptor.Owner, descriptor.Group, new Acl { Aces = aces }, descriptor.Sacl, descriptor.Control);
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
			if (disposition is CreateDispositionIntent.Open or CreateDispositionIntent.Overwrite) return Fail(NtStatus.ObjectNameNotFound);
			if (_readOnly) return Fail(NtStatus.AccessDenied);
			var created = CreateCore(basePath, access, CreateDispositionIntent.OpenIf, false, true, out var baseAction);
			if (!created.IsSuccess) return Fail(created.Status);
			using var baseHandle = created.Value;
			if (baseAction == CreateOutcome.Created) RemoveStreams(baseHandle.Identity!.Value);
			var status = SetBasicInfoAsync(baseHandle, new FileBasicInfoUpdate { Attributes = 0x20u }).Result;
			if (status != NtStatus.Success) return Fail(status);
		}

		var baseId = LocalIdentity.Resolve(fullPath)!.Value;
		if (LocalObjects.Objects.TryGetValue(baseId, out var baseObject) && baseObject.DeletePending) return Fail((NtStatus)0xc0000056);

		var key = StreamKey(fullPath, streamName);
		CreateOutcome action;
		lock (_adsLock)
		{
			var flag4 = _streams.ContainsKey(key);
			if (_readOnly && !flag4) return Fail(NtStatus.AccessDenied);
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

		lock (_adsLock) { _streams.Pin(key, fullPath); _streams[key].Opens++; }
		try { return new ValueTask<FileStoreResult<FileCreateResult>>(FileStoreResult<FileCreateResult>.Ok(new FileCreateResult(new NamedStreamHandle(this, fullPath, streamName), action))); }
		catch
		{
			CloseStream(_streams[key]);
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
			if (!HasDefaultStream(text)) list.Add(new StreamInfo(string.Empty, length, AlignUp(length, 4096L)));
		}

		var value = handle.Identity!.Value.ObjectId + "\0";
		lock (_adsLock) _streams.Observe(value);
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

	internal StreamData GetStreamData(string full, string name) { lock (_adsLock) return _streams[StreamKey(full, name)]; }

	private NtStatus SetStreamDelete(NamedStreamHandle handle, bool delete)
	{
        lock (LocalObjects.Gate)
        lock (_adsLock)
        {
            if (handle.IsClosed) return NtStatus.FileClosed;
            if (handle.IsDefaultStream) return handle.BaseHandle.SetDeleteOnClose(delete);

			var data = handle.Data;

			data.DeletePending = delete;
			return NtStatus.Success;
		}
	}

	internal void CloseStream(StreamData data)
	{
		lock (_adsLock)
		{
			if (--data.Opens == 0 && data.DeletePending)
				foreach (var key in new List<string>(_streams.Keys))
					if (ReferenceEquals(_streams[key], data)) _streams.Remove(key);
		}
	}

	internal FileStoreResult<int> StreamRead(StreamData value, long offset, Span<byte> buffer)
	{
		lock (_adsLock)
		{
			if (offset < 0 || offset >= value.Content.Length)
			{
				return FileStoreResult<int>.Ok(0);
			}

			var num = (int)Math.Min(buffer.Length, value.Content.Length - offset);
			value.Content.AsSpan((int)offset, num).CopyTo(buffer);
			return FileStoreResult<int>.Ok(num);
		}
	}

	internal FileStoreResult<int> StreamWrite(StreamData value, long offset, ReadOnlySpan<byte> data)
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

	internal NtStatus StreamSetLength(StreamData value, long length)
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
			var array = new byte[length];
			Array.Copy(value.Content, array, Math.Min(value.Content.Length, length));
			value.Content = array;
			return NtStatus.Success;
		}
	}

	internal long StreamLength(StreamData value)
	{
		lock (_adsLock)
		{
			return value.Content.Length;
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

	private FileEntryInfo? TryDirectoryEntry(FileSystemInfo info, string name)
	{
		// Only a vanished child is omitted. Root scans and access/I/O errors still fail.
		try { return ToEntry(info, name); }
		catch (FileNotFoundException) when (name is not ("." or "..")) { return null; }
		catch (DirectoryNotFoundException) when (name is not ("." or "..")) { return null; }
	}

	private FileEntryInfo ToEntry(FileSystemInfo info, string name)
	{
		var flag = (info.Attributes & FileAttributes.Directory) != 0;
		var num = (flag ? 0 : ((FileInfo)info).Length);
		return new FileEntryInfo
		{
			Name = name,
			Attributes = GetAttributes(LocalIdentity.Resolve(info.FullName) ?? throw new FileNotFoundException("Directory entry disappeared", info.FullName), info.Attributes),
			EndOfFile = num,
			AllocationSize = (flag ? 0 : AlignUp(num, 4096L)),
			CreationTime = CreationTime(LocalIdentity.Resolve(info.FullName) ?? throw new FileNotFoundException("Directory entry disappeared", info.FullName), SafeFileTime(info.CreationTimeUtc)),
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
