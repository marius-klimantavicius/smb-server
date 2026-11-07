using System;
using System.Collections.Generic;
using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server.Rpc;

namespace Smb.Server.State;

public sealed class SmbOpen
{
	public ulong PersistentFileId { get; set; }

	public required ulong VolatileFileId { get; init; }

	public SmbSession? Session { get; set; }

	public SmbTreeConnect? TreeConnect { get; set; }

	public IFileHandle? LocalOpen { get; set; }

	public bool IsDurable { get; set; }

	public TimeSpan DurableTimeout { get; set; }

	public Guid DurableCreateGuid { get; set; }

	public bool IsPersistentHandle { get; set; }

	public uint GrantedAccess { get; set; }

	public uint ShareAccess { get; set; }

	public SmbFileAttributes FileAttributes { get; set; }

	public string PathName { get; set; } = string.Empty;

	public bool DeleteOnClose { get; set; }

	public OplockLevel OplockLevel { get; set; }

	public LeaseKey LeaseKey { get; set; }

	public LeaseState LeaseState { get; set; }

	public ushort LeaseEpoch { get; set; }

	public LeaseKey ParentLeaseKey { get; set; }

	public IReadOnlyList<FileEntryInfo>? DirectoryListing { get; set; }

	public int DirectoryCursor { get; set; }

	public string? ShareModeKey { get; set; }

	public byte[]? ResumeKey { get; set; }

	public RpcPipe? Pipe { get; set; }

	public bool IsPipe => Pipe != null;

	public (ulong Persistent, ulong Volatile) Key => (Persistent: PersistentFileId, Volatile: VolatileFileId);
}
