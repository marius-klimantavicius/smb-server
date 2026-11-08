using System;
using Smb.FileSystem;

namespace Smb.Server.State;

public sealed class SmbTreeConnect
{
	public int OpenCount;

	public OpenLifetime Lifetime { get; } = new OpenLifetime();

	public required ulong TreeId { get; init; }

	public required SmbSession Session { get; init; }

	public required IShare Share { get; init; }

	public uint MaximalAccess { get; set; }

	public bool EncryptData { get; set; }

	public DateTimeOffset CreationTime { get; } = DateTimeOffset.UtcNow;
}
