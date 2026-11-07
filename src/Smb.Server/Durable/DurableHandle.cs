using System;
using Smb.Server.State;

namespace Smb.Server.Durable;

public sealed class DurableHandle
{
	public required ulong PersistentId { get; init; }

	public required ulong VolatileId { get; init; }

	public required SmbOpen Open { get; init; }

	public required DateTimeOffset Deadline { get; init; }

	public required string OwnerKey { get; init; }

	public Guid CreateGuid { get; init; }

	public bool IsPersistent { get; init; }

	public (ulong Persistent, ulong Volatile) Key => (Persistent: PersistentId, Volatile: VolatileId);
}
