using System;
using System.Collections.Generic;

namespace Smb.Server.Recovery;

/// <summary>Optional, exclusively owned, transactional journal. Calls must be durable
/// before returning. Snapshot replacement and ID allocation must be atomic. Implementations
/// must reject concurrent owners. The caller owns its lifetime. No authentication keys.</summary>
public interface IServerRecoveryStore
{
    Guid ServerGuid { get; }
    ulong AllocateId(RecoveryIdKind kind);
    void SaveSession(RecoverySessionRecord session);
    void RetireSession(ulong sessionId);
    void SaveHandle(RecoveryHandleRecord handle);
    void RemoveHandle(ulong persistentId);
    IReadOnlyList<RecoveryHandleRecord> LoadHandles();
}

public enum RecoveryIdKind { Session, PersistentHandle }
public sealed record RecoverySessionRecord(ulong SessionId, Guid ClientGuid, string OwnerKey, DateTimeOffset AuthenticatedAt);
public sealed record RecoveryLock(ulong Offset, ulong Length, bool Exclusive);

public sealed record RecoveryHandleRecord
{
    public int Version { get; init; } = 1;
    public required ulong PersistentId { get; init; }
    public required ulong VolatileId { get; init; }
    public required ulong SessionId { get; init; }
    public required string OwnerKey { get; init; }
    public required Guid ClientGuid { get; init; }
    public required Guid CreateGuid { get; init; }
    public required Guid Token { get; init; }
    public required string ShareName { get; init; }
    public required string BackendIdentity { get; init; }
    public required string ObjectId { get; init; }
    public string StreamId { get; init; } = "";
    public required string Path { get; init; }
    public uint GrantedAccess { get; init; }
    public uint ShareAccess { get; init; }
    public bool ReplayEligible { get; init; }
    public uint OriginalCreateAction { get; init; }
    public uint CreateOptions { get; init; }
    public bool IsV2 { get; init; }
    public bool LeaseV2 { get; init; }
    public byte Oplock { get; init; }
    public uint LeaseState { get; init; }
    public byte[] LeaseKey { get; init; } = new byte[16];
    public byte[] ParentLeaseKey { get; init; } = new byte[16];
    public ushort LeaseEpoch { get; init; }
    public long TimeoutTicks { get; init; }
    public DateTimeOffset? Deadline { get; init; }
    public ushort ChannelSequence { get; init; }
    public byte[] LockSequences { get; init; } = new byte[64];
    public RecoveryLock[] Locks { get; init; } = [];
    public long CurrentByteOffset { get; init; }
    public bool SuppressWriteTime { get; init; }
}
