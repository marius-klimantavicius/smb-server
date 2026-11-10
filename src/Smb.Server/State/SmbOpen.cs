using System;
using System.Collections.Generic;
using System.Threading;
using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server.Rpc;

namespace Smb.Server.State;

public sealed class SmbOpen
{
    public LockSequenceState LockSequences { get; } = new LockSequenceState();
    public ChannelSequenceState ChannelSequences { get; init; } = new ChannelSequenceState();
    internal readonly Lock NotificationGate = new Lock();
    internal Notification.DirectoryNotificationState? Notifications;
    internal bool NotificationDirectoryMarkedDeleted;
    public string IdentityKey => ShareModeKey ?? LocalOpen?.Identity?.Key ?? "legacy-conservative";

    internal readonly SemaphoreSlim RecoveryGate = new SemaphoreSlim(1, 1);
    internal Guid? RecoveryToken;
    internal DateTimeOffset? RecoveryDeadline;
    internal ulong RecoverySessionId;
    internal readonly object RecoverySnapshotGate = new();
    public OpenLifetime Lifetime { get; } = new OpenLifetime(false);
    internal FileIdentity? AdmissionIdentity;
    internal long CurrentByteOffset;
    internal bool Counted;
    internal bool MetricCounted;

    public ulong PersistentFileId { get; set; }

    public required ulong VolatileFileId { get; set; }

    public SmbSession? Session { get; set; }

    public SmbTreeConnect? TreeConnect { get; set; }

    public IFileHandle? LocalOpen { get; set; }

    public bool IsDurable { get; set; }
    public bool IsReplayEligible { get; set; }
    internal string? DurableOwnerKey;
    internal ulong CreateSessionId;
    internal CreateAction OriginalCreateAction;
    public bool DurableIsV2 { get; set; }
    public bool DurableLeaseV2 { get; set; }
    public Guid DurableClientGuid { get; set; }
    internal IShare? DurableShare;

    public TimeSpan DurableTimeout { get; set; }

    public Guid DurableCreateGuid { get; set; }

    public bool IsPersistentHandle { get; set; }

    public CreateOptions CreateOptions { get; set; }

    public uint GrantedAccess { get; set; }

    public uint ShareAccess { get; set; }

    public SmbFileAttributes FileAttributes { get; set; }

    public string PathName
    {
        get => LocalOpen?.Path ?? field;
        set;
    } = string.Empty;

    public bool DeleteOnClose { get; set; }

    public OplockLevel OplockLevel { get; set; }

    public LeaseKey LeaseKey { get; set; }

    public LeaseState LeaseState { get; set; }

    public ushort LeaseEpoch { get; set; }

    public LeaseKey ParentLeaseKey { get; set; }

    internal readonly SemaphoreSlim EaGate = new SemaphoreSlim(1, 1);
    internal int EaCursor;
    internal readonly SemaphoreSlim EnumerationGate = new SemaphoreSlim(1, 1);
    internal IDirectoryCursor? Enumeration;
    internal bool EnumerationStarted;
    internal bool EnumerationMore;
    internal string EnumerationPattern = "*";

    public IReadOnlyList<FileEntryInfo>? DirectoryListing { get; set; }

    public int DirectoryCursor { get; set; }

    public string? ShareModeKey { get; set; }

    internal readonly Lock ResumeKeyGate = new Lock();

    public byte[]? ResumeKey { get; set; }

    public RpcPipe? Pipe { get; set; }

    public bool IsPipe => Pipe != null;

    public (ulong Persistent, ulong Volatile) Key => (Persistent: PersistentFileId, Volatile: VolatileFileId);
}
