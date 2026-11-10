using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server.Leases;
using Smb.Server.Oplocks;
using Smb.Server.State;

namespace Smb.Server.Caching;

/// <summary>One object/stream conflict domain for classic oplocks, leases, and physical I/O.
/// Compatible CREATEs retain read/handle caching. No callback or await executes under the monitor.</summary>
public sealed class FileCacheCoordinator(SmbServerOptions options) : IOplockManager, ILeaseManager, IFileIoCoordinator
{
    private sealed class Grant(SmbOpen owner)
    {
        internal readonly HashSet<SmbOpen> Opens = [owner];
        internal SmbOpen Owner => Opens.FirstOrDefault(open => open.Session != null) ?? Opens.First();
        internal OplockLevel Classic;
        internal LeaseState State;
        internal LeaseKey Key;
        internal bool Lease, V2;
        internal ushort Epoch;
        internal TaskCompletionSource? Breaking;
        internal ITimer? Timer;
        internal bool AckRequired, AckConsumed, Sent, Completing;
        internal LeaseState TargetState;
        internal OplockLevel TargetClassic;
    }

    private readonly Dictionary<string, int> _namespacePhysical = new Dictionary<string, int>(StringComparer.Ordinal);

    public int NamespaceScopeCount
    {
        get
        {
            lock (_gate) return _namespacePhysical.Values.Sum();
        }
    }

    private readonly Dictionary<SmbOpen, int> _activeOpens = new Dictionary<SmbOpen, int>();
    private readonly Dictionary<(string Client, LeaseKey Key), (string Identity, int Count)> _reservations = new Dictionary<(string Client, LeaseKey Key), (string Identity, int Count)>();
    private static string Client(SmbOpen open) => Convert.ToHexString(open.Session?.Connection.ClientGuid ?? open.DurableClientGuid.ToByteArray());

    public IDisposable? ReserveLease(SmbOpen open, LeaseKey key)
    {
        var index = (Client(open), key);
        lock (_gate)
        {
            if (_reservations.TryGetValue(index, out var existing) && existing.Identity != open.IdentityKey) return null;
            if (_files.Any(pair => pair.Key != open.IdentityKey && pair.Value.Any(g => g.Lease && g.Key == key && Client(g.Owner) == index.Item1))) return null;

            _reservations[index] = (open.IdentityKey, existing.Count + 1);
            return new Reservation(this, index);
        }
    }

    private sealed class Reservation(FileCacheCoordinator owner, (string Client, LeaseKey Key) index) : IDisposable
    {
        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;

            lock (owner._gate)
            {
                var value = owner._reservations[index];
                if (value.Count == 1) owner._reservations.Remove(index);
                else owner._reservations[index] = (value.Identity, value.Count - 1);
            }
        }
    }

    private bool OtherPhysical(SmbOpen open) => open.LocalOpen?.Identity is { } id && _namespacePhysical.GetValueOrDefault(id.ObjectId) != 0 || _activeOpens.Any(p => p.Key != open && p.Key.IdentityKey == open.IdentityKey && p.Value > 0);
    private readonly Lock _gate = new Lock();
    private long _operationVersion;
    private readonly Dictionary<string, List<Grant>> _files = new Dictionary<string, List<Grant>>(StringComparer.Ordinal);
    private readonly Dictionary<string, int> _physical = new Dictionary<string, int>(StringComparer.Ordinal);
    public Func<SmbOpen, Task>? CloseDisconnectedAsync { internal get; set; }
    public Func<OplockBreak, Task>? SendOplockBreakAsync { internal get; set; }
    public Func<LeaseBreak, Task>? SendLeaseBreakAsync { internal get; set; }

    public int GrantCount
    {
        get
        {
            lock (_gate) return _files.Values.Sum(x => x.Count);
        }
    }

    public int PhysicalScopeCount
    {
        get
        {
            lock (_gate) return _physical.Values.Sum();
        }
    }

    public int BreakingCount
    {
        get
        {
            lock (_gate) return _files.Values.Sum(x => x.Count(g => g.Breaking != null));
        }
    }

    public static bool Supports(IFileStore? store) => store is ICacheCoherentFileStore { HasExclusiveServerAccess: true };

    private bool Eligible(SmbOpen open) => Supports(open.TreeConnect?.Share.FileStore) && open.LocalOpen is { IsDirectory: false, Identity: not null };

    private static bool SameLease(Grant g, SmbOpen open) => g.Lease && !open.LeaseKey.IsZero && g.Key == open.LeaseKey && Client(g.Owner) == Client(open);

    private List<Grant> Get(string key)
    {
        if (!_files.TryGetValue(key, out var list)) _files.Add(key, list = []);
        return list;
    }

    internal void Restore(SmbOpen open)
    {
        lock (_gate)
        {
            var list = Get(open.IdentityKey);
            var common = list.FirstOrDefault(g => SameLease(g, open));
            if (common != null)
            {
                if (common.State != open.LeaseState || common.Epoch != open.LeaseEpoch || common.V2 != open.DurableLeaseV2)
                    throw new System.IO.InvalidDataException("Inconsistent recovered lease group.");
                common.Opens.Add(open);
            }
            else list.Add(new Grant(open) { Classic = open.OplockLevel == OplockLevel.Lease ? OplockLevel.None : open.OplockLevel,
                Lease = open.OplockLevel == OplockLevel.Lease, Key = open.LeaseKey, State = open.LeaseState, V2 = open.DurableLeaseV2, Epoch = open.LeaseEpoch });
        }
    }

    public OplockGrant RequestOplock(SmbOpen open, OplockLevel requested)
    {
        long version;
        lock (_gate) version = _operationVersion;
        if (!options.FeaturePolicy.Oplocks || !Eligible(open) || !options.LockManager.IsRangeAccessible(open, 0, ulong.MaxValue, true) || requested is not (OplockLevel.LevelII or OplockLevel.Exclusive or OplockLevel.Batch)) return OplockGrant.None;

        lock (_gate)
        {
            // Eligibility calls the supplied range-lock manager outside our monitor.
            // Admission/retirement in that interval invalidates the sampled result.
            if (version != _operationVersion) return OplockGrant.None;

            var list = Get(open.IdentityKey);
            if (OtherPhysical(open) || list.Any(g => g.Opens.Contains(open) || g.Breaking != null || g.Lease && g.State is not (LeaseState.None or LeaseState.Read) ||
                g.Classic != OplockLevel.None && (g.Classic != OplockLevel.LevelII || requested != OplockLevel.LevelII))) return OplockGrant.None;

            list.Add(new Grant(open) { Classic = requested });
            open.OplockLevel = requested;
            return new OplockGrant(requested, Array.Empty<OplockBreak>());
        }
    }

    public LeaseGrant RequestLease(SmbOpen open, LeaseRequest request) => RequestLease(open, request, false);

    public LeaseGrant RequestLease(SmbOpen open, LeaseRequest request, bool contended)
    {
        long version;
        lock (_gate) version = _operationVersion;
        if (!options.FeaturePolicy.Leasing || !Eligible(open) || request.Key.IsZero || request.RequestedState is not (LeaseState.None or LeaseState.Read or LeaseState.ReadHandle or LeaseState.ReadWrite or LeaseState.ReadWriteHandle)) return LeaseGrant.None with { Epoch = request.IsV2 ? request.Epoch : (ushort)0, IsV2 = request.IsV2 };

        var lockAccessible = options.LockManager.IsRangeAccessible(open, 0, ulong.MaxValue, true);
        lock (_gate)
        {
            var stable = version == _operationVersion;

            var list = Get(open.IdentityKey);
            open.LeaseKey = request.Key;
            var existing = list.FirstOrDefault(g => SameLease(g, open));
            if (existing != null)
            {
                if (stable && existing.Breaking == null && !OtherPhysical(open) && request.RequestedState != existing.State && (request.RequestedState & existing.State) == existing.State
                    && ((request.RequestedState & LeaseState.Write) == 0 || !contended && lockAccessible)
                    && !list.Any(g => g != existing && (g.Breaking != null || (g.State & LeaseState.Write) != 0 ||
                        (request.RequestedState & LeaseState.Write) != 0 && (g.State != LeaseState.None || g.Classic != OplockLevel.None) ||
                        (request.RequestedState & LeaseState.Handle) != 0 && g.Classic != OplockLevel.None)))
                {
                    existing.State = request.RequestedState;
                    if (existing.V2) existing.Epoch = unchecked((ushort)(existing.Epoch + 1));
                }

                existing.Opens.Add(open);
                Apply(existing);
                return new LeaseGrant(existing.State, existing.Epoch, Array.Empty<LeaseBreak>()) { IsV2 = existing.V2 };
            }

            var state = !stable ? LeaseState.None : contended ? request.RequestedState & LeaseState.ReadHandle : request.RequestedState;
            if (OtherPhysical(open) || list.Any(g => g.Breaking != null || !g.Lease && g.Classic is not (OplockLevel.None or OplockLevel.LevelII) ||
                (g.State & LeaseState.Write) != 0)) state = LeaseState.None;
            else if (list.Any(g => g.Classic == OplockLevel.LevelII)) state &= LeaseState.Read;
            else if (list.Any(g => g.State != LeaseState.None)) state &= LeaseState.ReadHandle;
            // Shared cache promises can coexist with already coordinated leased
            // locks: every subsequent physical READ/WRITE still checks range access,
            // and lock acquisition invalidates foreign caches before entering.
            if (!lockAccessible && ((state & LeaseState.Write) != 0 || !list.Any(g => g.Lease))) state = LeaseState.None;
            var grant = new Grant(open) { Lease = true, Key = request.Key, State = state, V2 = request.IsV2, Epoch = request.IsV2 ? unchecked((ushort)(request.Epoch + (state != LeaseState.None ? 1 : 0))) : (ushort)0 };
            list.Add(grant);
            Apply(grant);
            return new LeaseGrant(state, grant.Epoch, Array.Empty<LeaseBreak>()) { IsV2 = grant.V2 };
        }
    }

    // Acquires all COPY ranges atomically with respect to grants; no nested object locks.
    public ValueTask<IDisposable> AcquireAsync(IReadOnlyList<FileIoRange> ranges, CancellationToken cancellationToken = default) => AcquireCoreAsync(ranges.Select(r => (r.Open, r.ForWrite)).ToArray(), cancellationToken);
    public ValueTask<IDisposable> AcquireCreateAsync(SmbOpen provisional, bool destructive, CancellationToken token, bool sharingConflict = false) => AcquireCoreAsync([(provisional, destructive)], token, creating: true, sharingConflict: sharingConflict);
    public ValueTask<IDisposable> AcquireNamespaceAsync(SmbOpen requester, FileIdentity? identity, CancellationToken token = default, bool preserveRead = false) => AcquireCoreAsync([(requester, true)], token, namespaceIdentity: identity, preserveRead: preserveRead);

    private static bool IsMetadataOnlyCreateAccess(uint access, bool leased)
    {
        // This object store's metadata-open policy includes READ_EA: MS-SMB2
        // 2.2.13.1.1 grants metadata reads, not stream I/O, for that right.
        // Native Windows' narrower IRP_MJ_CREATE stat mask is a different policy.
        const uint readEa = 0x8, readAttributes = 0x80, writeAttributes = 0x100, synchronize = 0x100000, readControl = 0x20000;
        return (access & ~(readEa | readAttributes | writeAttributes | synchronize | (leased ? readControl : 0))) == 0;
    }

    private async ValueTask<IDisposable> AcquireCoreAsync((SmbOpen Open, bool Write)[] operations, CancellationToken token, bool creating = false, FileIdentity? namespaceIdentity = null, bool sharingConflict = false, bool preserveRead = false)
    {
        var queuedEscalations = new HashSet<Grant>();
        while (true)
        {
            token.ThrowIfCancellationRequested();
            var notifications = new List<(Grant Grant, TaskCompletionSource Completion, bool Ack)>();
            var waits = new List<Task>();
            lock (_gate)
            {
                var allOperations = operations.ToList();
                if (namespaceIdentity is { } family)
                {
                    var requester = operations[0].Open;
                    foreach (var grant in _files.Values.SelectMany(x => x))
                        if (grant.Owner.LocalOpen?.Identity?.ObjectId == family.ObjectId && grant.Owner.IdentityKey != requester.IdentityKey)
                            allOperations.Add((new SmbOpen { VolatileFileId = requester.VolatileFileId, ShareModeKey = grant.Owner.IdentityKey, Session = requester.Session, TreeConnect = requester.TreeConnect, LeaseKey = requester.LeaseKey }, true));
                }

                foreach (var (open, write) in allOperations)
                {
                    if (!_files.TryGetValue(open.IdentityKey, out var list)) continue;

                    foreach (var g in list)
                    {
                        // Only nonmutating, share-compatible CREATEs can preserve caches.
                        // WRITE_EA, data rights, destructive dispositions and actual EA SETs
                        // continue through ordinary invalidation / physical admission.
                        if (creating && !write && !sharingConflict && IsMetadataOnlyCreateAccess(open.GrantedAccess, g.Lease)) continue;
                        if (sharingConflict && !g.Lease && g.Classic != OplockLevel.Batch) continue;
                        // A classic level-II grant is invalidated by every write/lock,
                        // including one issued through its own FileId.
                        if (g.Opens.Contains(open) && (!write || g.Classic != OplockLevel.LevelII) || SameLease(g, open)) continue;

                        var partial = creating && !write;
                        var targetState = preserveRead ? g.State & ~LeaseState.Handle : partial ? g.State & ~(sharingConflict ? LeaseState.Handle : LeaseState.Write) : LeaseState.None;
                        // A destructive CREATE queued behind the WRITE downgrade first
                        // retires HANDLE. Only after that ACK does it invalidate READ.
                        // This preserves one outstanding ACK obligation at each stage.
                        if (g.Lease && creating && write && g.Breaking != null && targetState != g.TargetState) queuedEscalations.Add(g);
                        if (g.Lease && g.Breaking == null && g.State == LeaseState.ReadHandle && queuedEscalations.Remove(g)) targetState = LeaseState.Read;
                        var targetClassic = partial ? OplockLevel.LevelII : OplockLevel.None;
                        var conflict = g.Lease ? targetState != g.State && (write || (g.State & (creating ? LeaseState.Write | LeaseState.Handle : LeaseState.Write)) != 0)
                            : write || g.Classic is OplockLevel.Exclusive or OplockLevel.Batch;
                        if (!conflict || g.Classic == OplockLevel.None && g.State == LeaseState.None && g.Breaking == null) continue;

                        if (g.Breaking == null)
                        {
                            var ack = g.Lease ? g.State != LeaseState.Read : g.Classic != OplockLevel.LevelII;
                            g.Breaking = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                            g.AckRequired = ack;
                            g.AckConsumed = false;
                            g.Sent = false;
                            g.TargetState = targetState;
                            g.TargetClassic = targetClassic;
                            notifications.Add((g, g.Breaking, ack));
                        }

                        waits.Add(g.Breaking.Task);
                    }
                }

                if (waits.Count == 0)
                {
                    _operationVersion++;
                    var keys = allOperations.Select(x => x.Open.IdentityKey).Distinct(StringComparer.Ordinal).ToArray();
                    foreach (var key in keys) _physical[key] = _physical.GetValueOrDefault(key) + 1;
                    var opens = allOperations.Select(x => x.Open).Distinct().ToArray();
                    foreach (var open in opens) _activeOpens[open] = _activeOpens.GetValueOrDefault(open) + 1;
                    if (namespaceIdentity is { } identity) _namespacePhysical[identity.ObjectId] = _namespacePhysical.GetValueOrDefault(identity.ObjectId) + 1;
                    return new Scope(this, keys, opens, namespaceIdentity?.ObjectId);
                }
            }

            // Register state before sending, and start timeout only after the send commits.
            foreach (var n in notifications) await NotifyAsync(n.Grant, n.Completion, n.Ack).ConfigureAwait(false);
            await Task.WhenAll(waits).WaitAsync(token).ConfigureAwait(false);
        }
    }

    private async Task NotifyAsync(Grant g, TaskCompletionSource completion, bool ack)
    {
        // Invalidate restart promises before notifications or physical mutation. A
        // journal failure leaves the original grant intact and fails all current waiters.
        try
        {
            SmbOpen[] recovering;
            lock (_gate) recovering = g.Opens.ToArray();
            foreach (var open in recovering) options.RecoveryCoordinator?.Forget(open);
        }
        catch (Exception error)
        {
            lock (_gate)
            {
                if (g.Breaking == completion) { g.Breaking = null; g.Completing = false; }
            }
            completion.TrySetException(error);
            throw;
        }
        try
        {
            SmbOpen[] disconnected;
            // A live member can flush and acknowledge the common lease for all
            // its opens (MS-SMB2 3.3.4.7). Do not discard a recoverable member
            // merely because its own session is gone. Route through a live owner.
            lock (_gate) disconnected = g.Opens.Any(open => open.Session != null) ? [] : g.Opens.Where(open => open.IsDurable && open.Session == null).ToArray();
            if (disconnected.Length != 0)
            {
                foreach (var open in disconnected)
                    if (CloseDisconnectedAsync != null)
                        await CloseDisconnectedAsync(open).ConfigureAwait(false);
                lock (_gate)
                {
                    if (g.Breaking != completion) return;
                }
                // A remaining live open still owns this shared lease and its caching promise.
            }

            if (g.Lease)
            {
                LeaseBreak notification;
                lock (_gate)
                {
                    if (g.Breaking != completion) return;

                    g.Epoch = g.V2 ? unchecked((ushort)(g.Epoch + 1)) : (ushort)0;
                    notification = new LeaseBreak(g.Key, g.State, g.TargetState, g.Epoch, g.Owner);
                }

                await (SendLeaseBreakAsync?.Invoke(notification) ?? Task.FromException(new InvalidOperationException("No cache break sender"))).ConfigureAwait(false);
            }
            else await (SendOplockBreakAsync?.Invoke(new OplockBreak(g.Owner, g.TargetClassic)) ?? Task.FromException(new InvalidOperationException("No cache break sender"))).ConfigureAwait(false);

            bool consumed;
            lock (_gate)
            {
                g.Sent = true;
                consumed = g.AckConsumed;
            }

            if (!ack || consumed)
            {
                Revoke(g, completion, preserveTarget: true);
                return;
            }

            var timer = options.TimeProvider.CreateTimer(_ => Revoke(g, completion), null, options.OplockBreakTimeout, Timeout.InfiniteTimeSpan);
            lock (_gate)
            {
                if (g.Breaking == completion) g.Timer = timer;
                else timer.Dispose();
            }
        }
        catch { Revoke(g, completion); }
    }

    private static void Apply(Grant g)
    {
        foreach (var open in g.Opens)
        {
            open.OplockLevel = g.Lease ? OplockLevel.Lease : g.Classic;
            open.LeaseState = g.State;
            open.LeaseEpoch = g.Epoch;
        }
    }

    private void Revoke(Grant g, TaskCompletionSource completion, bool preserveTarget = false)
    {
        ITimer? timer;
        SmbOpen[] disconnected;
        LeaseState state;
        OplockLevel classic;
        lock (_gate)
        {
            if (g.Breaking != completion || g.Completing) return;

            g.Completing = true;
            g.AckConsumed = true;
            state = preserveTarget ? g.TargetState : LeaseState.None;
            classic = preserveTarget ? g.TargetClassic : OplockLevel.None;
            disconnected = g.Lease && (state & LeaseState.Handle) == 0
                ? g.Opens.Where(open => open.IsDurable && open.Session == null).ToArray() : [];
            timer = g.Timer;
            g.Timer = null;
        }

        timer?.Dispose();
        if (disconnected.Length == 0) CompleteRevocation(g, completion, state, classic);
        else _ = RetireDisconnectedAsync();

        async Task RetireDisconnectedAsync()
        {
            // A subset ACK may remove HANDLE even when the requested target
            // retained it. Release all unreachable reservations before resuming
            // physical I/O; keep the common break armed while close drains.
            try
            {
                foreach (var open in disconnected)
                    if (CloseDisconnectedAsync != null) await CloseDisconnectedAsync(open).ConfigureAwait(false);
            }
            finally { CompleteRevocation(g, completion, state, classic); }
        }
    }

    private void CompleteRevocation(Grant g, TaskCompletionSource completion, LeaseState state, OplockLevel classic)
    {
        lock (_gate)
        {
            g.State = state;
            g.Classic = g.Lease ? OplockLevel.None : classic;
            g.Breaking = null;
            g.Completing = false;
            Apply(g);
        }
        completion.TrySetResult();
    }

    public bool IsDeletePending(string identityKey)
    {
        SmbOpen[] opens;
        lock (_gate) opens = _files.GetValueOrDefault(identityKey)?.SelectMany(g => g.Opens).ToArray() ?? [];
        // Unreachable durable owners must first go through the ordinary
        // HANDLE-break purge, which can complete deletion and recreate the name.
        return opens.Any(open => open.Session != null && open.LocalOpen?.DeletePending == true);
    }

    public bool IsBreaking(SmbOpen open)
    {
        lock (_gate) return _files.GetValueOrDefault(open.IdentityKey)?.Any(g => g.Opens.Contains(open) && g.Breaking != null) == true;
    }

    public NtStatus Acknowledge(SmbOpen open, OplockLevel level, out OplockLevel actual)
    {
        actual = OplockLevel.None;
        Grant? g;
        TaskCompletionSource? completion;
        bool sent;
        NtStatus status;
        lock (_gate)
        {
            g = _files.GetValueOrDefault(open.IdentityKey)?.FirstOrDefault(x => !x.Lease && x.Opens.Contains(open));
            completion = g?.Breaking;
            if (g == null || completion == null || !g.AckRequired || g.AckConsumed) return (NtStatus)0xc0000184;

            status = level switch
            {
                OplockLevel.None => NtStatus.Success,
                OplockLevel.Lease => NtStatus.InvalidParameter,
                OplockLevel.Exclusive when g.Classic == OplockLevel.Batch => NtStatus.Success,
                OplockLevel.LevelII => g.TargetClassic == OplockLevel.LevelII ? NtStatus.Success : (NtStatus)0xc00000e2,
                _ => (NtStatus)0xc00000e3
            };
            g.AckConsumed = true;
            if (status == NtStatus.Success && level == OplockLevel.LevelII) actual = level;
            else g.TargetClassic = OplockLevel.None;
            sent = g.Sent;
        }

        if (sent) Revoke(g, completion, preserveTarget: true);
        return status;
    }

    public OplockLevel Acknowledge(SmbOpen open, OplockLevel newLevel)
    {
        Acknowledge(open, newLevel, out var result);
        return result;
    }

    public NtStatus Acknowledge(SmbConnection connection, LeaseKey key, LeaseState state, out LeaseState actual)
    {
        actual = LeaseState.None;
        Grant? g;
        TaskCompletionSource? completion;
        bool sent;
        lock (_gate)
        {
            g = _files.Values.SelectMany(x => x).FirstOrDefault(x => x.Lease && x.Key == key && Client(x.Owner) == Convert.ToHexString(connection.ClientGuid));
            completion = g?.Breaking;
            if (g == null) return NtStatus.ObjectNameNotFound;
            if (completion == null || !g.AckRequired || g.AckConsumed) return (NtStatus)0xc0000001;
            if ((state & ~g.TargetState) != 0) return (NtStatus)0xc00000d0;

            g.AckConsumed = true;
            g.TargetState = actual = state;
            sent = g.Sent;
        }

        if (sent) Revoke(g, completion, preserveTarget: true);
        return NtStatus.Success;
    }

    LeaseState ILeaseManager.Acknowledge(LeaseKey key, LeaseState newState) => LeaseState.None; // Wire ACKs require a client scope.

    public void ReleaseOwner(SmbOpen open)
    {
        var revoked = new List<(Grant, TaskCompletionSource)>();
        lock (_gate)
        {
            if (!_files.TryGetValue(open.IdentityKey, out var list)) return;

            foreach (var g in list.ToArray())
                if (g.Opens.Remove(open) && g.Opens.Count == 0)
                {
                    list.Remove(g);
                    if (g.Breaking is { } t) revoked.Add((g, t));
                }

            if (list.Count == 0) _files.Remove(open.IdentityKey);
        }

        foreach (var (g, t) in revoked) Revoke(g, t);
    }

    public IReadOnlyList<LeaseBreak> BreakDirectoryLease(string directoryFileKey) => Array.Empty<LeaseBreak>();

    private sealed class Scope(FileCacheCoordinator owner, string[] keys, SmbOpen[] opens, string? namespaceObject) : IDisposable
    {
        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;

            lock (owner._gate)
            {
                owner._operationVersion++;
                if (namespaceObject != null && --owner._namespacePhysical[namespaceObject] == 0) owner._namespacePhysical.Remove(namespaceObject);
                foreach (var key in keys)
                {
                    if (--owner._physical[key] == 0) owner._physical.Remove(key);
                }

                foreach (var open in opens)
                {
                    if (--owner._activeOpens[open] == 0) owner._activeOpens.Remove(open);
                }
            }
        }
    }
}
