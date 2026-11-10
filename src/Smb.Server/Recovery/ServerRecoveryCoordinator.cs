using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server.Durable;
using Smb.Server.Locking;
using Smb.Server.Sharing;
using Smb.Server.State;

namespace Smb.Server.Recovery;

/// <summary>Rehydrates reservations before admission. Sessions always authenticate anew;
/// only identity/ownership lineage is journaled. No dependency on a storage implementation.</summary>
public sealed class ServerRecoveryCoordinator(SmbServerState server, IServerRecoveryStore store)
{
    private readonly ConcurrentDictionary<SmbOpen, byte> _tracked = new();
    private readonly SemaphoreSlim _startup = new(1, 1);
    private IRecoveryLockManager Locks => (IRecoveryLockManager)server.Options.LockManager;
    private IRetainedDurableHandleStore Registry => (IRetainedDurableHandleStore)server.Options.DurableHandleStore;
    private static bool Eligible(SmbOpen open) => open.IsDurable && open.LocalOpen?.Identity != null &&
        open.DurableShare?.FileStore is IRecoverableFileStore { HasExclusiveServerAccess: true };
    private static bool HasCaching(SmbOpen open) => open.OplockLevel == OplockLevel.Batch || open.OplockLevel == OplockLevel.Lease && open.LeaseState.HasFlag(LeaseState.Handle);
    private static void Require(NtStatus status, string operation)
    { if (status != NtStatus.Success) throw new IOException($"{operation} failed: {status}."); }

    public void SaveSession(SmbSession session)
        => store.SaveSession(new(session.SessionId, new Guid(session.Connection.ClientGuid), Owner(session), server.Options.TimeProvider.GetUtcNow()));
    public void RetireSession(SmbSession session) => store.RetireSession(session.SessionId);
    private static string Owner(SmbSession session) => session.Identity?.UserSid ?? (session.Identity is { } identity ? identity.DomainName + "\\" + identity.UserName : "<none>");

    public void Persist(SmbOpen open)
    {
        lock (open.RecoverySnapshotGate)
        {
            if (!Eligible(open)) return;
            if (open.Lifetime.State is not (OpenState.Active or OpenState.Disconnected)) return;
            if (!HasCaching(open) || server.Options.CacheCoordinator.IsBreaking(open)) { Forget(open); return; }
            var backend = (IRecoverableFileStore)open.DurableShare!.FileStore!;
            var token = open.RecoveryToken ?? Guid.NewGuid();
            var newRetention = open.RecoveryToken == null;
            if (newRetention) Require(backend.RetainForRecovery(open.LocalOpen!, token), "Retaining recovery object");
            try
            {
                var state = backend.CaptureRecoveryState(open.LocalOpen!);
                var sessionId = open.Session?.SessionId ?? open.RecoverySessionId;
                store.SaveHandle(new()
                {
                    PersistentId = open.PersistentFileId, VolatileId = open.VolatileFileId,
                    SessionId = sessionId, OwnerKey = open.DurableOwnerKey!, ClientGuid = open.DurableClientGuid,
                    CreateGuid = open.DurableCreateGuid, Token = token, ShareName = open.DurableShare.Name,
                    BackendIdentity = backend.RecoveryStoreIdentity, ObjectId = open.LocalOpen!.Identity!.Value.ObjectId,
                    StreamId = open.LocalOpen.Identity.Value.StreamId, Path = state.Path, SuppressWriteTime = state.SuppressWriteTimeUpdates,
                    ReplayEligible = open.IsReplayEligible, OriginalCreateAction = (uint)open.OriginalCreateAction,
                    GrantedAccess = open.GrantedAccess, ShareAccess = open.ShareAccess, CreateOptions = (uint)open.CreateOptions,
                    IsV2 = open.DurableIsV2, LeaseV2 = open.DurableLeaseV2, Oplock = (byte)open.OplockLevel,
                    LeaseState = (uint)open.LeaseState, LeaseKey = open.LeaseKey.ToBytes(), ParentLeaseKey = open.ParentLeaseKey.ToBytes(), LeaseEpoch = open.LeaseEpoch,
                    TimeoutTicks = open.DurableTimeout.Ticks, Deadline = open.RecoveryDeadline,
                    ChannelSequence = open.ChannelSequences.Snapshot.Sequence, LockSequences = open.LockSequences.Capture(),
                    Locks = Locks.CaptureLocks(open), CurrentByteOffset = Interlocked.Read(ref open.CurrentByteOffset)
                });
                open.RecoveryToken = token; open.RecoverySessionId = sessionId; _tracked[open] = 0;
            }
            catch
            {
                if (newRetention) Require(backend.ReleaseRecovery(token), "Releasing failed recovery retention");
                throw;
            }
        }
    }
    public void Flush()
    {
        foreach (var open in server.SessionGlobalList.Values.SelectMany(s => s.Opens.Values).Concat(_tracked.Keys).Distinct()) Persist(open);
    }
    public void Forget(SmbOpen open)
    {
        lock (open.RecoverySnapshotGate)
        {
            if (open.RecoveryToken is not { } token) return;
            // Delete the journal record first. A crash between stores can leave only an
            // orphan anchor, which startup reconciles; it cannot resurrect an ACKed close.
            store.RemoveHandle(open.PersistentFileId);
            Require(((IRecoverableFileStore)open.DurableShare!.FileStore!).ReleaseRecovery(token), "Releasing recovery retention");
            open.RecoveryToken = null; _tracked.TryRemove(open, out _);
        }
    }
    public void DetachPhysical(SmbOpen open) => _tracked.TryRemove(open, out _);

    public async Task InitializeAsync(CancellationToken token = default)
    {
        await _startup.WaitAsync(token).ConfigureAwait(false);
        var restored = new List<SmbOpen>();
        try
        {
            var records = store.LoadHandles();
            // Validate routing before any reconciliation. A renamed/missing share or a
            // different filesystem must fail startup, never substitute an object by name.
            var routes = new Dictionary<string, IShare>(StringComparer.OrdinalIgnoreCase);
            foreach (var share in server.Shares.All)
                if (share.FileStore is IRecoverableFileStore) routes.Add(share.Name, share);
            foreach (var record in records)
                if (!routes.TryGetValue(record.ShareName, out var share) || share.FileStore is not IRecoverableFileStore backend ||
                    !backend.HasExclusiveServerAccess || backend.RecoveryStoreIdentity != record.BackendIdentity)
                    throw new InvalidDataException("Recovery record does not match the configured share/backend.");
            foreach (var record in records)
            {
                var backend = (IRecoverableFileStore)routes[record.ShareName].FileStore!;
                var now = server.Options.TimeProvider.GetUtcNow();
                var deadline = record.Deadline ?? now + TimeSpan.FromTicks(record.TimeoutTicks);
                if (deadline <= now) { store.RemoveHandle(record.PersistentId); continue; }
                var result = await backend.ReopenForRecoveryAsync(record.Token, new(record.ObjectId, record.StreamId), Access(record.GrantedAccess),
                    new(record.Path, record.SuppressWriteTime), token).ConfigureAwait(false);
                if (!result.IsSuccess) throw new InvalidDataException("Recovery object is missing or has changed identity: " + result.Status);
                var open = new SmbOpen
                {
                    PersistentFileId = record.PersistentId, VolatileFileId = record.VolatileId,
                    LocalOpen = result.Value, DurableShare = routes[record.ShareName], PathName = record.Path,
                    ShareModeKey = result.Value!.Identity!.Value.Key, AdmissionIdentity = result.Value.Identity,
                    IsDurable = true, DurableOwnerKey = record.OwnerKey, DurableClientGuid = record.ClientGuid,
                    DurableIsV2 = record.IsV2, DurableLeaseV2 = record.LeaseV2, DurableCreateGuid = record.CreateGuid,
                    IsReplayEligible = record.ReplayEligible, OriginalCreateAction = (CreateAction)record.OriginalCreateAction, CreateSessionId = record.SessionId,
                    DurableTimeout = TimeSpan.FromTicks(record.TimeoutTicks), GrantedAccess = record.GrantedAccess, ShareAccess = record.ShareAccess,
                    CreateOptions = (CreateOptions)record.CreateOptions, OplockLevel = (OplockLevel)record.Oplock,
                    LeaseState = (LeaseState)record.LeaseState, LeaseKey = LeaseKey.From(record.LeaseKey), ParentLeaseKey = LeaseKey.From(record.ParentLeaseKey), LeaseEpoch = record.LeaseEpoch,
                    DeleteOnClose = result.Value.DeletePending, RecoveryToken = record.Token, RecoveryDeadline = deadline, RecoverySessionId = record.SessionId,
                    ChannelSequences = new(record.ChannelSequence), CurrentByteOffset = record.CurrentByteOffset
                };
                restored.Add(open);
                if (!HasCaching(open)) throw new InvalidDataException("Recovery record has no durable caching promise.");
                open.LockSequences.Restore(record.LockSequences);
                if (!server.Options.ShareModeManager.TryOpen(open.IdentityKey, open, Access(open.GrantedAccess), (FileShareMode)open.ShareAccess))
                    throw new InvalidDataException("Conflicting recovered share reservations.");
                var lockResult = await Locks.ApplyAsync(open, record.Locks.Select(r => new LockElement(r.Offset, r.Length, r.Exclusive, false)).ToArray(), true, token).ConfigureAwait(false);
                if (lockResult != LockOutcome.Granted) throw new InvalidDataException("Conflicting recovered byte locks.");
                server.Options.CacheCoordinator.Restore(open);
                open.Lifetime.Activate(); open.Lifetime.BeginDisconnect(out _); open.Lifetime.CompleteDisconnect();
                store.SaveHandle(record with { Deadline = deadline }); // Restarting again must not extend retention.
                Registry.Add(new() { PersistentId = record.PersistentId, VolatileId = record.VolatileId, Open = open,
                    Deadline = deadline, OwnerKey = record.OwnerKey, ClientGuid = record.ClientGuid, CreateGuid = record.CreateGuid, IsV2 = record.IsV2 });
                if (open.DurableIsV2 && open.IsReplayEligible) server.CreateReplays.Restore(open);
                _tracked[open] = 0;
                server.Options.Metrics.OnHandleOpened(); open.MetricCounted = true;
            }
            var keep = store.LoadHandles().Select(r => r.Token).ToHashSet();
            foreach (var backend in routes.Values.Select(s => (IRecoverableFileStore)s.FileStore!).Distinct())
                foreach (var orphan in backend.GetRecoveryTokens())
                    if (!keep.Contains(orphan)) Require(backend.ReleaseRecovery(orphan), "Reconciling abandoned recovery retention");
        }
        catch
        {
            foreach (var open in restored)
            {
                server.CreateReplays.Retire(open); Registry.Retire(open); _tracked.TryRemove(open, out _);
                server.Options.CacheCoordinator.ReleaseOwner(open); Locks.ReleaseOwner(open);
                server.Options.ShareModeManager.Close(open.IdentityKey, open);
                if (open.MetricCounted) { server.Options.Metrics.OnHandleClosed(); open.MetricCounted = false; }
                await open.LocalOpen!.DisposeAsync().ConfigureAwait(false);
            }
            throw;
        }
        finally { _startup.Release(); }
    }
    private static FileAccessIntent Access(uint mask)
    {
        var result = FileAccessIntent.None;
        if ((mask & (0x80000000u | 0x10000000u | 0x02000000u | 1u | 0x20000020u)) != 0) result |= FileAccessIntent.Read;
        if ((mask & (0x40000000u | 0x10000000u | 2u | 4u)) != 0) result |= FileAccessIntent.Write;
        if ((mask & (0x10000000u | 0x10000u)) != 0) result |= FileAccessIntent.Delete;
        return result;
    }
}
