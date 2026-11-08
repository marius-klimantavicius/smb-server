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
/// Breaks conservatively revoke to NONE. No callback or await executes under the monitor.</summary>
public sealed class FileCacheCoordinator(SmbServerOptions options) : IOplockManager, ILeaseManager, IFileIoCoordinator
{
	private sealed class Grant(SmbOpen owner)
	{
		internal readonly HashSet<SmbOpen> Opens = [owner];
		internal SmbOpen Owner => Opens.First();
		internal OplockLevel Classic;
		internal LeaseState State;
		internal LeaseKey Key;
		internal bool Lease, V2;
		internal ushort Epoch;
		internal TaskCompletionSource? Breaking;
		internal ITimer? Timer;
		internal bool AckRequired, AckConsumed, Sent;
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

	private bool Eligible(SmbOpen open) => Supports(open.TreeConnect?.Share.FileStore) && open.LocalOpen is { IsDirectory: false, Identity: not null }
		&& options.LockManager.IsRangeAccessible(open, 0, ulong.MaxValue, true);

	private static bool SameLease(Grant g, SmbOpen open) => g.Lease && !open.LeaseKey.IsZero && g.Key == open.LeaseKey && Client(g.Owner) == Client(open);

	private List<Grant> Get(string key)
	{
		if (!_files.TryGetValue(key, out var list)) _files.Add(key, list = []);
		return list;
	}

	public OplockGrant RequestOplock(SmbOpen open, OplockLevel requested)
	{
		long version;
		lock (_gate) version = _operationVersion;
		if (!options.FeaturePolicy.Oplocks || !Eligible(open) || requested is not (OplockLevel.LevelII or OplockLevel.Exclusive or OplockLevel.Batch)) return OplockGrant.None;

		lock (_gate)
		{
			// Eligibility calls the supplied range-lock manager outside our monitor.
			// Admission/retirement in that interval invalidates the sampled result.
			if (version != _operationVersion) return OplockGrant.None;

			var list = Get(open.IdentityKey);
			if (OtherPhysical(open) || list.Any(g => g.Opens.Contains(open) || g.Breaking != null || g.Lease || g.Classic != OplockLevel.LevelII || requested != OplockLevel.LevelII)) return OplockGrant.None;

			list.Add(new Grant(open) { Classic = requested });
			open.OplockLevel = requested;
			return new OplockGrant(requested, Array.Empty<OplockBreak>());
		}
	}

	public LeaseGrant RequestLease(SmbOpen open, LeaseRequest request)
	{
		long version;
		lock (_gate) version = _operationVersion;
		if (!options.FeaturePolicy.Leasing || !Eligible(open) || request.Key.IsZero || request.RequestedState is not (LeaseState.None or LeaseState.Read or LeaseState.ReadHandle or LeaseState.ReadWrite or LeaseState.ReadWriteHandle)) return LeaseGrant.None;

		lock (_gate)
		{
			if (version != _operationVersion) return LeaseGrant.None;

			var list = Get(open.IdentityKey);
			open.LeaseKey = request.Key;
			var existing = list.FirstOrDefault(g => SameLease(g, open));
			if (existing != null)
			{
				if (existing.Breaking == null && !OtherPhysical(open) && (request.RequestedState & existing.State) == existing.State && !list.Any(g => g != existing && (g.State != LeaseState.None || g.Classic != OplockLevel.None)))
				{
					existing.State = request.RequestedState;
					if (existing.V2) existing.Epoch = unchecked((ushort)(existing.Epoch + 1));
				}

				existing.Opens.Add(open);
				Apply(existing);
				return new LeaseGrant(existing.State, existing.Epoch, Array.Empty<LeaseBreak>());
			}

			var state = request.RequestedState;
			if (OtherPhysical(open) || list.Any(g => g.Breaking != null || !g.Lease || (g.State & (LeaseState.Write | LeaseState.Handle)) != 0)) state = LeaseState.None;
			else if (list.Count > 0) state &= LeaseState.Read;
			var grant = new Grant(open) { Lease = true, Key = request.Key, State = state, V2 = request.IsV2, Epoch = request.IsV2 ? unchecked((ushort)(request.Epoch + 1)) : (ushort)0 };
			list.Add(grant);
			Apply(grant);
			return new LeaseGrant(state, grant.Epoch, Array.Empty<LeaseBreak>());
		}
	}

	// Acquires all COPY ranges atomically with respect to grants; no nested object locks.
	public ValueTask<IDisposable> AcquireAsync(IReadOnlyList<FileIoRange> ranges, CancellationToken cancellationToken = default) => AcquireCoreAsync(ranges.Select(r => (r.Open, r.ForWrite)).ToArray(), cancellationToken);
	public ValueTask<IDisposable> AcquireCreateAsync(SmbOpen provisional, bool destructive, CancellationToken token) => AcquireCoreAsync([(provisional, destructive)], token, creating: true);
	public ValueTask<IDisposable> AcquireNamespaceAsync(SmbOpen requester, FileIdentity? identity, CancellationToken token = default) => AcquireCoreAsync([(requester, true)], token, namespaceIdentity: identity);

	private async ValueTask<IDisposable> AcquireCoreAsync((SmbOpen Open, bool Write)[] operations, CancellationToken token, bool creating = false, FileIdentity? namespaceIdentity = null)
	{
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
					// Attribute-only opens do not access stream data or cached handles.
					// Destructive CREATEs still invalidate even with only attribute access.
					if (creating && !write && (open.GrantedAccess & ~0x00100180u) == 0) continue;
					if (!_files.TryGetValue(open.IdentityKey, out var list)) continue;

					foreach (var g in list)
					{
						// A classic level-II grant is invalidated by every write/lock,
						// including one issued through its own FileId.
						if (g.Opens.Contains(open) && (!write || g.Classic != OplockLevel.LevelII) || SameLease(g, open)) continue;

						var conflict = write || (g.Lease ? (g.State & (creating ? LeaseState.Write | LeaseState.Handle : LeaseState.Write)) != 0 : g.Classic is OplockLevel.Exclusive or OplockLevel.Batch);
						if (!conflict || g.Classic == OplockLevel.None && g.State == LeaseState.None && g.Breaking == null) continue;

						if (g.Breaking == null)
						{
							var ack = g.Lease ? g.State != LeaseState.Read : g.Classic != OplockLevel.LevelII;
							g.Breaking = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
							g.AckRequired = ack;
							g.AckConsumed = false;
							g.Sent = false;
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
		try
		{
			SmbOpen[] disconnected;
			lock (_gate) disconnected = g.Opens.Where(open => open.IsDurable && open.Session == null).ToArray();
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
					notification = new LeaseBreak(g.Key, g.State, LeaseState.None, g.Epoch, g.Owner);
				}

				await (SendLeaseBreakAsync?.Invoke(notification) ?? Task.FromException(new InvalidOperationException("No cache break sender"))).ConfigureAwait(false);
			}
			else await (SendOplockBreakAsync?.Invoke(new OplockBreak(g.Owner, OplockLevel.None)) ?? Task.FromException(new InvalidOperationException("No cache break sender"))).ConfigureAwait(false);

			bool consumed;
			lock (_gate)
			{
				g.Sent = true;
				consumed = g.AckConsumed;
			}

			if (!ack || consumed)
			{
				Revoke(g, completion);
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

	private void Revoke(Grant g, TaskCompletionSource completion)
	{
		ITimer? timer;
		lock (_gate)
		{
			if (g.Breaking != completion) return;

			g.State = LeaseState.None;
			g.Classic = OplockLevel.None;
			g.Breaking = null;
			timer = g.Timer;
			g.Timer = null;
			Apply(g);
		}

		timer?.Dispose();
		completion.TrySetResult();
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
				OplockLevel.LevelII => (NtStatus)0xc00000e2, // Valid ACK, but NONE-target object store declines the new II grant.
				_ => (NtStatus)0xc00000e3
			};
			g.AckConsumed = true;
			sent = g.Sent;
		}

		if (sent) Revoke(g, completion);
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
			g = _files.Values.SelectMany(x => x).FirstOrDefault(x => x.Lease && x.Key == key && x.Owner.Session?.Connection.ClientGuid.AsSpan().SequenceEqual(connection.ClientGuid) == true);
			completion = g?.Breaking;
			if (g == null) return NtStatus.ObjectNameNotFound;
			if (completion == null || !g.AckRequired || g.AckConsumed) return (NtStatus)0xc0000001;
			if (state != LeaseState.None) return (NtStatus)0xc00000d0;

			g.AckConsumed = true;
			sent = g.Sent;
		}

		if (sent) Revoke(g, completion);
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
