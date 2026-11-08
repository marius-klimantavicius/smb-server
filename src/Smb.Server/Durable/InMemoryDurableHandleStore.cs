using System;
using System.Collections.Generic;
using System.Threading;

namespace Smb.Server.Durable;

/// <summary>One owner per retained FileId and client/CreateGuid. Does not confer durable or replay eligibility.</summary>
public sealed class InMemoryDurableHandleStore : IDurableHandleStore
{
	private readonly Lock _gate = new Lock();
	private readonly Dictionary<(ulong, ulong), DurableHandle> _handles = new Dictionary<(ulong, ulong), DurableHandle>();
	private readonly Dictionary<(Guid Client, Guid Create), DurableHandle> _replays = new Dictionary<(Guid Client, Guid Create), DurableHandle>();
	private readonly Dictionary<(ulong, ulong), (Guid Client, Guid Create)> _replayKeys = new Dictionary<(ulong, ulong), (Guid Client, Guid Create)>();

	public void Add(DurableHandle handle)
	{
		// Snapshot the client scope before publication, without callbacks under the gate.
		var client = handle.ClientGuid ?? (handle.Open.Session is { } session ? new Guid(session.Connection.ClientGuid) : Guid.Empty);
		var replayKey = (client, handle.CreateGuid);
		lock (_gate)
		{
			if (_handles.ContainsKey(handle.Key) || (handle.IsV2 || handle.CreateGuid != Guid.Empty) && _replays.ContainsKey(replayKey))
				throw new InvalidOperationException("A retained open already owns this FileId or client/CreateGuid.");

			_handles.Add(handle.Key, handle);
			if ((handle.IsV2 || handle.CreateGuid != Guid.Empty))
			{
				_replays.Add(replayKey, handle);
				_replayKeys.Add(handle.Key, replayKey);
			}
		}
	}

	/// <summary>Non-consuming lookup for P7c. The caller must establish eligibility and existing ownership prerequisites.</summary>
	public bool TryGetReplay(Guid clientGuid, Guid createGuid, out DurableHandle handle)
	{
		lock (_gate) return _replays.TryGetValue((clientGuid, createGuid), out handle!);
	}

	public bool TryGetPersistent(ulong persistentId, out DurableHandle handle)
	{
		lock (_gate)
		{
			foreach (var candidate in _handles.Values)
				if (candidate.PersistentId == persistentId)
				{
					handle = candidate;
					return true;
				}

			handle = null!;
			return false;
		}
	}

	public bool TryClaim(ulong persistentId, ulong volatileId, out DurableHandle handle)
	{
		lock (_gate)
		{
			if (!_handles.Remove((persistentId, volatileId), out handle!)) return false;

			RemoveReplay(handle);
			return true;
		}
	}

	/// <summary>Terminal open cleanup cannot retire a different record that happens to have the same FileId.</summary>
	public void Retire(State.SmbOpen open)
	{
		lock (_gate)
		{
			if (_handles.TryGetValue(open.Key, out var handle) && ReferenceEquals(handle.Open, open))
			{
				_handles.Remove(open.Key);
				RemoveReplay(handle);
			}
		}
	}

	private void RemoveReplay(DurableHandle handle)
	{
		if (_replayKeys.Remove(handle.Key, out var key)) _replays.Remove(key);
	}

	public IReadOnlyList<DurableHandle> TakeExpired(DateTimeOffset now)
	{
		var result = new List<DurableHandle>();
		lock (_gate)
		{
			foreach (var handle in _handles.Values)
				if (!handle.IsPersistent && handle.Deadline <= now)
					result.Add(handle);
			foreach (var handle in result)
			{
				_handles.Remove(handle.Key);
				RemoveReplay(handle);
			}
		}

		return result;
	}

	public IReadOnlyList<DurableHandle> TakeAll()
	{
		lock (_gate)
		{
			var result = new List<DurableHandle>(_handles.Values);
			_handles.Clear();
			_replays.Clear();
			_replayKeys.Clear();
			return result;
		}
	}
}
