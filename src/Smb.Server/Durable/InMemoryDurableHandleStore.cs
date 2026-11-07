using System;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace Smb.Server.Durable;

public sealed class InMemoryDurableHandleStore : IDurableHandleStore
{
	private readonly ConcurrentDictionary<(ulong, ulong), DurableHandle> _handles = new ConcurrentDictionary<(ulong, ulong), DurableHandle>();

	public void Add(DurableHandle handle)
	{
		_handles[handle.Key] = handle;
	}

	public bool TryClaim(ulong persistentId, ulong volatileId, out DurableHandle handle)
	{
		return _handles.TryRemove((persistentId, volatileId), out handle);
	}

	public IReadOnlyList<DurableHandle> TakeExpired(DateTimeOffset now)
	{
		var list = new List<DurableHandle>();
		foreach (var value2 in _handles.Values)
		{
			if (!value2.IsPersistent && !(value2.Deadline > now) && _handles.TryRemove(value2.Key, out var value))
			{
				list.Add(value);
			}
		}

		return list;
	}

	public IReadOnlyList<DurableHandle> TakeAll()
	{
		var result = new List<DurableHandle>(_handles.Values);
		_handles.Clear();
		return result;
	}
}
