using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Smb.Server.State;

namespace Smb.Server.Durable;

/// <summary>Serializes only a durable-v2 CREATE transaction key. No arbitrary command responses are cached.</summary>
public sealed class CreateReplayRegistry
{
	private readonly Lock _gate = new Lock();
	private readonly Dictionary<(Guid, Guid), Entry> _entries = new Dictionary<(Guid, Guid), Entry>();

	internal sealed class Entry
	{
		internal readonly SemaphoreSlim Gate = new SemaphoreSlim(1, 1);
		internal SmbOpen? Open;
		internal int Users;
	}

	public int Count
	{
		get
		{
			lock (_gate) return _entries.Count;
		}
	}

	public async ValueTask<Reservation> EnterAsync(Guid client, Guid create, CancellationToken token)
	{
		var key = (client, create);
		Entry entry;
		lock (_gate)
		{
			if (!_entries.TryGetValue(key, out entry!)) _entries.Add(key, entry = new Entry());
			entry.Users++;
		}

		try { await entry.Gate.WaitAsync(token).ConfigureAwait(false); }
		catch
		{
			Release(key, entry, false);
			throw;
		}

		return new Reservation(this, key, entry);
	}

	private void Release((Guid, Guid) key, Entry entry, bool acquired)
	{
		if (acquired) entry.Gate.Release();
		lock (_gate)
		{
			if (--entry.Users == 0 && entry.Open == null) _entries.Remove(key);
		}
	}

	public void Retire(SmbOpen open)
	{
		lock (_gate)
		{
			var key = (open.DurableClientGuid, open.DurableCreateGuid);
			if (_entries.TryGetValue(key, out var entry) && ReferenceEquals(entry.Open, open))
			{
				entry.Open = null;
				if (entry.Users == 0) _entries.Remove(key);
			}
		}
	}

	public sealed class Reservation : IDisposable
	{
		private CreateReplayRegistry? _owner;
		private readonly (Guid, Guid) _key;
		private readonly Entry _entry;

		internal Reservation(CreateReplayRegistry owner, (Guid, Guid) key, Entry entry)
		{
			_owner = owner;
			_key = key;
			_entry = entry;
		}

		public SmbOpen? Open
		{
			get
			{
				lock (_owner!._gate) return _entry.Open;
			}
			set
			{
				lock (_owner!._gate) _entry.Open = value is { IsReplayEligible: true } && value.Lifetime.State == OpenState.Active ? value : null;
			}
		}

		public void Dispose() { Interlocked.Exchange(ref _owner, null)?.Release(_key, _entry, true); }
	}
}
