using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Smb.Server.State;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;

namespace Smb.Server.Durable;

/// <summary>Serializes only a durable-v2 CREATE transaction key. No arbitrary command responses are cached.</summary>
public sealed class CreateReplayRegistry
{
	private readonly Lock _gate = new Lock();
	private readonly Dictionary<(Guid, Guid), Entry> _entries = new Dictionary<(Guid, Guid), Entry>();

	private readonly Dictionary<(Guid, Guid), PendingClaim> _pending = new Dictionary<(Guid, Guid), PendingClaim>();

	internal PendingClaim? TryBeginRequest(Guid client, Guid create)
	{
		lock (_gate)
		{
			var key = (client, create);
			if (_pending.ContainsKey(key)) return null;
			var claim = new PendingClaim(this, key);
			_pending.Add(key, claim);
			return claim;
		}
	}

	internal sealed class PendingClaim(CreateReplayRegistry owner, (Guid, Guid) key)
	{
		private bool _executed, _delivered;
		private byte[]? _expectedBody;
		private NtStatus _expectedStatus;
		internal void Expect(NtStatus status, byte[] body)
		{
			_expectedStatus = status;
			Volatile.Write(ref _expectedBody, body);
		}
		internal bool Commit(ReadOnlyMemory<byte> message)
		{
			var body = Volatile.Read(ref _expectedBody);
			if (body == null || message.Length < 64 + body.Length) return false;
			var header = Smb2Header.Read(message.Span);
			if (header.Command != SmbCommand.Create || header.Status != _expectedStatus || !message.Span.Slice(64, body.Length).SequenceEqual(body)) return false;
			ResponseDone();
			return true;
		}
		internal void ExecutionDone() => Finish(true);
		internal void ResponseDone() => Finish(false);
		private void Finish(bool execution)
		{
			lock (owner._gate)
			{
				if (execution) _executed = true; else _delivered = true;
				if (_executed && _delivered && owner._pending.TryGetValue(key, out var current) && ReferenceEquals(current, this))
					owner._pending.Remove(key);
			}
		}
	}

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
