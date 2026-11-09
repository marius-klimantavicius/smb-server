using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Smb.Server.State;

namespace Smb.Server.Locking;

public sealed class InMemoryLockManager : ILockManager
{
	private readonly record struct ActiveLock(SmbOpen Owner, ulong Offset, ulong Length, bool Exclusive);

	private sealed class FileLockState
	{
		public List<ActiveLock> Active { get; } = new List<ActiveLock>();

		public List<Waiter> Waiters { get; } = new List<Waiter>();
	}

	private sealed class Waiter(SmbOpen owner, ulong offset, ulong length, bool exclusive, TaskCompletionSource<LockOutcome> tcs)
	{
		public SmbOpen Owner { get; } = owner;

		public ulong Offset { get; } = offset;

		public ulong Length { get; } = length;

		public bool Exclusive { get; } = exclusive;

		public TaskCompletionSource<LockOutcome> Tcs { get; } = tcs;

		public CancellationTokenRegistration Registration { get; set; }
	}

	private readonly Lock _gate = new Lock();

	private readonly Dictionary<string, FileLockState> _files = new Dictionary<string, FileLockState>(StringComparer.OrdinalIgnoreCase);

	public int ActiveLockCount
	{
		get
		{
			lock (_gate)
			{
				var count = 0;
				foreach (var state in _files.Values) count += state.Active.Count;
				return count;
			}
		}
	}

	public int PendingLockCount
	{
		get
		{
			lock (_gate)
			{
				var count = 0;
				foreach (var state in _files.Values) count += state.Waiters.Count;
				return count;
			}
		}
	}

	public Task<LockOutcome> ApplyAsync(SmbOpen owner, IReadOnlyList<LockElement> elements, bool failImmediately, CancellationToken ct)
	{
		if (elements.Count == 0) return Task.FromResult(LockOutcome.Granted);

		var key = FileKey(owner);
		var decisions = new List<(Waiter, LockOutcome)>();
		Waiter? waiter = null;
		LockOutcome outcome;
		FileLockState state;
		lock (_gate)
		{
			state = GetOrAdd(key);
			if (elements[0].Unlock) outcome = ApplyUnlocks(state, owner, elements, decisions);
			else
			{
				var firstNewLock = state.Active.Count;
				outcome = LockOutcome.Granted;
				foreach (var e in elements)
				{
					if (Conflicts(state, owner, e.Offset, e.Length, e.Exclusive))
					{
						outcome = LockOutcome.Conflict;
						break;
					}

					state.Active.Add(new ActiveLock(owner, e.Offset, e.Length, e.Exclusive));
				}

				if (outcome == LockOutcome.Conflict)
				{
					// Only grants from this request are rolled back; earlier locks survive.
					state.Active.RemoveRange(firstNewLock, state.Active.Count - firstNewLock);
					if (!failImmediately && elements.Count == 1)
					{
						var e = elements[0];
						waiter = new Waiter(owner, e.Offset, e.Length, e.Exclusive, new TaskCompletionSource<LockOutcome>(TaskCreationOptions.RunContinuationsAsynchronously));
						state.Waiters.Add(waiter);
					}
				}
			}

			Prune(key, state);
		}

		Finish(decisions);
		if (waiter == null) return Task.FromResult(outcome);

		var registration = ct.Register(() =>
		{
			bool removed;
			lock (_gate)
			{
				removed = state.Waiters.Remove(waiter);
				Prune(key, state);
			}

			if (removed) Finish([(waiter, LockOutcome.Cancelled)]);
		});
		// Register can invoke synchronously, or grant/cancel can win before attachment.
		bool waiting;
		lock (_gate)
		{
			waiting = state.Waiters.Contains(waiter);
			if (waiting) waiter.Registration = registration;
		}

		if (!waiting) registration.Dispose();
		return waiter.Tcs.Task;
	}

	private void Prune(string key, FileLockState state)
	{
		if (state.Active.Count == 0 && state.Waiters.Count == 0 && _files.TryGetValue(key, out var current) && current == state) _files.Remove(key);
	}

	private static void Finish(List<(Waiter Waiter, LockOutcome Outcome)> decisions)
	{
		foreach (var (waiter, outcome) in decisions)
		{
			waiter.Registration.Dispose();
			waiter.Tcs.TrySetResult(outcome);
		}
	}

	public bool HasConflict(SmbOpen owner, IReadOnlyList<LockElement> elements)
	{
		lock (_gate)
		{
			if (!_files.TryGetValue(FileKey(owner), out var state)) return false;
			foreach (var element in elements)
				if (!element.Unlock && Conflicts(state, owner, element.Offset, element.Length, element.Exclusive)) return true;
			return false;
		}
	}

	public bool IsRangeAccessible(SmbOpen owner, ulong offset, ulong length, bool forWrite)
	{
		if (length == 0L)
		{
			return true;
		}

		var key = FileKey(owner);
		lock (_gate)
		{
			if (!_files.TryGetValue(key, out var value))
			{
				return true;
			}

			foreach (var item in value.Active)
			{
				if (Overlaps(offset, length, item.Offset, item.Length) && (item.Exclusive ? item.Owner != owner : forWrite))
				{
					return false;
				}
			}

			return true;
		}
	}

	public void ReleaseOwner(SmbOpen owner)
	{
		var key = FileKey(owner);
		var decisions = new List<(Waiter, LockOutcome)>();
		lock (_gate)
		{
			if (!_files.TryGetValue(key, out var state)) return;

			state.Active.RemoveAll(a => a.Owner == owner);
			for (var i = state.Waiters.Count - 1; i >= 0; i--)
				if (state.Waiters[i].Owner == owner)
				{
					decisions.Add((state.Waiters[i], LockOutcome.Cancelled));
					state.Waiters.RemoveAt(i);
				}

			WakeWaiters(state, decisions);
			Prune(key, state);
		}

		Finish(decisions);
	}

	private LockOutcome ApplyUnlocks(FileLockState state, SmbOpen owner, IReadOnlyList<LockElement> elements, List<(Waiter, LockOutcome)> decisions)
	{
		var outcome = LockOutcome.Granted;
		foreach (var element in elements)
		{
			// MS-SMB2 3.3.5.14.1 retains every successfully unlocked prefix.
			if (element.Shared || element.Exclusive)
			{
				outcome = LockOutcome.InvalidParameter;
				break;
			}

			var num = -1;
			for (var i = 0; i < state.Active.Count; i++)
			{
				var activeLock = state.Active[i];
				if (activeLock.Owner == owner && activeLock.Offset == element.Offset && activeLock.Length == element.Length)
				{
					if (num < 0 || activeLock.Exclusive) num = i;
					if (activeLock.Exclusive) break;
				}
			}

			if (num < 0)
			{
				outcome = LockOutcome.RangeNotLocked;
				break;
			}

			state.Active.RemoveAt(num);
		}

		WakeWaiters(state, decisions);
		return outcome;
	}

	private static void WakeWaiters(FileLockState state, List<(Waiter, LockOutcome)> decisions)
	{
		var num = 0;
		while (num < state.Waiters.Count)
		{
			var waiter = state.Waiters[num];
			if (!Conflicts(state, waiter.Owner, waiter.Offset, waiter.Length, waiter.Exclusive))
			{
				state.Active.Add(new ActiveLock(waiter.Owner, waiter.Offset, waiter.Length, waiter.Exclusive));
				state.Waiters.RemoveAt(num);
				decisions.Add((waiter, LockOutcome.Granted));
			}
			else
			{
				num++;
			}
		}
	}

	private static bool Conflicts(FileLockState state, SmbOpen owner, ulong offset, ulong length, bool exclusive)
	{
		foreach (var item in state.Active)
		{
			// Exclusive acquisition conflicts even with this open's existing locks.
			if (Overlaps(offset, length, item.Offset, item.Length) && (exclusive || item.Exclusive && item.Owner != owner))
			{
				return true;
			}
		}

		return false;
	}

	private static bool Overlaps(ulong aOff, ulong aLen, ulong bOff, ulong bLen)
	{
		if (aOff == 0 && aLen == 0 || bOff == 0 && bLen == 0) return false;
		// A zero-length range at N spans [N, N-1]; it overlaps only a strict interior.
		if (aLen == 0) return bOff < aOff && aOff < bOff + (UInt128)bLen;
		if (bLen == 0) return aOff < bOff && bOff < aOff + (UInt128)aLen;

		var uInt = aOff + (UInt128)aLen;
		var uInt2 = bOff + (UInt128)bLen;
		if (aOff < uInt2)
		{
			return bOff < uInt;
		}

		return false;
	}

	private FileLockState GetOrAdd(string key)
	{
		if (!_files.TryGetValue(key, out var value))
		{
			value = (_files[key] = new FileLockState());
		}

		return value;
	}

	private static string FileKey(SmbOpen owner)
	{
		return owner.IdentityKey;
	}
}
