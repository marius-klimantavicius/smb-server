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

	public Task<LockOutcome> ApplyAsync(SmbOpen owner, IReadOnlyList<LockElement> elements, bool failImmediately, CancellationToken ct)
	{
		if (elements.Count == 0)
		{
			return Task.FromResult(LockOutcome.Granted);
		}

		var key = FileKey(owner);
		lock (_gate)
		{
			var state = GetOrAdd(key);
			if (elements[0].Unlock)
			{
				return Task.FromResult(ApplyUnlocks(state, owner, elements));
			}

			var flag = false;
			foreach (var element in elements)
			{
				if (Conflicts(state, owner, element.Offset, element.Length, element.Exclusive))
				{
					flag = true;
					break;
				}
			}

			if (!flag)
			{
				foreach (var element2 in elements)
				{
					state.Active.Add(new ActiveLock(owner, element2.Offset, element2.Length, element2.Exclusive));
				}

				return Task.FromResult(LockOutcome.Granted);
			}

			if (failImmediately || elements.Count != 1)
			{
				return Task.FromResult(LockOutcome.Conflict);
			}

			var lockElement = elements[0];
			var tcs = new TaskCompletionSource<LockOutcome>(TaskCreationOptions.RunContinuationsAsynchronously);
			var waiter = new Waiter(owner, lockElement.Offset, lockElement.Length, lockElement.Exclusive, tcs);
			state.Waiters.Add(waiter);
			waiter.Registration = ct.Register(() =>
			{
				lock (_gate)
				{
					if (!state.Waiters.Remove(waiter))
					{
						return;
					}
				}

				tcs.TrySetResult(LockOutcome.Cancelled);
			});
			return tcs.Task;
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
				if (item.Owner != owner && Overlaps(offset, length, item.Offset, item.Length) && (forWrite || item.Exclusive))
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
		lock (_gate)
		{
			if (!_files.TryGetValue(key, out var value))
			{
				return;
			}

			value.Active.RemoveAll(a => a.Owner == owner);
			for (var num = value.Waiters.Count - 1; num >= 0; num--)
			{
				if (value.Waiters[num].Owner == owner)
				{
					var waiter = value.Waiters[num];
					value.Waiters.RemoveAt(num);
					waiter.Registration.Dispose();
					waiter.Tcs.TrySetResult(LockOutcome.Cancelled);
				}
			}

			WakeWaiters(value);
			if (value.Active.Count == 0 && value.Waiters.Count == 0)
			{
				_files.Remove(key);
			}
		}
	}

	private LockOutcome ApplyUnlocks(FileLockState state, SmbOpen owner, IReadOnlyList<LockElement> elements)
	{
		var list = new List<int>(elements.Count);
		foreach (var element in elements)
		{
			var num = -1;
			for (var i = 0; i < state.Active.Count; i++)
			{
				var activeLock = state.Active[i];
				if (activeLock.Owner == owner && activeLock.Offset == element.Offset && activeLock.Length == element.Length && !list.Contains(i))
				{
					num = i;
					break;
				}
			}

			if (num < 0)
			{
				return LockOutcome.RangeNotLocked;
			}

			list.Add(num);
		}

		list.Sort();
		for (var num2 = list.Count - 1; num2 >= 0; num2--)
		{
			state.Active.RemoveAt(list[num2]);
		}

		WakeWaiters(state);
		return LockOutcome.Granted;
	}

	private static void WakeWaiters(FileLockState state)
	{
		var num = 0;
		while (num < state.Waiters.Count)
		{
			var waiter = state.Waiters[num];
			if (!Conflicts(state, waiter.Owner, waiter.Offset, waiter.Length, waiter.Exclusive))
			{
				state.Active.Add(new ActiveLock(waiter.Owner, waiter.Offset, waiter.Length, waiter.Exclusive));
				state.Waiters.RemoveAt(num);
				waiter.Registration.Dispose();
				waiter.Tcs.TrySetResult(LockOutcome.Granted);
			}
			else
			{
				num++;
			}
		}
	}

	private static bool Conflicts(FileLockState state, SmbOpen owner, ulong offset, ulong length, bool exclusive)
	{
		if (length == 0L)
		{
			return false;
		}

		foreach (var item in state.Active)
		{
			if (item.Owner != owner && Overlaps(offset, length, item.Offset, item.Length) && (exclusive || item.Exclusive))
			{
				return true;
			}
		}

		return false;
	}

	private static bool Overlaps(ulong aOff, ulong aLen, ulong bOff, ulong bLen)
	{
		if (aLen == 0L || bLen == 0L)
		{
			return false;
		}

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
		return owner.LocalOpen?.PhysicalPath ?? owner.PathName;
	}
}
