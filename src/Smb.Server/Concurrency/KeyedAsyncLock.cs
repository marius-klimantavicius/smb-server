using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Smb.Server.Concurrency;

public sealed class KeyedAsyncLock<TKey> where TKey : notnull
{
	internal sealed class Entry
	{
		public readonly SemaphoreSlim Semaphore = new SemaphoreSlim(1, 1);

		public int RefCount;
	}

	public readonly struct Releaser : IDisposable
	{
		private readonly KeyedAsyncLock<TKey>? _owner;

		private readonly TKey _key;

		private readonly Entry _entry;

		internal Releaser(KeyedAsyncLock<TKey> owner, TKey key, Entry entry)
		{
			_owner = owner;
			_key = key;
			_entry = entry;
		}

		public void Dispose()
		{
			_owner?.Release(_key, _entry, semaphoreWasTaken: true);
		}
	}

	private readonly Dictionary<TKey, Entry> _entries;

	private readonly Lock _gate = new Lock();

	public int TrackedKeyCount
	{
		get
		{
			lock (_gate)
			{
				return _entries.Count;
			}
		}
	}

	public KeyedAsyncLock(IEqualityComparer<TKey>? comparer = null)
	{
		_entries = new Dictionary<TKey, Entry>(comparer);
	}

	public async ValueTask<Releaser> AcquireAsync(TKey key, CancellationToken cancellationToken = default(CancellationToken))
	{
		Entry entry;
		lock (_gate)
		{
			if (!_entries.TryGetValue(key, out entry))
			{
				entry = new Entry();
				_entries[key] = entry;
			}

			entry.RefCount++;
		}

		try
		{
			await entry.Semaphore.WaitAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
		}
		catch
		{
			Release(key, entry, semaphoreWasTaken: false);
			throw;
		}

		return new Releaser(this, key, entry);
	}

	private void Release(TKey key, Entry entry, bool semaphoreWasTaken)
	{
		if (semaphoreWasTaken)
		{
			entry.Semaphore.Release();
		}

		lock (_gate)
		{
			if (--entry.RefCount == 0)
			{
				_entries.Remove(key);
				entry.Semaphore.Dispose();
			}
		}
	}
}
