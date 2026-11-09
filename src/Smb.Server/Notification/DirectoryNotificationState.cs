using System;
using System.Collections.Generic;
using System.Threading;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;

namespace Smb.Server.Notification;

/// <summary>One subscription and bounded FIFO per directory open; first request selects the policy.</summary>
public sealed class DirectoryNotificationState : IDisposable
{
	public readonly record struct Result(NtStatus Status, byte[] Body);

	private sealed class Waiter(uint size, Action<Result> callback)
	{
		public readonly uint Size = size;
		public readonly Action<Result> Callback = callback;
	}

	private readonly Lock _gate = new Lock();
	private readonly List<(uint, string)> _events = new List<(uint, string)>();
	private readonly List<Waiter> _waiters = new List<Waiter>();
	private readonly ChangeNotifyFilter _filter;
	private readonly int _capacity;
	private readonly Lazy<bool> _initialize;
	private IDisposable? _watcher;
	private bool _closed;
	private bool _deleted;
	private readonly bool _subtree;
	private int _bytes;
	private NtStatus? _error;

	public DirectoryNotificationState(IDirectoryWatcher watcher, string path, bool subtree, uint filter, uint capacity)
	{
		_subtree = subtree;
		_filter = (ChangeNotifyFilter)(filter & 0xfff);
		_capacity = (int)Math.Min(capacity, 65536u);
		_initialize = new Lazy<bool>(() =>
		{
			var subscription = watcher.Watch(path, subtree, _filter, Changes, Error);
			bool dispose;
			lock (_gate)
			{
				dispose = _closed;
				if (!dispose) _watcher = subscription;
			}

			if (dispose) subscription?.Dispose();
			return subscription != null;
		});
	}

	public bool Initialize() => _initialize.Value;

	public bool TryTake(uint size, out Result result)
	{
		lock (_gate)
		{
			if (_waiters.Count != 0 || (_events.Count == 0 && !_error.HasValue && !_deleted))
			{
				result = default;
				return false;
			}

			result = Take(size);
			return true;
		}
	}

	public IDisposable Wait(uint size, Action<Result> callback)
	{
		var waiter = new Waiter(size, callback);
		List<(Action<Result>, Result)> ready;
		lock (_gate)
		{
			_waiters.Add(waiter);
			ready = Drain();
		}

		Deliver(ready);
		return new Removal(this, waiter);
	}

	private sealed class Removal(DirectoryNotificationState state, Waiter waiter) : IDisposable
	{
		public void Dispose()
		{
			lock (state._gate) state._waiters.Remove(waiter);
		}
	}

	// Process-memory metadata cannot be observed by the native filesystem watcher.
	// The caller supplies current acquired-open paths, so a renamed watched directory
	// and a renamed child are evaluated in the same namespace as the successful SET.
	internal void Publish(string directoryPath, string changedPath, ChangeNotifyFilter filter)
	{
		if ((_filter & filter) == 0) return;
		var relative = System.IO.Path.GetRelativePath(directoryPath, changedPath);
		if (relative == "." || relative == ".." || System.IO.Path.IsPathRooted(relative) ||
		    relative.StartsWith(".." + System.IO.Path.DirectorySeparatorChar, StringComparison.Ordinal)) return;
		if (!_subtree && relative.IndexOfAny([System.IO.Path.DirectorySeparatorChar, System.IO.Path.AltDirectorySeparatorChar]) >= 0) return;
		Changes([new FileNotifyEvent(FileNotifyAction.Modified, relative.Replace('/', '\\'))]);
	}

	internal void MarkDeleted(bool permanent)
	{
		List<(Action<Result>, Result)> ready = new();
		lock (_gate)
		{
			if (_closed || _deleted) return;
			_deleted = permanent;
			_events.Clear();
			_bytes = 0;
			_error = null;
			foreach (var waiter in _waiters)
				ready.Add((waiter.Callback, new Result((NtStatus)0xc0000056, ErrorResponse.BuildBody())));
			_waiters.Clear();
		}
		Deliver(ready);
	}

	private void Changes(IReadOnlyList<FileNotifyEvent> changes)
	{
		List<(Action<Result>, Result)> ready;
		lock (_gate)
		{
			if (_closed || _deleted || _filter == 0) return;

			foreach (var change in changes)
			{
				var bytes = checked(12 + System.Text.Encoding.Unicode.GetByteCount(change.RelativeName) + 3) & ~3;
				if (_error.HasValue) break;

				if (bytes > _capacity - _bytes)
				{
					_events.Clear();
					_bytes = 0;
					_error = NtStatus.NotifyEnumDir;
					break;
				}

				_events.Add(((uint)change.Action, change.RelativeName));
				_bytes += bytes;
			}

			ready = Drain();
		}

		Deliver(ready);
	}

	private void Error(NtStatus status)
	{
		List<(Action<Result>, Result)> ready;
		lock (_gate)
		{
			if (_closed || _deleted || _filter == 0) return;

			_events.Clear();
			_bytes = 0;
			_error = status;
			ready = Drain();
		}

		Deliver(ready);
	}

	private Result Take(uint size)
	{
		if (_deleted) return new Result((NtStatus)0xc0000056, ErrorResponse.BuildBody());
		if (_error is { } error)
		{
			_error = null;
			return new Result(error, (uint)error >= 0x80000000 ? ErrorResponse.BuildBody() : ChangeNotifyMessage.BuildResponseBody(Array.Empty<(uint, string)>(), 0).body);
		}

		var (body, overflow) = ChangeNotifyMessage.BuildResponseBody(_events, size);
		_events.Clear();
		_bytes = 0;
		return new Result(overflow ? NtStatus.NotifyEnumDir : NtStatus.Success, body);
	}

	private List<(Action<Result>, Result)> Drain()
	{
		var ready = new List<(Action<Result>, Result)>();
		while (_waiters.Count > 0 && (_events.Count > 0 || _error.HasValue || _deleted))
		{
			var first = _waiters[0];
			_waiters.RemoveAt(0);
			ready.Add((first.Callback, Take(first.Size)));
		}

		return ready;
	}

	private static void Deliver(List<(Action<Result>, Result)> ready)
	{
		foreach (var (callback, result) in ready) callback(result);
	}

	public void Dispose()
	{
		IDisposable? subscription;
		lock (_gate)
		{
			if (_closed) return;

			_closed = true;
			subscription = _watcher;
			_watcher = null;
			_events.Clear();
			_waiters.Clear();
			_bytes = 0;
		}

		subscription?.Dispose();
	}
}
