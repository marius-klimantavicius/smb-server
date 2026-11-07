using System;
using System.Collections.Generic;
using System.Threading;

namespace Smb.Server.Witness;

public sealed class WitnessNotificationChannel
{
	private sealed class Detacher(WitnessNotificationChannel owner, Action<WitnessNotification> waiter) : IDisposable
	{
		public void Dispose()
		{
			owner.Detach(waiter);
		}
	}

	private sealed class NoopDisposable : IDisposable
	{
		public static readonly NoopDisposable Instance = new NoopDisposable();

		public void Dispose()
		{
		}
	}

	private const int MaxBuffered = 64;

	private readonly Lock _gate = new Lock();

	private readonly Queue<WitnessNotification> _pending = new Queue<WitnessNotification>();

	private Action<WitnessNotification>? _waiter;

	public IDisposable Wait(Action<WitnessNotification> onNotify)
	{
		lock (_gate)
		{
			if (_pending.Count == 0)
			{
				_waiter = onNotify;
				return new Detacher(this, onNotify);
			}

			var n = _pending.Dequeue();
			ThreadPool.QueueUserWorkItem(_ =>
			{
				onNotify(n);
			});
			return NoopDisposable.Instance;
		}
	}

	public void Push(WitnessNotification notification)
	{
		Action<WitnessNotification> waiter;
		lock (_gate)
		{
			if (_waiter == null)
			{
				if (_pending.Count < MaxBuffered)
				{
					_pending.Enqueue(notification);
				}

				return;
			}

			waiter = _waiter;
			_waiter = null;
		}

		waiter(notification);
	}

	private void Detach(Action<WitnessNotification> waiter)
	{
		lock (_gate)
		{
			if ((object)_waiter == waiter)
			{
				_waiter = null;
			}
		}
	}
}
