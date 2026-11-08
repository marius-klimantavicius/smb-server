using System;
using System.Threading;
using System.Threading.Tasks;

namespace Smb.Server.State;

public enum OpenState
{
	Provisional,
	Active,
	Disconnecting,
	Disconnected,
	Reconnecting,
	Closing,
	Closed
}

/// <summary>Short state transitions; no monitor is held while awaiting backend operations.</summary>
public sealed class OpenLifetime
{
	private readonly Lock _gate = new Lock();
	private OpenState _state;
	private int _operations;
	private TaskCompletionSource _drained = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
	private readonly TaskCompletionSource _closed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
	public OpenLifetime(bool active = true) => _state = active ? OpenState.Active : OpenState.Provisional;

	public OpenState State
	{
		get
		{
			lock (_gate) return _state;
		}
	}

	public void Activate()
	{
		lock (_gate)
		{
			if (_state != OpenState.Provisional) throw new InvalidOperationException("Open is no longer provisional.");

			_state = OpenState.Active;
		}
	}

	public IDisposable? TryAcquire()
	{
		lock (_gate)
		{
			if (_state != OpenState.Active) return null;

			_operations++;
			return new Reference(this);
		}
	}

	public bool BeginReconnect()
	{
		lock (_gate)
		{
			if (_state != OpenState.Disconnected) return false;

			_state = OpenState.Reconnecting;
			return true;
		}
	}

	public void CompleteReconnect(bool committed)
	{
		lock (_gate)
		{
			if (_state != OpenState.Reconnecting) throw new InvalidOperationException("Reconnect lost lifetime ownership.");

			_state = committed ? OpenState.Active : OpenState.Disconnected;
			if (committed) _drained = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
		}
	}

	public bool BeginDisconnect(out Task drained)
	{
		lock (_gate)
		{
			drained = _drained.Task;
			if (_state != OpenState.Active) return false;

			_state = OpenState.Disconnecting;
			if (_operations == 0) _drained.TrySetResult();
			return true;
		}
	}

	public bool CompleteDisconnect()
	{
		lock (_gate)
		{
			if (_state != OpenState.Disconnecting) return false;

			_state = OpenState.Disconnected;
			return true;
		}
	}

	public bool BeginClose(out Task drained)
	{
		lock (_gate)
		{
			if (_state is OpenState.Closing or OpenState.Closed)
			{
				drained = _closed.Task;
				return false;
			}

			_state = OpenState.Closing;
			if (_operations == 0) _drained.TrySetResult();
			drained = _drained.Task;
			return true;
		}
	}

	public void CompleteClose()
	{
		lock (_gate)
		{
			_state = OpenState.Closed;
			_closed.TrySetResult();
		}
	}

	private void Release()
	{
		lock (_gate)
		{
			if (--_operations == 0 && _state is OpenState.Closing or OpenState.Disconnecting) _drained.TrySetResult();
		}
	}

	private sealed class Reference(OpenLifetime owner) : IDisposable
	{
		private OpenLifetime? _owner = owner;
		public void Dispose() => Interlocked.Exchange(ref _owner, null)?.Release();
	}
}
