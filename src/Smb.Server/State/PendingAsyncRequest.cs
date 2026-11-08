using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Smb.Protocol.Enums;

namespace Smb.Server.State;

public enum PendingRequestState
{
	Registered,
	InterimCommitted,
	Completing,
	Completed,
	Abandoned
}

/// <summary>Owns one pending response. Publication precedes callbacks; only the sender commits an interim.</summary>
public sealed class PendingAsyncRequest
{
	private readonly Lock _gate = new Lock();
	private readonly CancellationTokenSource _cts = new CancellationTokenSource();
	private readonly CancellationToken _token;
	public PendingAsyncRequest() { _token = _cts.Token; }
	private readonly List<IDisposable> _resources = new List<IDisposable>();
	private PendingRequestState _state;
	private Func<Task>? _completion;
	private int _cancellationStatus;
	private Action? _remove;
	private readonly TaskCompletionSource _interim = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
	public Task InterimTransmitted => _interim.Task;
	public NtStatus FinalStatus { get; private set; }
	public byte[] FinalBody { get; private set; } = Array.Empty<byte>();
	internal bool ReservedForContinuation;
	private readonly TaskCompletionSource _finished = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

	public PendingRequestState State
	{
		get
		{
			lock (_gate) return _state;
		}
	}

	public Task Finished => _finished.Task;
	public NtStatus? CloseStatus { get; init; }
	public NtStatus CancellationStatus => (NtStatus)unchecked((uint)Volatile.Read(ref _cancellationStatus));
	public required ulong MessageId { get; init; }
	public required ulong AsyncId { get; init; }
	public SmbOpen? Owner { get; set; }
	public CancellationToken Token => _token;
	internal void OnRemove(Action remove) => _remove = remove;

	public void Attach(IDisposable resource)
	{
		bool dispose;
		lock (_gate)
		{
			dispose = _state is PendingRequestState.Completed or PendingRequestState.Abandoned;
			if (!dispose) _resources.Add(resource);
		}

		if (dispose) resource.Dispose();
	}

	public bool Complete(NtStatus status, byte[] body, Func<Task> completion)
	{
		bool run;
		lock (_gate)
		{
			if (_completion != null || _state is PendingRequestState.Completed or PendingRequestState.Abandoned) return false;

			FinalStatus = status;
			FinalBody = body;
			_completion = completion;
			run = _state == PendingRequestState.InterimCommitted;
			if (run) _state = PendingRequestState.Completing;
		}

		if (run) _ = RunAsync();
		return true;
	}

	public void CommitInterim()
	{
		bool run;
		lock (_gate)
		{
			if (_state != PendingRequestState.Registered) return;

			run = _completion != null;
			_state = run ? PendingRequestState.Completing : PendingRequestState.InterimCommitted;
		}

		_interim.TrySetResult();
		if (run) _ = RunAsync();
	}

	private async Task RunAsync()
	{
		try
		{
			await _completion!().ConfigureAwait(false);
			Finish(false);
		}
		catch { Abandon(); }
	}

	public void Abandon()
	{
		Finish(true);
	}

	private void Finish(bool abandoned)
	{
		IDisposable[] resources;
		lock (_gate)
		{
			if (_state is PendingRequestState.Completed or PendingRequestState.Abandoned) return;

			_state = abandoned ? PendingRequestState.Abandoned : PendingRequestState.Completed;
			resources = _resources.ToArray();
			_resources.Clear();
		}

		if (abandoned)
		{
			try { Cancel(); }
			catch
			{
				/* Teardown continues after a fallible consumer callback. */
			}
		}

		_remove?.Invoke();
		foreach (var resource in resources)
		{
			try { resource.Dispose(); }
			catch
			{
				// ignored
			}
		}

		_cts.Dispose();
		_interim.TrySetResult();
		_finished.TrySetResult();
	}

	public void Cancel() => CancelWithStatus(NtStatus.Cancelled);
	public void CancelForClose() => CancelWithStatus(CloseStatus ?? NtStatus.Cancelled);

	private void CancelWithStatus(NtStatus status)
	{
		Interlocked.CompareExchange(ref _cancellationStatus, unchecked((int)status), 0);
		try { _cts.Cancel(); }
		catch (ObjectDisposedException) { }
	}
}
