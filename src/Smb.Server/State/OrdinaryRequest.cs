using System;
using System.Threading;
using System.Threading.Tasks;

namespace Smb.Server.State;

/// <summary>Response cancellation and physical backend drain have separate lifetimes.</summary>
public sealed class OrdinaryRequest(SmbOpen? owner) : IDisposable
{
	private readonly CancellationTokenSource _cts = new CancellationTokenSource();
	private readonly TaskCompletionSource _physical = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
	private int _disposed;
	private SmbOpen? _owner = owner;
	public SmbOpen? Owner => Volatile.Read(ref _owner);
	internal void BindOwner(SmbOpen open) => Volatile.Write(ref _owner, open);
	public CancellationToken Token => _cts.Token;
	public Task PhysicalFinished => _physical.Task;

	public void Cancel()
	{
		try { _cts.Cancel(); }
		catch (ObjectDisposedException) { }
	}

	public void Dispose()
	{
		if (Interlocked.Exchange(ref _disposed, 1) == 0)
		{
			_physical.TrySetResult();
			_cts.Dispose();
		}
	}
}
