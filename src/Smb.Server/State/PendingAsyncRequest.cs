using System;
using System.Threading;

namespace Smb.Server.State;

public sealed class PendingAsyncRequest
{
	private readonly CancellationTokenSource _cts = new CancellationTokenSource();

	public required ulong MessageId { get; init; }

	public required ulong AsyncId { get; init; }

	public SmbOpen? Owner { get; init; }

	public CancellationToken Token => _cts.Token;

	public void Cancel()
	{
		try
		{
			_cts.Cancel();
		}
		catch (ObjectDisposedException)
		{
		}
	}
}
