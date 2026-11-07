using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Smb.Auth;
using Smb.FileSystem;
using Smb.Server.Authorization;
using Smb.Server.Durable;
using Smb.Server.Witness;

namespace Smb.Server.State;

public sealed class SmbServerState
{
	private long _sessionIdCounter;

	private long _sessionGlobalIdCounter;

	private long _persistentIdCounter;

	public SmbServerOptions Options { get; }

	public ShareCollection Shares { get; }

	public ConcurrentDictionary<ulong, SmbSession> SessionGlobalList { get; } = new ConcurrentDictionary<ulong, SmbSession>();

	public ConcurrentDictionary<Guid, SmbConnection> Connections { get; } = new ConcurrentDictionary<Guid, SmbConnection>();

	public WitnessRegistrationStore WitnessRegistrations { get; } = new WitnessRegistrationStore();

	public SmbServerState(SmbServerOptions options)
	{
		Options = options;
		Shares = options.Shares;
		if (options.DurableHandleStore is IPersistentHandleStore persistentHandleStore)
		{
			_persistentIdCounter = (long)(persistentHandleStore.HighestPersistentId & 0x7FFFFFFFFFFFFFFFL);
		}
	}

	public IReadOnlyList<IShare> GetVisibleShares(SecurityIdentity identity, SmbConnection? connection = null)
	{
		var list = new List<IShare>();
		foreach (var item in Shares.All)
		{
			var context = new ShareAccessContext
			{
				Identity = identity,
				Share = item,
				Connection = connection,
			};
			if (Options.ShareAccessPolicy.IsVisible(context))
			{
				list.Add(item);
			}
		}

		return list;
	}

	public async ValueTask<IReadOnlyList<IShare>> GetVisibleSharesAsync(SecurityIdentity identity, SmbConnection? connection = null)
	{
		var result = new List<IShare>();
		foreach (var share in Shares.All)
		{
			var context = new ShareAccessContext
			{
				Identity = identity,
				Share = share,
				Connection = connection,
			};
			if (await Options.ShareAccessPolicy.IsVisibleAsync(context).ConfigureAwait(continueOnCapturedContext: false))
			{
				result.Add(share);
			}
		}

		return result;
	}

	public ulong AllocateSessionId()
	{
		ulong num;
		do
		{
			num = (ulong)Interlocked.Increment(ref _sessionIdCounter);
		} while (num == 0L);

		return num;
	}

	public ulong AllocateSessionGlobalId()
	{
		return (ulong)Interlocked.Increment(ref _sessionGlobalIdCounter);
	}

	public ulong AllocatePersistentId()
	{
		return (ulong)(long.MinValue | Interlocked.Increment(ref _persistentIdCounter));
	}
}
