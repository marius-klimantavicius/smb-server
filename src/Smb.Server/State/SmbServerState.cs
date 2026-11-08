using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Smb.Auth;
using Smb.Protocol.Enums;
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

	public CreateReplayRegistry CreateReplays { get; } = new CreateReplayRegistry();

	public SmbServerOptions Options { get; }

	public ShareCollection Shares { get; }

	public ConcurrentDictionary<ulong, SmbSession> SessionGlobalList { get; } = new ConcurrentDictionary<ulong, SmbSession>();

	public ConcurrentDictionary<Guid, SmbConnection> Connections { get; } = new ConcurrentDictionary<Guid, SmbConnection>();

	public WitnessRegistrationStore WitnessRegistrations { get; } = new WitnessRegistrationStore();

	private sealed class ClientEntry
	{
		internal SmbDialect Dialect;
		internal readonly HashSet<Guid> Connections = new HashSet<Guid>();
	}
	private readonly Lock _clientGate = new Lock();
	private readonly Dictionary<Guid, ClientEntry> _clients = new Dictionary<Guid, ClientEntry>();

	internal void RegisterClientConnection(SmbConnection connection)
	{
		if (connection.Dialect == SmbDialect.Smb202) return;
		lock (_clientGate)
		{
			var guid = new Guid(connection.ClientGuid);
			if (!_clients.TryGetValue(guid, out var client)) _clients.Add(guid, client = new ClientEntry());
			client.Connections.Add(connection.ConnectionId);
		}
	}

	internal bool AcceptClientDialect(SmbConnection connection)
	{
		if (connection.Dialect == SmbDialect.Smb202) return true;
		lock (_clientGate)
		{
			var guid = new Guid(connection.ClientGuid);
			if (!_clients.TryGetValue(guid, out var client)) _clients.Add(guid, client = new ClientEntry());
			client.Connections.Add(connection.ConnectionId);
			if (client.Dialect != SmbDialect.None && client.Dialect != connection.Dialect) return false;
			client.Dialect = connection.Dialect;
			return true;
		}
	}

	internal void UnregisterClientConnection(SmbConnection connection)
	{
		if (connection.Dialect == SmbDialect.Smb202) return;
		lock (_clientGate)
		{
			var guid = new Guid(connection.ClientGuid);
			if (_clients.TryGetValue(guid, out var client) && client.Connections.Remove(connection.ConnectionId) && client.Connections.Count == 0)
				_clients.Remove(guid);
		}
	}

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
