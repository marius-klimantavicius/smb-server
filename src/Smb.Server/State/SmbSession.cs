using System;
using System.Collections.Concurrent;
using System.Threading;
using Smb.Auth;
using Smb.Crypto;

namespace Smb.Server.State;

public sealed class SmbSession
{
	private long _encryptionNonce;

	public required ulong SessionId { get; init; }

	public required ulong SessionGlobalId { get; init; }

	public required SmbConnection Connection { get; init; }

	public SessionState State { get; set; }

	public long LastActivityTicks { get; set; }

	public ISpnegoServerContext? AuthContext { get; set; }

	public SecurityIdentity? Identity { get; set; }

	public bool IsAnonymous { get; set; }

	public bool IsGuest { get; set; }

	public bool SigningRequired { get; set; }

	public bool EncryptData { get; set; }

	public byte[] FullSessionKey { get; set; } = Array.Empty<byte>();

	public byte[] SessionKey { get; set; } = Array.Empty<byte>();

	public byte[] SigningKey { get; set; } = Array.Empty<byte>();

	public byte[] EncryptionKey { get; set; } = Array.Empty<byte>();

	public byte[] DecryptionKey { get; set; } = Array.Empty<byte>();

	public byte[] ApplicationKey { get; set; } = Array.Empty<byte>();

	public PreauthIntegrityHash? PreauthHash { get; set; }

	public ConcurrentDictionary<ulong, SmbTreeConnect> TreeConnects { get; } = new ConcurrentDictionary<ulong, SmbTreeConnect>();

	public ConcurrentDictionary<(ulong Persistent, ulong Volatile), SmbOpen> Opens { get; } = new ConcurrentDictionary<(ulong, ulong), SmbOpen>();

	public ConcurrentDictionary<Guid, SmbChannel> Channels { get; } = new ConcurrentDictionary<Guid, SmbChannel>();

	public DateTimeOffset CreationTime { get; } = DateTimeOffset.UtcNow;

	public byte[] SigningKeyFor(SmbConnection connection)
	{
		if (!Channels.TryGetValue(connection.ConnectionId, out var value))
		{
			return SigningKey;
		}

		return value.SigningKey;
	}

	public SmbConnection? SelectSendChannel(SmbConnection? preferred = null)
	{
		if (preferred != null && preferred.SendRawAsync != null)
		{
			return preferred;
		}

		foreach (var value in Channels.Values)
		{
			if (value.Connection.SendRawAsync != null)
			{
				return value.Connection;
			}
		}

		return null;
	}

	public ulong NextEncryptionNonce()
	{
		return (ulong)Interlocked.Increment(ref _encryptionNonce);
	}
}
