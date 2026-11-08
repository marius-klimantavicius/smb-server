using System;
using System.Collections.Concurrent;
using System.Threading;
using Smb.Auth;
using Smb.Crypto;

namespace Smb.Server.State;

public sealed class SmbSession
{
	private long _encryptionNonce;
	private readonly Lock _idGate = new Lock();
	private ulong _treeIdCounter;
	private ulong _fileIdCounter;
	public OpenLifetime Lifetime { get; } = new OpenLifetime();

	// Monotonic, never reuse or wrap. Exhaustion requires a new session.
	public ulong AllocateTreeId()
	{
		lock (_idGate)
		{
			do
			{
				if (_treeIdCounter >= uint.MaxValue - 1UL) throw new InvalidOperationException("TreeId namespace exhausted.");

				_treeIdCounter++;
			} while (TreeConnects.ContainsKey(_treeIdCounter));

			return _treeIdCounter;
		}
	}

	public ulong AllocateFileId()
	{
		lock (_idGate)
		{
			do
			{
				if (_fileIdCounter >= ulong.MaxValue - 1) throw new InvalidOperationException("FileId namespace exhausted.");

				_fileIdCounter++;
			} while (System.Linq.Enumerable.Any(Opens.Keys, k => k.Volatile == _fileIdCounter));

			return _fileIdCounter;
		}
	}

	private readonly Lock _admissionGate = new Lock();
	private int _provisional;

	public int ProvisionalOpenCount
	{
		get
		{
			lock (_admissionGate) return _provisional;
		}
	}

	public IDisposable? TryReserveOpen(int maximum)
	{
		lock (_admissionGate)
		{
			if (Lifetime.State != OpenState.Active || (maximum > 0 && Opens.Count + _provisional >= maximum)) return null;

			_provisional++;
			return new Admission(this);
		}
	}

	private sealed class Admission(SmbSession session) : IDisposable
	{
		private SmbSession? _session = session;

		public void Dispose()
		{
			var s = Interlocked.Exchange(ref _session, null);
			if (s != null)
				lock (s._admissionGate)
					s._provisional--;
		}
	}

	public required ulong SessionId { get; init; }

	public required ulong SessionGlobalId { get; init; }

	public required SmbConnection Connection { get; set; }

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

	private readonly Lock _channelGate = new Lock();

	private bool _channelsClosing;

	// Only channel-set publication/retirement is serialized. No backend work or await under this gate.
	public bool TryAttachChannel(SmbChannel channel)
	{
		var connection = channel.Connection;
		lock (_channelGate)
		{
			if (_channelsClosing || Lifetime.State != OpenState.Active || connection.ResponseSendFailed || connection.MustTerminate) return false;
			if (Channels.ContainsKey(connection.ConnectionId)) return false;

			var added = connection.Sessions.TryAdd(SessionId, this);
			if (!added && (!connection.Sessions.TryGetValue(SessionId, out var current) || !ReferenceEquals(current, this))) return false;
			if (Channels.TryAdd(connection.ConnectionId, channel)) return true;

			if (added) connection.Sessions.TryRemove(new System.Collections.Generic.KeyValuePair<ulong, SmbSession>(SessionId, this));
			return false;
		}
	}

	// Claims final loss before physical retirement, so a late binder cannot revive this session.
	public bool DetachChannel(SmbConnection connection)
	{
		lock (_channelGate)
		{
			Channels.TryRemove(connection.ConnectionId, out _);
			if (!Channels.IsEmpty)
			{
				if (ReferenceEquals(Connection, connection)) Connection = System.Linq.Enumerable.First(Channels.Values).Connection;
				return false;
			}

			_channelsClosing = true;
			return true;
		}
	}

	public void StopChannelAdmission()
	{
		lock (_channelGate) _channelsClosing = true;
	}

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
		if (preferred != null && IsLiveSendChannel(preferred))
		{
			return preferred;
		}

		foreach (var value in Channels.Values)
		{
			if (IsLiveSendChannel(value.Connection))
			{
				return value.Connection;
			}
		}

		return null;
	}

	private bool IsLiveSendChannel(SmbConnection connection) =>
		!connection.ResponseSendFailed && !connection.MustTerminate && connection.SendRawAsync != null &&
		(connection.Dialect < Protocol.Enums.SmbDialect.Smb300
			? ReferenceEquals(Connection, connection) && connection.Sessions.ContainsKey(SessionId)
			: Channels.TryGetValue(connection.ConnectionId, out var channel) && ReferenceEquals(channel.Connection, connection));

	public ulong NextEncryptionNonce()
	{
		return (ulong)Interlocked.Increment(ref _encryptionNonce);
	}
}
