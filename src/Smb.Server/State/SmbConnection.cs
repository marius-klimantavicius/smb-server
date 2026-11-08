using System;
using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Smb.Auth;
using Smb.Crypto;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;

namespace Smb.Server.State;

public sealed class SmbConnection
{
	private long _treeIdCounter;
	private readonly Lock _legacyIdGate = new Lock();

	private long _fileIdCounter;

	private long _asyncIdCounter;

	public Guid ConnectionId { get; } = Guid.NewGuid();

	public string? ClientAddress { get; set; }

	public bool IsTransportSecured { get; set; }

	public X509Certificate2? ClientCertificate { get; set; }

	public SecurityIdentity? TransportAssertedIdentity { get; set; }

	public long LastActivityTicks { get; set; }

	public long CreatedTicks { get; set; }

	public Action? RequestClose { get; set; }

	public bool ResponseSendFailed { get; set; }

	public SmbDialect Dialect { get; set; }

	public bool NegotiateDone { get; set; }

	public bool MustTerminate { get; set; }

	public byte[] ClientGuid { get; set; } = new byte[16];

	public Smb2Capabilities ClientCapabilities { get; set; }

	public Smb2Capabilities ServerCapabilities { get; set; }

	public SmbSecurityMode ClientSecurityMode { get; set; }

	public SmbSecurityMode ServerSecurityMode { get; set; }

	public bool ShouldSign { get; set; }

	public bool SupportsEncryption { get; set; }

	public bool SupportsMultiCredit { get; set; }

	public uint MaxReadSize { get; set; } = 65536u;

	public uint MaxWriteSize { get; set; } = 65536u;

	public uint MaxTransactSize { get; set; } = 65536u;

	public PreauthHashAlgorithm PreauthIntegrityHashId { get; set; } = PreauthHashAlgorithm.Sha512;

	public SmbCipherId CipherId { get; set; }

	public SmbSigningAlgorithmId SigningAlgorithmId { get; set; }

	public SmbCompressionAlgorithm CompressionAlgorithm { get; set; }

	public PreauthIntegrityHash PreauthHash { get; } = new PreauthIntegrityHash();

	public ConcurrentDictionary<ulong, SmbSession> Sessions { get; } = new ConcurrentDictionary<ulong, SmbSession>();

	public ConcurrentDictionary<ulong, ChannelBindInProgress> PendingBindings { get; } = new ConcurrentDictionary<ulong, ChannelBindInProgress>();

	public DateTimeOffset CreationTime { get; } = DateTimeOffset.UtcNow;

	public CreditSequenceLedger Credits { get; } = new CreditSequenceLedger();

	public ushort OutstandingRequestCount { get; set; }

	public Func<byte[], bool, Task>? SendRawAsync { get; set; }

	public ConcurrentDictionary<ulong, PendingAsyncRequest> PendingRequests { get; } = new ConcurrentDictionary<ulong, PendingAsyncRequest>();

	public ConcurrentDictionary<ulong, OrdinaryRequest> OrdinaryRequests { get; } = new ConcurrentDictionary<ulong, OrdinaryRequest>();

	public void CancelOrdinary()
	{
		foreach (var operation in OrdinaryRequests.Values) operation.Cancel();
	}

	public ConcurrentDictionary<ulong, PendingAsyncRequest> AsyncRequests { get; } = new ConcurrentDictionary<ulong, PendingAsyncRequest>();

	public bool RegisterPending(PendingAsyncRequest pending)
	{
		pending.OnRemove(() =>
		{
			PendingRequests.TryRemove(new System.Collections.Generic.KeyValuePair<ulong, PendingAsyncRequest>(pending.MessageId, pending));
			AsyncRequests.TryRemove(new System.Collections.Generic.KeyValuePair<ulong, PendingAsyncRequest>(pending.AsyncId, pending));
		});
		if (!PendingRequests.TryAdd(pending.MessageId, pending)) return false;
		if (AsyncRequests.TryAdd(pending.AsyncId, pending)) return true;

		PendingRequests.TryRemove(new System.Collections.Generic.KeyValuePair<ulong, PendingAsyncRequest>(pending.MessageId, pending));
		return false;
	}

	internal ConcurrentDictionary<ulong, (Func<ReadOnlyMemory<byte>, bool> Commit, Action Abandon)> ResponseCommitActions { get; } = new ConcurrentDictionary<ulong, (Func<ReadOnlyMemory<byte>, bool>, Action)>();

	/// <summary>Call only after the complete ordered transport write and flush succeeds.</summary>
	public void ResponseSent(ReadOnlyMemory<byte> response)
	{
		var offset = 0;
		while (response.Length - offset >= 64)
		{
			var header = Smb2Header.Read(response.Span.Slice(offset));
			if (header.Status != NtStatus.Pending && ResponseCommitActions.TryGetValue(header.MessageId, out var committed) &&
				committed.Commit(response.Slice(offset, header.NextCommand == 0 ? response.Length - offset : checked((int)header.NextCommand))))
				ResponseCommitActions.TryRemove(new System.Collections.Generic.KeyValuePair<ulong, (Func<ReadOnlyMemory<byte>, bool>, Action)>(header.MessageId, committed));
			if (header.IsAsync && header.Status == NtStatus.Pending && AsyncRequests.TryGetValue(header.AsyncId, out var pending)) pending.CommitInterim();
			if (header.NextCommand == 0) break;

			offset += checked((int)header.NextCommand);
		}
	}

	public void AbandonPending()
	{
		foreach (var pending in PendingRequests.Values) pending.Abandon();
		foreach (var pair in ResponseCommitActions)
			if (ResponseCommitActions.TryRemove(pair.Key, out var abandoned)) abandoned.Abandon();
	}

	public ulong AllocateTreeId()
	{
		lock (_legacyIdGate)
		{
			if (_treeIdCounter >= uint.MaxValue - 1L) throw new InvalidOperationException("TreeId namespace exhausted.");

			return (ulong)++_treeIdCounter;
		}
	}

	public ulong AllocateFileId()
	{
		lock (_legacyIdGate)
		{
			if (_fileIdCounter == long.MaxValue) throw new InvalidOperationException("Legacy FileId namespace exhausted.");

			return (ulong)++_fileIdCounter;
		}
	}

	public ulong AllocateAsyncId()
	{
		return (ulong)Interlocked.Increment(ref _asyncIdCounter);
	}

	public void CancelAllPending()
	{
		foreach (var value in PendingRequests.Values)
		{
			try { value.Cancel(); }
			catch (Exception)
			{
				/* Continue releasing other pending work after a callback fault. */
			}
			finally
			{
				value.Abandon();
				PendingRequests.TryRemove(new System.Collections.Generic.KeyValuePair<ulong, PendingAsyncRequest>(value.MessageId, value));
				AsyncRequests.TryRemove(new System.Collections.Generic.KeyValuePair<ulong, PendingAsyncRequest>(value.AsyncId, value));
			}
		}
	}
}
