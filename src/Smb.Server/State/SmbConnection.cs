using System;
using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Smb.Auth;
using Smb.Crypto;
using Smb.Protocol.Enums;

namespace Smb.Server.State;

public sealed class SmbConnection
{
	private long _treeIdCounter;

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

	public ulong SequenceWindowStart { get; set; }

	public ulong SequenceWindowSize { get; set; } = 1uL;

	public ushort OutstandingRequestCount { get; set; }

	public Func<byte[], bool, Task>? SendRawAsync { get; set; }

	public ConcurrentDictionary<ulong, PendingAsyncRequest> PendingRequests { get; } = new ConcurrentDictionary<ulong, PendingAsyncRequest>();

	public ulong AllocateTreeId()
	{
		return (ulong)Interlocked.Increment(ref _treeIdCounter);
	}

	public ulong AllocateFileId()
	{
		return (ulong)Interlocked.Increment(ref _fileIdCounter);
	}

	public ulong AllocateAsyncId()
	{
		return (ulong)Interlocked.Increment(ref _asyncIdCounter);
	}

	public void CancelAllPending()
	{
		foreach (var value in PendingRequests.Values)
		{
			value.Cancel();
		}

		PendingRequests.Clear();
	}
}
