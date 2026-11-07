using System;
using System.Collections.Generic;
using Smb.Auth;
using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Server.Authorization;
using Smb.Server.Dfs;
using Smb.Server.Diagnostics;
using Smb.Server.Durable;
using Smb.Server.Leases;
using Smb.Server.Locking;
using Smb.Server.Multichannel;
using Smb.Server.Notification;
using Smb.Server.Oplocks;
using Smb.Server.Quota;
using Smb.Server.Sharing;

namespace Smb.Server;

public sealed class SmbServerOptions
{
	public string ServerName { get; set; } = Environment.MachineName;

	public byte[] ServerGuid { get; set; } = Guid.NewGuid().ToByteArray();

	public SmbDialect MaxDialect { get; set; } = SmbDialect.Smb311;

	public SmbDialect MinDialect { get; set; } = SmbDialect.Smb202;

	public bool RequireMessageSigning { get; set; } = true;

	public bool RequireEncryption { get; set; }

	public bool RejectUnencryptedAccess { get; set; } = true;

	public bool RejectGuestAccess { get; set; } = true;

	public bool AllowAnonymousAccess { get; set; }

	public IReadOnlyList<SmbCipherId> CipherPreference { get; set; } =
	[
		SmbCipherId.Aes128Gcm,
		SmbCipherId.Aes256Gcm,
		SmbCipherId.Aes128Ccm,
		SmbCipherId.Aes256Ccm,
	];

	public IReadOnlyList<SmbSigningAlgorithmId> SigningPreference { get; set; } =
	[
		SmbSigningAlgorithmId.AesGmac,
		SmbSigningAlgorithmId.AesCmac,
		SmbSigningAlgorithmId.HmacSha256,
	];

	public uint MaxTransactSize { get; set; } = 8388608u;

	public uint MaxReadSize { get; set; } = 8388608u;

	public uint MaxWriteSize { get; set; } = 8388608u;

	public bool EnableCompression { get; set; }

	public IReadOnlyList<SmbCompressionAlgorithm> CompressionPreference { get; set; } = [SmbCompressionAlgorithm.Lz77];

	public int CompressionMinSize { get; set; } = 4096;

	public ushort MaxCreditsPerResponse { get; set; } = 512;

	public int MaxOutstandingRequests { get; set; } = 512;

	public int MaxConcurrentFileOpsPerConnection { get; set; } = 8;

	public bool ConcurrentMetadataOps { get; set; }

	public int MaxOpenHandlesPerSession { get; set; } = 16384;

	public int MaxDirectoryEnumerationEntries { get; set; } = 1048576;

	public ISpnegoNegotiator? SpnegoNegotiator { get; set; }

	public ShareCollection Shares { get; set; } = new ShareCollection();

	public IShareAccessPolicy ShareAccessPolicy { get; set; } = new AllowAllSharePolicy();

	public ILockManager LockManager { get; set; } = new InMemoryLockManager();

	public IDirectoryWatcher DirectoryWatcher { get; set; } = new FileSystemDirectoryWatcher();

	public IOplockManager OplockManager { get; set; } = new InMemoryOplockManager();

	public TimeSpan OplockBreakTimeout { get; set; } = TimeSpan.FromSeconds(35L);

	public ILeaseManager LeaseManager { get; set; } = new InMemoryLeaseManager();

	public IShareModeManager ShareModeManager { get; set; } = new InMemoryShareModeManager();

	public IDurableHandleStore DurableHandleStore { get; set; } = new InMemoryDurableHandleStore();

	public TimeSpan DurableHandleTimeout { get; set; } = TimeSpan.FromSeconds(60L);

	public TimeSpan MaxDurableHandleTimeout { get; set; } = TimeSpan.FromMinutes(16L);

	public TimeProvider TimeProvider { get; set; } = System.TimeProvider.System;

	public bool EnableMultichannel { get; set; } = true;

	public INetworkInterfaceProvider NetworkInterfaceProvider { get; set; } = new SystemNetworkInterfaceProvider();

	public IDfsNamespace? DfsNamespace { get; set; }

	public ISmbAuditLogger AuditLogger { get; set; } = NullSmbAuditLogger.Instance;

	public SmbServerMetrics Metrics { get; set; } = new SmbServerMetrics();

	public TimeSpan SessionIdleTimeout { get; set; } = TimeSpan.FromMinutes(15L);

	public TimeSpan ConnectionIdleTimeout { get; set; } = TimeSpan.FromMinutes(5L);

	public TimeSpan AuthenticationTimeout { get; set; } = TimeSpan.FromSeconds(30L);

	public TimeSpan TimeoutSweepInterval { get; set; } = TimeSpan.FromSeconds(30L);

	public int MaxConnections { get; set; } = 1024;

	public int MaxConnectionsPerClient { get; set; } = 64;

	public TimeSpan ShutdownDrainTimeout { get; set; } = TimeSpan.FromSeconds(30L);

	public IQuotaProvider QuotaProvider { get; set; } = NullQuotaProvider.Instance;

	public void Validate()
	{
		var serverGuid = ServerGuid;
		if (serverGuid == null || serverGuid.Length != 16)
		{
			throw new InvalidOperationException("ServerGuid must be 16 bytes.");
		}

		if ((int)MaxDialect < (int)MinDialect)
		{
			throw new InvalidOperationException("MaxDialect must not be less than MinDialect.");
		}

		if (SpnegoNegotiator == null)
		{
			throw new InvalidOperationException("SpnegoNegotiator is required (auth provider).");
		}
	}
}
