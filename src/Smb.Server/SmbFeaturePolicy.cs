using System;
using System.Collections.Generic;
using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server.Durable;

namespace Smb.Server;

/// <summary>
/// Selectable correctness profiles. Restricted is the default; CopyOnly adds coordinated
/// server-side copy after its P5 gate. Caching/CachingWithCopy add coordinated file
/// caching only on a backend with an explicit coherence contract. Multichannel profiles
/// opt in to tested SMB300/302 connection sets. Durability, directory leases and recovery remain unavailable.
/// </summary>
public sealed class SmbFeaturePolicy
{
	public static SmbFeaturePolicy Restricted { get; } = new SmbFeaturePolicy(false);
    public static SmbFeaturePolicy CopyOnly { get; } = new SmbFeaturePolicy(true);
    public static SmbFeaturePolicy Caching { get; } = new SmbFeaturePolicy(false, true);
    public static SmbFeaturePolicy CachingWithCopy { get; } = new SmbFeaturePolicy(true, true);
    public static SmbFeaturePolicy MultichannelOnly { get; } = new SmbFeaturePolicy(false, false, true);
    public static SmbFeaturePolicy MultichannelWithCopy { get; } = new SmbFeaturePolicy(true, false, true);
    public static SmbFeaturePolicy MultichannelWithCaching { get; } = new SmbFeaturePolicy(false, true, true);
    public static SmbFeaturePolicy MultichannelWithCachingAndCopy { get; } = new SmbFeaturePolicy(true, true, true);
    public static SmbFeaturePolicy Durable { get; } = new SmbFeaturePolicy(false, true, false, true);
    public static SmbFeaturePolicy DurableWithCopy { get; } = new SmbFeaturePolicy(true, true, false, true);
    public static SmbFeaturePolicy DurableWithMultichannel { get; } = new SmbFeaturePolicy(false, true, true, true);
    public static SmbFeaturePolicy DurableWithMultichannelAndCopy { get; } = new SmbFeaturePolicy(true, true, true, true);
    private readonly bool _durable;
    private readonly bool _multichannel;
    private readonly bool _caching;
    private readonly bool _copy;
	private SmbFeaturePolicy(bool copy, bool caching = false, bool multichannel = false, bool durable = false) { _durable = durable; _copy = copy; _caching = caching; _multichannel = multichannel; }

	public bool Oplocks => _caching;
	public bool Leasing => _caching;
	public bool Multichannel => _multichannel;
    public bool SupportsMultichannel(SmbDialect dialect) => Multichannel && dialect is SmbDialect.Smb300 or SmbDialect.Smb302;
	public bool DurableHandles => _durable;
    public bool SupportsDurable(SmbDialect dialect) => _durable && dialect is SmbDialect.Smb300 or SmbDialect.Smb302;
	public bool PersistentHandles => false;
	public bool ContinuousAvailability => false;
	public bool CopyChunk => _copy;

	public bool AllowsShare(IShare share) => !share.ContinuousAvailability || ContinuousAvailability;

	public void ValidateShare(IShare share)
	{
		if (!AllowsShare(share))
			throw new InvalidOperationException("Continuous availability is unavailable until backend recovery gates pass.");
	}

	public void Validate(SmbServerOptions options)
	{
        if (DurableHandles && (options.DurableHandleTimeout <= TimeSpan.Zero || options.DurableHandleTimeout.TotalMilliseconds > uint.MaxValue - 1 ||
            options.MaxDurableHandleTimeout <= TimeSpan.Zero || options.MaxDurableHandleTimeout.TotalMilliseconds > uint.MaxValue - 1))
            throw new InvalidOperationException("Durability requires positive, finite retention timeouts.");
        if (Oplocks && (options.OplockBreakTimeout <= TimeSpan.Zero || options.OplockBreakTimeout.TotalMilliseconds > uint.MaxValue - 1))
            throw new InvalidOperationException("Caching requires a positive, finite break acknowledgment timeout.");
		if (options.EnableMultichannel && !Multichannel)
			throw new InvalidOperationException("Multichannel is unavailable until identity and channel lifecycle gates pass.");
		if (options.DurableHandleStore is IPersistentHandleStore && !PersistentHandles)
			throw new InvalidOperationException("Persistent handle storage cannot enable recovery before its lifecycle gate passes.");
		foreach (var share in options.Shares.All)
			ValidateShare(share);
	}

	/// <summary>Validate conflicting recovery contexts even when no durability is granted.</summary>
	public NtStatus ValidateCreateContexts(IReadOnlyList<CreateContext> contexts, SmbDialect dialect)
	{
		var v1Request = CreateContextList.Find(contexts, 1145597521u) != null; // DHnQ
		var v1Reconnect = CreateContextList.Find(contexts, 1145597507u) != null; // DHnC
		var v2Request = CreateContextList.Find(contexts, 1145582161u) != null; // DH2Q
		var v2Reconnect = CreateContextList.Find(contexts, 1145582147u) != null; // DH2C
		// MS-SMB2 3.3.5.9.10 MUST; 3.3.5.9.6/.7 SHOULD for conflicting versions.
		if ((v2Request || v2Reconnect) && (v1Request || v1Reconnect) || v2Request && v2Reconnect)
			return NtStatus.InvalidParameter;
		return NtStatus.Success;
	}

	public bool AllowsIoctl(uint code) => code switch
	{
		0x001401fc => Multichannel,
		0x00140078 or 0x001440f2 or 0x001480f2 => CopyChunk,
		_ => true,
	};
}
