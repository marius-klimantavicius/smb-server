using Smb.Protocol.Enums;

namespace Smb.Server.Authorization;

public sealed class ShareAccessResult
{
	public bool Allowed { get; private init; }

	public SmbAccessMask MaximalAccess { get; private init; }

	public NtStatus DenyStatus { get; private init; }

	public static ShareAccessResult Grant(SmbAccessMask maximalAccess = SmbAccessMask.FullAccess)
	{
		return new ShareAccessResult
		{
			Allowed = true,
			MaximalAccess = maximalAccess,
		};
	}

	public static ShareAccessResult Deny(NtStatus status = NtStatus.AccessDenied)
	{
		return new ShareAccessResult
		{
			Allowed = false,
			DenyStatus = status,
		};
	}
}
