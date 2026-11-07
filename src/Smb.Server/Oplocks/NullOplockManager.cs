using Smb.Protocol.Enums;
using Smb.Server.State;

namespace Smb.Server.Oplocks;

public sealed class NullOplockManager : IOplockManager
{
	public OplockGrant RequestOplock(SmbOpen open, OplockLevel requested)
	{
		return OplockGrant.None;
	}

	public OplockLevel Acknowledge(SmbOpen open, OplockLevel newLevel)
	{
		return OplockLevel.None;
	}

	public void ReleaseOwner(SmbOpen open)
	{
	}
}
