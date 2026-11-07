using System.Collections.Generic;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server.State;

namespace Smb.Server.Leases;

public interface ILeaseManager
{
	LeaseGrant RequestLease(SmbOpen open, LeaseRequest request);

	LeaseState Acknowledge(LeaseKey key, LeaseState newState);

	void ReleaseOwner(SmbOpen open);

	IReadOnlyList<LeaseBreak> BreakDirectoryLease(string directoryFileKey);
}
