using System;
using System.Collections.Generic;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server.State;

namespace Smb.Server.Leases;

public sealed class NullLeaseManager : ILeaseManager
{
    public LeaseGrant RequestLease(SmbOpen open, LeaseRequest request)
    {
        return LeaseGrant.None;
    }

    public LeaseState Acknowledge(LeaseKey key, LeaseState newState)
    {
        return LeaseState.None;
    }

    public void ReleaseOwner(SmbOpen open)
    {
    }

    public IReadOnlyList<LeaseBreak> BreakDirectoryLease(string directoryFileKey)
    {
        return Array.Empty<LeaseBreak>();
    }
}
