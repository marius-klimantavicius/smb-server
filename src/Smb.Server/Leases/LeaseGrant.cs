using System;
using System.Collections.Generic;
using Smb.Protocol.Enums;

namespace Smb.Server.Leases;

public readonly record struct LeaseGrant(LeaseState GrantedState, ushort Epoch, IReadOnlyList<LeaseBreak> Breaks)
{
    public bool IsV2 { get; init; }

    public static readonly LeaseGrant None = new LeaseGrant(LeaseState.None, 0, Array.Empty<LeaseBreak>());
}
