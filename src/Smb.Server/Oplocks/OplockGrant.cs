using System;
using System.Collections.Generic;
using Smb.Protocol.Enums;

namespace Smb.Server.Oplocks;

public readonly record struct OplockGrant(OplockLevel GrantedLevel, IReadOnlyList<OplockBreak> Breaks)
{
    public static readonly OplockGrant None = new OplockGrant(OplockLevel.None, Array.Empty<OplockBreak>());
}
