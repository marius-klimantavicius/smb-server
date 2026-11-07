using System;

namespace Smb.Protocol.Enums;

[Flags]
public enum LeaseFlags : uint
{
	None = 0u,
	BreakInProgress = 2u,
	ParentLeaseKeySet = 4u,
}
