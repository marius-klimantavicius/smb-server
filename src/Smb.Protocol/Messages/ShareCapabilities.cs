using System;

namespace Smb.Protocol.Messages;

[Flags]
public enum ShareCapabilities : uint
{
	None = 0u,
	Dfs = 8u,
	ContinuousAvailability = 0x10u,
	Scaleout = 0x20u,
	Cluster = 0x40u,
	Asymmetric = 0x80u,
	RedirectToOwner = 0x100u,
}
