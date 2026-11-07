using System;

namespace Smb.Server.Witness;

[Flags]
public enum WitnessIpAddrFlags : uint
{
	None = 0u,
	IPv4 = 1u,
	IPv6 = 2u,
	Online = 8u,
	Offline = 0x10u,
}
