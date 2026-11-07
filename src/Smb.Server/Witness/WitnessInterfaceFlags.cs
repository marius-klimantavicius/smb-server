using System;

namespace Smb.Server.Witness;

[Flags]
public enum WitnessInterfaceFlags : uint
{
	None = 0u,
	IPv4Valid = 1u,
	IPv6Valid = 2u,
	InterfaceWitness = 4u,
}
