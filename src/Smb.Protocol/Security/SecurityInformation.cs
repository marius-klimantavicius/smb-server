using System;

namespace Smb.Protocol.Security;

[Flags]
public enum SecurityInformation : uint
{
	None = 0u,
	Owner = 1u,
	Group = 2u,
	Dacl = 4u,
	Sacl = 8u,
	Label = 0x10u,
	Attribute = 0x20u,
	Scope = 0x40u,
	Backup = 0x10000u,
	ProtectedDacl = 0x80000000u,
	ProtectedSacl = 0x40000000u,
	UnprotectedDacl = 0x20000000u,
	UnprotectedSacl = 0x10000000u,
}
