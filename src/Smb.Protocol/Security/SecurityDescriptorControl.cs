using System;

namespace Smb.Protocol.Security;

[Flags]
public enum SecurityDescriptorControl : ushort
{
	None = 0,
	OwnerDefaulted = 1,
	GroupDefaulted = 2,
	DaclPresent = 4,
	DaclDefaulted = 8,
	SaclPresent = 0x10,
	SaclDefaulted = 0x20,
	DaclAutoInheritReq = 0x100,
	SaclAutoInheritReq = 0x200,
	DaclAutoInherited = 0x400,
	SaclAutoInherited = 0x800,
	DaclProtected = 0x1000,
	SaclProtected = 0x2000,
	RmControlValid = 0x4000,
	SelfRelative = 0x8000,
}
