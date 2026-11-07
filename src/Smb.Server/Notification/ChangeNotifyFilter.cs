using System;

namespace Smb.Server.Notification;

[Flags]
public enum ChangeNotifyFilter : uint
{
	None = 0u,
	FileName = 1u,
	DirName = 2u,
	Attributes = 4u,
	Size = 8u,
	LastWrite = 0x10u,
	LastAccess = 0x20u,
	Creation = 0x40u,
	Ea = 0x80u,
	Security = 0x100u,
	StreamName = 0x200u,
	StreamSize = 0x400u,
	StreamWrite = 0x800u,
}
