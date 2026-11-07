using System;

namespace Smb.Protocol.Enums;

[Flags]
public enum Smb2Capabilities : uint
{
	None = 0u,
	Dfs = 1u,
	Leasing = 2u,
	LargeMtu = 4u,
	MultiChannel = 8u,
	PersistentHandles = 0x10u,
	DirectoryLeasing = 0x20u,
	Encryption = 0x40u,
	Notifications = 0x80u,
}
