using System;

namespace Smb.FileSystem;

[Flags]
public enum SmbFileAttributes : uint
{
	None = 0u,
	ReadOnly = 1u,
	Hidden = 2u,
	System = 4u,
	Directory = 0x10u,
	Archive = 0x20u,
	Normal = 0x80u,
	Temporary = 0x100u,
	Sparse = 0x200u,
	ReparsePoint = 0x400u,
	Compressed = 0x800u,
	Offline = 0x1000u,
	NotContentIndexed = 0x2000u,
	Encrypted = 0x4000u,
}
