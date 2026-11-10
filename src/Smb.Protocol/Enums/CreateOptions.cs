using System;

namespace Smb.Protocol.Enums;

[Flags]
public enum CreateOptions : uint
{
    None = 0u,
    DirectoryFile = 1u,
    WriteThrough = 2u,
    SequentialOnly = 4u,
    NonDirectoryFile = 0x40u,
    DeleteOnClose = 0x1000u,
    OpenByFileId = 0x2000u,
    OpenReparsePoint = 0x200000u,
    OpenForBackupIntent = 0x4000u,
}
