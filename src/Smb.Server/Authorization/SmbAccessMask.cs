using System;

namespace Smb.Server.Authorization;

[Flags]
public enum SmbAccessMask : uint
{
    None = 0u,
    FileReadData = 1u,
    FileWriteData = 2u,
    FileAppendData = 4u,
    FileReadEa = 8u,
    FileWriteEa = 0x10u,
    FileExecute = 0x20u,
    FileDeleteChild = 0x40u,
    FileReadAttributes = 0x80u,
    FileWriteAttributes = 0x100u,
    Delete = 0x10000u,
    ReadControl = 0x20000u,
    WriteDac = 0x40000u,
    WriteOwner = 0x80000u,
    Synchronize = 0x100000u,
    MaximumAllowed = 0x2000000u,
    GenericAll = 0x10000000u,
    GenericExecute = 0x20000000u,
    GenericWrite = 0x40000000u,
    GenericRead = 0x80000000u,
    FullAccess = FileReadData | FileWriteData | FileAppendData | FileReadEa | FileWriteEa | FileExecute | FileDeleteChild | FileReadAttributes | FileWriteAttributes | Delete | ReadControl | WriteDac | WriteOwner | Synchronize,
    ReadOnly = 0x1200A9u,
    ReadWrite = 0x1201BFu,
}
