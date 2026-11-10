using System;

namespace Smb.Protocol.Messages;

[Flags]
public enum ShareFlags : uint
{
    None = 0u,
    ManualCaching = 0u,
    AutoCaching = 0x10u,
    VdoCaching = 0x20u,
    NoCaching = AutoCaching | VdoCaching,
    Dfs = 1u,
    DfsRoot = 2u,
    EncryptData = 0x8000u,
}
