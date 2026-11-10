using System;

namespace Smb.Protocol.Messages;

[Flags]
public enum NetworkInterfaceCapability : uint
{
    None = 0u,
    RssCapable = 1u,
    RdmaCapable = 2u,
}
