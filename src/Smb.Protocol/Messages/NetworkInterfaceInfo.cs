using System.Net;

namespace Smb.Protocol.Messages;

public readonly record struct NetworkInterfaceInfo(uint IfIndex, NetworkInterfaceCapability Capability, ulong LinkSpeedBitsPerSecond, IPAddress Address);
