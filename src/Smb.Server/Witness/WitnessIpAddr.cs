namespace Smb.Server.Witness;

public sealed record WitnessIpAddr(WitnessIpAddrFlags Flags, uint IPv4, byte[]? IPv6 = null);
