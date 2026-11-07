namespace Smb.Server.Witness;

public sealed record WitnessInterfaceInfo(string InterfaceGroupName, uint Version, WitnessNodeState NodeState, uint IPv4, WitnessInterfaceFlags Flags);
