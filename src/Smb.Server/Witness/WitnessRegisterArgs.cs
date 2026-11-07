namespace Smb.Server.Witness;

public sealed record WitnessRegisterArgs(uint Version, string? NetName, string? ShareName, string? IpAddress, string? ClientComputerName, uint Flags, uint KeepAliveTimeoutSeconds);
