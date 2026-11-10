namespace Smb.Server.Witness;

public enum WitnessNodeState : ushort
{
    Unknown = 0,
    Available = 1,
    Unavailable = 255,
}
