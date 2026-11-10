namespace Smb.Server.Witness;

public enum WitnessNotifyType : uint
{
    ResourceChange = 1u,
    ClientMove,
    ShareMove,
    IpChange,
}
