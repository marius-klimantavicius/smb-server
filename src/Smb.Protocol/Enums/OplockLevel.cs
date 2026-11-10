namespace Smb.Protocol.Enums;

public enum OplockLevel : byte
{
    None = 0,
    LevelII = 1,
    Exclusive = 8,
    Batch = 9,
    Lease = byte.MaxValue,
}
