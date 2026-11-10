namespace Smb.Protocol.Messages;

public readonly record struct LockEntry(ulong Offset, ulong Length, uint Flags)
{
    public bool IsUnlock => (Flags & 4) != 0;

    public bool IsExclusive => (Flags & 2) != 0;

    public bool IsShared => (Flags & 1) != 0;

    public bool FailImmediately => (Flags & 0x10) != 0;
}
