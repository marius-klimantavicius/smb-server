using Smb.Protocol.Messages;

namespace Smb.Server.Locking;

public readonly record struct LockElement(ulong Offset, ulong Length, LockFlags Flags)
{
    public LockElement(ulong Offset, ulong Length, bool Exclusive, bool Unlock)
        : this(Offset, Length, (Exclusive ? LockFlags.ExclusiveLock : Unlock ? LockFlags.None : LockFlags.SharedLock) | (Unlock ? LockFlags.Unlock : LockFlags.None)) { }

    public bool Exclusive => (Flags & LockFlags.ExclusiveLock) != 0;

    public bool Shared => (Flags & LockFlags.SharedLock) != 0;

    public bool Unlock => (Flags & LockFlags.Unlock) != 0;
}
