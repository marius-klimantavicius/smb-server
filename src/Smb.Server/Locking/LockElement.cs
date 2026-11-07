namespace Smb.Server.Locking;

public readonly record struct LockElement(ulong Offset, ulong Length, bool Exclusive, bool Unlock);
