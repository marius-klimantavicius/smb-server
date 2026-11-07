using System;

namespace Smb.Protocol.Messages;

[Flags]
public enum LockFlags : uint
{
	None = 0u,
	SharedLock = 1u,
	ExclusiveLock = 2u,
	Unlock = 4u,
	FailImmediately = 0x10u,
}
