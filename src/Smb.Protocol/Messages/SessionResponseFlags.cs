using System;

namespace Smb.Protocol.Messages;

[Flags]
public enum SessionResponseFlags : ushort
{
	None = 0,
	IsGuest = 1,
	IsNull = 2,
	EncryptData = 4,
}
