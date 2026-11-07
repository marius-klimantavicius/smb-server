using System;

namespace Smb.Protocol.Messages;

[Flags]
public enum SessionSetupFlags : byte
{
	None = 0,
	Binding = 1,
}
