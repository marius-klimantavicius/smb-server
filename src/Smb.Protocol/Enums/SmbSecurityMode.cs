using System;

namespace Smb.Protocol.Enums;

[Flags]
public enum SmbSecurityMode : ushort
{
    None = 0,
    SigningEnabled = 1,
    SigningRequired = 2,
}
