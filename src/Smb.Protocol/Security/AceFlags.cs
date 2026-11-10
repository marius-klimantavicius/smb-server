using System;

namespace Smb.Protocol.Security;

[Flags]
public enum AceFlags : byte
{
    None = 0,
    ObjectInherit = 1,
    ContainerInherit = 2,
    NoPropagateInherit = 4,
    InheritOnly = 8,
    Inherited = 0x10,
    SuccessfulAccess = 0x40,
    FailedAccess = 0x80,
}
