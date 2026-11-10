using System;

namespace Smb.Protocol.Enums;

[Flags]
public enum LeaseState : uint
{
    None = 0u,
    Read = 1u,
    Handle = 2u,
    Write = 4u,
    ReadHandle = Read | Handle,
    ReadWrite = Read | Write,
    ReadWriteHandle = ReadHandle | Write,
}
