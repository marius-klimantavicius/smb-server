using System;

namespace Smb.FileSystem;

[Flags]
public enum FileAccessIntent
{
    None = 0,
    Read = 1,
    Write = 2,
    Delete = 4,
    ReadWrite = Read | Write,
}
