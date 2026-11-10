using System;

namespace Smb.Server.Sharing;

[Flags]
public enum FileShareMode
{
    None = 0,
    Read = 1,
    Write = 2,
    Delete = 4,
}
