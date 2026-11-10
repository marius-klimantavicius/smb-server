using System;

namespace Smb.Protocol.Compression;

[Flags]
public enum SmbCompressionFlags : uint
{
    None = 0u,
    Chained = 1u,
}
