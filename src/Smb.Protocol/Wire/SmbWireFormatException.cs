using System;

namespace Smb.Protocol.Wire;

public sealed class SmbWireFormatException : Exception
{
    public SmbWireFormatException(string message)
        : base(message)
    {
    }

    public SmbWireFormatException(string message, Exception inner)
        : base(message, inner)
    {
    }
}
