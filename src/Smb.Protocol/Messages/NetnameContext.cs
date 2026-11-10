using System;
using System.Text;
using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public sealed class NetnameContext : NegotiateContext
{
    public override NegotiateContextType Type => NegotiateContextType.NetnameNegotiateContextId;

    public string NetName { get; init; } = string.Empty;

    protected override void WriteData(GrowableWriter w)
    {
        w.WriteUtf16(NetName);
    }

    public static NetnameContext ParseData(ReadOnlySpan<byte> data)
    {
        return new NetnameContext
        {
            NetName = Encoding.Unicode.GetString(data),
        };
    }
}
