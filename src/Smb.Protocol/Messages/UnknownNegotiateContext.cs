using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public sealed class UnknownNegotiateContext : NegotiateContext
{
    private readonly NegotiateContextType _type;

    public byte[] Data { get; }

    public override NegotiateContextType Type => _type;

    public UnknownNegotiateContext(NegotiateContextType type, byte[] data)
    {
        _type = type;
        Data = data;
    }

    protected override void WriteData(GrowableWriter w)
    {
        w.WriteBytes(Data);
    }
}
