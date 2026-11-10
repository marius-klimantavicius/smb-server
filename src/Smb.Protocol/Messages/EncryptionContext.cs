using System;
using System.Collections.Generic;
using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public sealed class EncryptionContext : NegotiateContext
{
    public override NegotiateContextType Type => NegotiateContextType.EncryptionCapabilities;

    public IReadOnlyList<SmbCipherId> Ciphers { get; init; } = Array.Empty<SmbCipherId>();

    protected override void WriteData(GrowableWriter w)
    {
        w.WriteUInt16((ushort)Ciphers.Count);
        foreach (var cipher in Ciphers)
        {
            w.WriteUInt16((ushort)cipher);
        }
    }

    public static EncryptionContext ParseData(ReadOnlySpan<byte> data)
    {
        var spanReader = new SpanReader(data);
        int num = spanReader.ReadUInt16();
        var array = new SmbCipherId[num];
        for (var i = 0; i < num; i++)
        {
            array[i] = (SmbCipherId)spanReader.ReadUInt16();
        }

        return new EncryptionContext
        {
            Ciphers = array,
        };
    }
}
