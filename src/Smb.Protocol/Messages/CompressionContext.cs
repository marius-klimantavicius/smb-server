using System;
using System.Collections.Generic;
using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public sealed class CompressionContext : NegotiateContext
{
    public override NegotiateContextType Type => NegotiateContextType.CompressionCapabilities;

    public uint Flags { get; init; }

    public IReadOnlyList<SmbCompressionAlgorithm> Algorithms { get; init; } = Array.Empty<SmbCompressionAlgorithm>();

    protected override void WriteData(GrowableWriter w)
    {
        w.WriteUInt16((ushort)Algorithms.Count);
        w.WriteUInt16(0);
        w.WriteUInt32(Flags);
        foreach (var algorithm in Algorithms)
        {
            w.WriteUInt16((ushort)algorithm);
        }
    }

    public static CompressionContext ParseData(ReadOnlySpan<byte> data)
    {
        var spanReader = new SpanReader(data);
        int num = spanReader.ReadUInt16();
        spanReader.Skip(2);
        var flags = spanReader.ReadUInt32();
        var array = new SmbCompressionAlgorithm[num];
        for (var i = 0; i < num; i++)
        {
            array[i] = (SmbCompressionAlgorithm)spanReader.ReadUInt16();
        }

        return new CompressionContext
        {
            Flags = flags,
            Algorithms = array,
        };
    }
}
