using System;
using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Compression;

public sealed class CompressionPayloadHeader
{
    public const int Size = 8;

    public SmbCompressionAlgorithm CompressionAlgorithm { get; init; }

    public SmbCompressionFlags Flags { get; init; }

    public uint Length { get; init; }

    public void Write(GrowableWriter w)
    {
        w.WriteUInt16((ushort)CompressionAlgorithm);
        w.WriteUInt16((ushort)Flags);
        w.WriteUInt32(Length);
    }

    public static CompressionPayloadHeader Read(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < Size)
        {
            throw new SmbWireFormatException($"Compression payload header requires {Size} bytes.");
        }

        var spanReader = new SpanReader(buffer);
        return new CompressionPayloadHeader
        {
            CompressionAlgorithm = (SmbCompressionAlgorithm)spanReader.ReadUInt16(),
            Flags = (SmbCompressionFlags)spanReader.ReadUInt16(),
            Length = spanReader.ReadUInt32(),
        };
    }
}
