using System;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public static class ReadMessage
{
    public readonly record struct Request(uint Length, ulong Offset, ulong PersistentId, ulong VolatileId, uint MinimumCount)
    {
        public byte FlagsByte { get; init; }
        public uint Flags { get; init; }
        public uint Channel { get; init; }
        public uint RemainingBytes { get; init; }
        public ushort ChannelInfoOffset { get; init; }
        public ushort ChannelInfoLength { get; init; }
    }

    public const ushort RequestStructureSize = 49;

    public const ushort ResponseStructureSize = 17;

    public static Request ParseRequest(ReadOnlySpan<byte> message, int bodyOffset)
    {
        var spanReader = new SpanReader(message.Slice(bodyOffset));
        var num = spanReader.ReadUInt16();
        if (num != RequestStructureSize)
        {
            throw new SmbWireFormatException($"READ Request StructureSize {num} ≠ {RequestStructureSize}.");
        }

        spanReader.Skip(1);
        var flags = spanReader.ReadByte();
        var length = spanReader.ReadUInt32();
        var offset = spanReader.ReadUInt64();
        var persistentId = spanReader.ReadUInt64();
        var volatileId = spanReader.ReadUInt64();
        var minimumCount = spanReader.ReadUInt32();
        var channel = spanReader.ReadUInt32();
        var remaining = spanReader.ReadUInt32();
        var infoOffset = spanReader.ReadUInt16();
        var infoLength = spanReader.ReadUInt16();

        return new Request(length, offset, persistentId, volatileId, minimumCount)
        {
            Flags = flags,
            FlagsByte = flags,
            Channel = channel,
            RemainingBytes = remaining,
            ChannelInfoOffset = infoOffset,
            ChannelInfoLength = infoLength
        };
    }

    public static byte[] BuildResponseBody(ReadOnlySpan<byte> data)
    {
        var array = new byte[16 + data.Length];
        var spanWriter = new SpanWriter(array);
        spanWriter.WriteUInt16(ResponseStructureSize);
        spanWriter.WriteByte(80);
        spanWriter.WriteByte(0);
        spanWriter.WriteUInt32((uint)data.Length);
        spanWriter.WriteUInt32(0u);
        spanWriter.WriteUInt32(0u);
        spanWriter.WriteBytes(data);
        return array;
    }
}
