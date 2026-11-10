using System;
using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public static class OplockBreakMessage
{
    public readonly record struct Acknowledgment(OplockLevel OplockLevel, ulong PersistentId, ulong VolatileId);

    public const ushort StructureSize = 24;

    public static Acknowledgment ParseAcknowledgment(ReadOnlySpan<byte> message, int bodyOffset)
    {
        var spanReader = new SpanReader(message.Slice(bodyOffset));
        var num = spanReader.ReadUInt16();
        if (num != StructureSize)
        {
            throw new SmbWireFormatException($"OPLOCK_BREAK Ack StructureSize {num} ≠ {StructureSize} (lease break?).");
        }

        var oplockLevel = spanReader.ReadByte();
        spanReader.Skip(1);
        spanReader.Skip(4);
        var persistentId = spanReader.ReadUInt64();
        var volatileId = spanReader.ReadUInt64();
        return new Acknowledgment((OplockLevel)oplockLevel, persistentId, volatileId);
    }

    public static byte[] BuildBody(OplockLevel oplockLevel, ulong persistentId, ulong volatileId)
    {
        var array = new byte[StructureSize];
        var spanWriter = new SpanWriter(array);
        spanWriter.WriteUInt16(StructureSize);
        spanWriter.WriteByte((byte)oplockLevel);
        spanWriter.WriteByte(0);
        spanWriter.WriteUInt32(0u);
        spanWriter.WriteUInt64(persistentId);
        spanWriter.WriteUInt64(volatileId);
        return array;
    }
}
