using System;
using System.Collections.Generic;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public static class LockMessage
{
    public sealed record Request(ulong PersistentId, ulong VolatileId, uint LockSequence, IReadOnlyList<LockEntry> Locks);

    public const ushort RequestStructureSize = 48;

    public const ushort ResponseStructureSize = 4;

    public const int LockElementSize = 24;

    public static Request ParseRequest(ReadOnlySpan<byte> message, int bodyOffset)
    {
        var spanReader = new SpanReader(message.Slice(bodyOffset));
        var num = spanReader.ReadUInt16();
        if (num != RequestStructureSize)
        {
            throw new SmbWireFormatException($"LOCK Request StructureSize {num} ≠ {RequestStructureSize}.");
        }
        var num2 = spanReader.ReadUInt16();
        var lockSequence = spanReader.ReadUInt32();
        var persistentId = spanReader.ReadUInt64();
        var volatileId = spanReader.ReadUInt64();
        if (num2 == 0)
        {
            throw new SmbWireFormatException("LOCK request with LockCount 0.");
        }
        var array = new LockEntry[num2];
        for (var i = 0; i < num2; i++)
        {
            var offset = spanReader.ReadUInt64();
            var length = spanReader.ReadUInt64();
            var flags = spanReader.ReadUInt32();
            spanReader.Skip(4);
            array[i] = new LockEntry(offset, length, flags);
        }
        return new Request(persistentId, volatileId, lockSequence, array);
    }

    public static byte[] BuildResponseBody()
    {
        var array = new byte[ResponseStructureSize];
        var spanWriter = new SpanWriter(array);
        spanWriter.WriteUInt16(ResponseStructureSize);
        spanWriter.WriteUInt16(0);
        return array;
    }
}
