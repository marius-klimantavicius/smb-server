using System;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public static class CloseMessage
{
    public const ushort RequestStructureSize = 24;

    public const ushort ResponseStructureSize = 60;

    public const ushort FlagPostQueryAttributes = 1;

    public static (ushort flags, ulong persistentId, ulong volatileId) ParseRequest(ReadOnlySpan<byte> message, int bodyOffset)
    {
        var spanReader = new SpanReader(message.Slice(bodyOffset));
        var num = spanReader.ReadUInt16();
        if (num != RequestStructureSize)
        {
            throw new SmbWireFormatException($"CLOSE Request StructureSize {num} ≠ {RequestStructureSize}.");
        }

        var item = spanReader.ReadUInt16();
        spanReader.Skip(4);
        var item2 = spanReader.ReadUInt64();
        var item3 = spanReader.ReadUInt64();
        return (flags: item, persistentId: item2, volatileId: item3);
    }

    public static byte[] BuildResponseBody(bool postQuery = false, FileTimes? times = null, long allocationSize = 0L, long endOfFile = 0L, uint fileAttributes = 0u)
    {
        var array = new byte[ResponseStructureSize];
        var spanWriter = new SpanWriter(array);
        spanWriter.WriteUInt16(ResponseStructureSize);
        spanWriter.WriteUInt16(postQuery ? FlagPostQueryAttributes : ((ushort)0));
        spanWriter.WriteUInt32(0u);
        var valueOrDefault = times.GetValueOrDefault();
        spanWriter.WriteInt64(valueOrDefault.Creation);
        spanWriter.WriteInt64(valueOrDefault.LastAccess);
        spanWriter.WriteInt64(valueOrDefault.LastWrite);
        spanWriter.WriteInt64(valueOrDefault.Change);
        spanWriter.WriteInt64(allocationSize);
        spanWriter.WriteInt64(endOfFile);
        spanWriter.WriteUInt32(fileAttributes);
        return array;
    }
}
