using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public static class LogoffMessage
{
    public const ushort StructureSize = 4;

    public static byte[] BuildResponseBody()
    {
        var array = new byte[StructureSize];
        var spanWriter = new SpanWriter(array);
        spanWriter.WriteUInt16(StructureSize);
        spanWriter.WriteUInt16(0);
        return array;
    }
}
