using System;
using System.Buffers.Binary;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public static class ErrorResponse
{
    public const ushort StructureSize = 9;

    public const uint Smb2ErrorIdDefault = 0u;

    public static byte[] BuildBody(ReadOnlySpan<byte> errorData = default(ReadOnlySpan<byte>))
    {
        var num = Math.Max(errorData.Length, 1);
        var array = new byte[8 + num];
        var spanWriter = new SpanWriter(array);
        spanWriter.WriteUInt16(StructureSize);
        spanWriter.WriteByte(0);
        spanWriter.WriteByte(0);
        spanWriter.WriteUInt32((uint)errorData.Length);
        if (errorData.Length > 0)
        {
            spanWriter.WriteBytes(errorData);
        }
        else
        {
            spanWriter.WriteByte(0);
        }

        return array;
    }

    public static byte[] BuildBodyWithContext(ReadOnlySpan<byte> errorContextData, uint errorId = Smb2ErrorIdDefault)
    {
        var num = 8 + errorContextData.Length;
        var array = new byte[8 + num];
        var spanWriter = new SpanWriter(array);
        spanWriter.WriteUInt16(StructureSize);
        spanWriter.WriteByte(1);
        spanWriter.WriteByte(0);
        spanWriter.WriteUInt32((uint)num);
        spanWriter.WriteUInt32((uint)errorContextData.Length);
        spanWriter.WriteUInt32(errorId);
        spanWriter.WriteBytes(errorContextData);
        return array;
    }

    public static byte[] ReadErrorData(ReadOnlySpan<byte> body)
    {
        if (body.Length < 8)
        {
            throw new SmbWireFormatException($"ERROR response body too short: {body.Length} bytes.");
        }

        var b = body[2];
        var length = (int)BinaryPrimitives.ReadUInt32LittleEndian(body.Slice(4, 4));
        var readOnlySpan = body.Slice(8, length);
        if (b == 0)
        {
            return readOnlySpan.ToArray();
        }

        var length2 = (int)BinaryPrimitives.ReadUInt32LittleEndian(readOnlySpan.Slice(0, 4));
        return readOnlySpan.Slice(8, length2).ToArray();
    }
}
