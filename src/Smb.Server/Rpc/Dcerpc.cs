using System;
using System.Buffers.Binary;
using System.Text;
using Smb.Protocol.Wire;

namespace Smb.Server.Rpc;

public static class Dcerpc
{
    public const int HeaderSize = 16;

    public static ReadOnlySpan<byte> NdrTransferSyntax =>
    [
        4, 93, 136, 138, 235, 28, 201, 17, 159, 232,
        8, 0, 43, 16, 72, 96,
    ];

    public static DcerpcRequest Parse(ReadOnlySpan<byte> pdu)
    {
        if (pdu.Length < HeaderSize)
        {
            throw new SmbWireFormatException("DCERPC PDU too short.");
        }

        var dcerpcPduType = (DcerpcPduType)pdu[2];
        var callId = BinaryPrimitives.ReadUInt32LittleEndian(pdu.Slice(12, 4));
        if (dcerpcPduType == DcerpcPduType.Request)
        {
            if (pdu.Length < 24)
            {
                throw new SmbWireFormatException("DCERPC request PDU too short for opnum.");
            }

            var opnum = BinaryPrimitives.ReadUInt16LittleEndian(pdu.Slice(22, 2));
            var stub = ((pdu.Length > 24) ? pdu.Slice(24).ToArray() : Array.Empty<byte>());
            return new DcerpcRequest(dcerpcPduType, callId, opnum, stub);
        }

        return new DcerpcRequest(dcerpcPduType, callId, 0, Array.Empty<byte>());
    }

    public static byte[] BuildBindAck(uint callId, string secondaryAddress)
    {
        var bytes = Encoding.ASCII.GetBytes(secondaryAddress + "\0");
        var growableWriter = new GrowableWriter(96);
        WriteHeader(growableWriter, DcerpcPduType.BindAck, callId);
        growableWriter.WriteUInt16(4280);
        growableWriter.WriteUInt16(4280);
        growableWriter.WriteUInt32(83u);
        growableWriter.WriteUInt16((ushort)bytes.Length);
        growableWriter.WriteBytes(bytes);
        AlignTo4(growableWriter);
        growableWriter.WriteByte(1);
        growableWriter.WriteByte(0);
        growableWriter.WriteUInt16(0);
        growableWriter.WriteUInt16(0);
        growableWriter.WriteUInt16(0);
        growableWriter.WriteBytes(NdrTransferSyntax);
        growableWriter.WriteUInt32(2u);
        PatchFragLength(growableWriter);
        return growableWriter.ToArray();
    }

    public static byte[] BuildResponse(uint callId, ReadOnlySpan<byte> stub)
    {
        var growableWriter = new GrowableWriter(24 + stub.Length);
        WriteHeader(growableWriter, DcerpcPduType.Response, callId);
        growableWriter.WriteUInt32((uint)stub.Length);
        growableWriter.WriteUInt16(0);
        growableWriter.WriteByte(0);
        growableWriter.WriteByte(0);
        growableWriter.WriteBytes(stub);
        PatchFragLength(growableWriter);
        return growableWriter.ToArray();
    }

    public static byte[] BuildFault(uint callId, uint status)
    {
        var growableWriter = new GrowableWriter(32);
        WriteHeader(growableWriter, DcerpcPduType.Fault, callId);
        growableWriter.WriteUInt32(0u);
        growableWriter.WriteUInt16(0);
        growableWriter.WriteByte(0);
        growableWriter.WriteByte(0);
        growableWriter.WriteUInt32(status);
        growableWriter.WriteUInt32(0u);
        PatchFragLength(growableWriter);
        return growableWriter.ToArray();
    }

    private static void WriteHeader(GrowableWriter w, DcerpcPduType type, uint callId)
    {
        w.WriteByte(5);
        w.WriteByte(0);
        w.WriteByte((byte)type);
        w.WriteByte(3);
        w.WriteUInt32(16u);
        w.WriteUInt16(0);
        w.WriteUInt16(0);
        w.WriteUInt32(callId);
    }

    private static void PatchFragLength(GrowableWriter w)
    {
        w.PatchUInt16(8, (ushort)w.Position);
    }

    private static void AlignTo4(GrowableWriter w)
    {
        while (w.Position % 4 != 0)
        {
            w.WriteByte(0);
        }
    }
}
