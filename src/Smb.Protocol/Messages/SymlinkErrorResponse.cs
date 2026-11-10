using System;
using System.Buffers.Binary;
using System.Text;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public static class SymlinkErrorResponse
{
    public readonly record struct Parsed(string SubstituteName, string PrintName, int UnparsedPathLength, bool IsRelative);

    public const uint SymLinkErrorTag = 1280137555u;

    public const uint IoReparseTagSymlink = 2684354572u;

    public const uint SymlinkFlagRelative = 1u;

    public static byte[] Build(string substituteName, string printName, int unparsedPathLength, bool relative)
    {
        ArgumentNullException.ThrowIfNull(substituteName);
        ArgumentNullException.ThrowIfNull(printName);
        var byteCount = Encoding.Unicode.GetByteCount(substituteName);
        var byteCount2 = Encoding.Unicode.GetByteCount(printName);
        var num = byteCount + byteCount2;
        var num2 = 12 + num;
        var num3 = 12 + num2;
        var array = new byte[4 + num3];
        var spanWriter = new SpanWriter(array);
        spanWriter.WriteUInt32((uint)num3);
        spanWriter.WriteUInt32(SymLinkErrorTag);
        spanWriter.WriteUInt32(IoReparseTagSymlink);
        spanWriter.WriteUInt16((ushort)num2);
        spanWriter.WriteUInt16((ushort)unparsedPathLength);
        spanWriter.WriteUInt16(0);
        spanWriter.WriteUInt16((ushort)byteCount);
        spanWriter.WriteUInt16((ushort)byteCount);
        spanWriter.WriteUInt16((ushort)byteCount2);
        spanWriter.WriteUInt32(relative ? SymlinkFlagRelative : 0u);
        spanWriter.WriteUtf16(substituteName);
        spanWriter.WriteUtf16(printName);
        return array;
    }

    public static Parsed Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < 28)
        {
            throw new SmbWireFormatException($"SYMLINK_ERROR_RESPONSE too short: {data.Length} bytes.");
        }

        var num = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(4, 4));
        if (num != SymLinkErrorTag)
        {
            throw new SmbWireFormatException($"Unexpected SymLinkErrorTag 0x{num:X8}.");
        }

        int unparsedPathLength = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(14, 2));
        int start = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(16, 2));
        int length = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(18, 2));
        int start2 = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(20, 2));
        int length2 = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(22, 2));
        var num2 = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(24, 4));
        var readOnlySpan = data.Slice(28);
        var substituteName = Encoding.Unicode.GetString(readOnlySpan.Slice(start, length));
        var printName = Encoding.Unicode.GetString(readOnlySpan.Slice(start2, length2));
        return new Parsed(substituteName, printName, unparsedPathLength, (num2 & SymlinkFlagRelative) != 0);
    }
}
