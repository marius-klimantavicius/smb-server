using System;
using System.Text;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public sealed class TreeConnectRequest
{
    public const ushort ExpectedStructureSize = 9;

    public string Path { get; init; } = string.Empty;

    public string ShareName
    {
        get
        {
            var num = Path.LastIndexOf('\\');
            if (num < 0)
            {
                return Path;
            }

            return Path.Substring(num + 1);
        }
    }

    public static TreeConnectRequest Parse(ReadOnlySpan<byte> message, int bodyOffset)
    {
        var spanReader = new SpanReader(message.Slice(bodyOffset));
        var num = spanReader.ReadUInt16();
        if (num != ExpectedStructureSize)
        {
            throw new SmbWireFormatException($"TREE_CONNECT Request StructureSize {num} ≠ {ExpectedStructureSize}.");
        }

        spanReader.Skip(2);
        var num2 = spanReader.ReadUInt16();
        var num3 = spanReader.ReadUInt16();
        RequestBounds.Buffer(message, num2, num3, bodyOffset + 8, "TREE_CONNECT path");
        var path = string.Empty;
        if (num3 > 0)
        {
            if (num2 + num3 > message.Length)
            {
                throw new SmbWireFormatException("TREE_CONNECT path extends past the message.");
            }

            path = RequestBounds.ReadUnicode(message.Slice(num2, num3), "TREE_CONNECT path");
        }

        return new TreeConnectRequest
        {
            Path = path,
        };
    }
}
