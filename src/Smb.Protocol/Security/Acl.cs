using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Security;

public sealed class Acl
{
    public const byte RevisionDefault = 2;

    public const byte RevisionDs = 4;

    private const int HeaderSize = 8;

    public byte Revision { get; init; } = RevisionDefault;

    public IReadOnlyList<Ace> Aces { get; init; } = Array.Empty<Ace>();

    public int BinaryLength
    {
        get
        {
            var num = HeaderSize;
            foreach (var ace in Aces)
            {
                num += ace.BinaryLength;
            }

            return num;
        }
    }

    public static Acl Parse(ReadOnlySpan<byte> data, out int consumed)
    {
        if (data.Length < HeaderSize)
        {
            throw new SmbWireFormatException($"ACL header needs {HeaderSize} bytes, has {data.Length}.");
        }

        var revision = data[0];
        int num = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(2, 2));
        int num2 = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(4, 2));
        if (num < HeaderSize || num > data.Length)
        {
            throw new SmbWireFormatException($"ACL size {num} invalid (buffer {data.Length}).");
        }

        var list = new List<Ace>(num2);
        var num3 = HeaderSize;
        for (var i = 0; i < num2; i++)
        {
            var item = Ace.Parse(data.Slice(num3, num - num3), out var consumed2);
            list.Add(item);
            num3 += consumed2;
        }

        consumed = num;
        return new Acl
        {
            Revision = revision,
            Aces = list,
        };
    }

    public void Write(ref SpanWriter w)
    {
        w.WriteByte(Revision);
        w.WriteByte(0);
        w.WriteUInt16((ushort)BinaryLength);
        w.WriteUInt16((ushort)Aces.Count);
        w.WriteUInt16(0);
        foreach (var ace in Aces)
        {
            ace.Write(ref w);
        }
    }

    public byte[] ToBytes()
    {
        var array = new byte[BinaryLength];
        var w = new SpanWriter(array);
        Write(ref w);
        return array;
    }
}
