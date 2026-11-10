using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using Smb.Protocol.Security;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public static class QuotaMessage
{
    public readonly record struct QueryRequest(bool ReturnSingle, bool RestartScan, IReadOnlyList<Sid> SidFilter);

    public const int EntryFixedSize = 40;

    public static QueryRequest ParseQueryInfo(ReadOnlySpan<byte> input)
    {
        if (input.Length < 16)
        {
            return new QueryRequest(ReturnSingle: false, RestartScan: false, Array.Empty<Sid>());
        }

        var spanReader = new SpanReader(input);
        var returnSingle = spanReader.ReadByte() != 0;
        var restartScan = spanReader.ReadByte() != 0;
        spanReader.Skip(2);
        var num = spanReader.ReadUInt32();
        var num2 = spanReader.ReadUInt32();
        var num3 = spanReader.ReadUInt32();
        var list = new List<Sid>();
        if (num != 0)
        {
            var i = 16;
            uint num5;
            for (var num4 = Math.Min(input.Length, 16L + num); i + 8 <= num4; i += (int)num5)
            {
                num5 = BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(i, 4));
                var num6 = BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(i + 4, 4));
                if (num6 != 0 && i + 8 + num6 <= input.Length)
                {
                    list.Add(Sid.Parse(input.Slice(i + 8, (int)num6)));
                }

                if (num5 == 0)
                {
                    break;
                }
            }
        }
        else if (num2 != 0 && num3 + num2 <= (uint)input.Length)
        {
            list.Add(Sid.Parse(input.Slice((int)num3, (int)num2)));
        }

        return new QueryRequest(returnSingle, restartScan, list);
    }

    public static byte[] BuildQuotaInformation(IReadOnlyList<FileQuotaInformation> entries, int maxBytes)
    {
        var growableWriter = new GrowableWriter(Math.Min(256, Math.Max(16, maxBytes)));
        var num = -1;
        foreach (var entry in entries)
        {
            var array = entry.Sid.ToBytes();
            var num2 = Align8(EntryFixedSize + array.Length);
            if (growableWriter.Position + num2 > maxBytes)
            {
                break;
            }

            var position = growableWriter.Position;
            growableWriter.WriteUInt32(0u);
            growableWriter.WriteUInt32((uint)array.Length);
            growableWriter.WriteUInt64((ulong)entry.ChangeTime);
            growableWriter.WriteUInt64((ulong)entry.QuotaUsed);
            growableWriter.WriteUInt64((ulong)entry.QuotaThreshold);
            growableWriter.WriteUInt64((ulong)entry.QuotaLimit);
            growableWriter.WriteBytes(array);
            while (growableWriter.Position < position + num2)
            {
                growableWriter.WriteByte(0);
            }

            if (num >= 0)
            {
                growableWriter.PatchUInt32(num, (uint)(position - num));
            }

            num = position;
        }

        return growableWriter.ToArray();
    }

    public static IReadOnlyList<FileQuotaInformation> ParseQuotaInformation(ReadOnlySpan<byte> buffer)
    {
        var list = new List<FileQuotaInformation>();
        uint num;
        for (var i = 0; i + EntryFixedSize <= buffer.Length; i += (int)num)
        {
            var spanReader = new SpanReader(buffer.Slice(i));
            num = spanReader.ReadUInt32();
            var num2 = spanReader.ReadUInt32();
            var changeTime = spanReader.ReadInt64();
            var quotaUsed = spanReader.ReadInt64();
            var quotaThreshold = spanReader.ReadInt64();
            var quotaLimit = spanReader.ReadInt64();
            if (num2 == 0 || i + EntryFixedSize + num2 > buffer.Length)
            {
                break;
            }

            var sid = Sid.Parse(buffer.Slice(i + EntryFixedSize, (int)num2));
            list.Add(new FileQuotaInformation(sid, changeTime, quotaUsed, quotaThreshold, quotaLimit));
            if (num == 0)
            {
                break;
            }
        }

        return list;
    }

    private static int Align8(int value)
    {
        return (value + 7) & -8;
    }
}
