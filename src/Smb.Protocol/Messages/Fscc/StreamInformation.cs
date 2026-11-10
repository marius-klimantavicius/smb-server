using System;
using System.Collections.Generic;
using System.Text;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages.Fscc;

public static class StreamInformation
{
    public static byte[] Build(IReadOnlyList<FsccStreamEntry> streams)
    {
        if (streams.Count == 0)
        {
            return Array.Empty<byte>();
        }

        var list = new List<byte[]>(streams.Count);
        foreach (var stream in streams)
        {
            list.Add(SerializeEntry(stream));
        }

        var growableWriter = new GrowableWriter(64);
        for (var i = 0; i < list.Count; i++)
        {
            var position = growableWriter.Position;
            growableWriter.WriteBytes(list[i]);
            if (i != list.Count - 1)
            {
                var num = Align8(growableWriter.Position - position) - (growableWriter.Position - position);
                if (num > 0)
                {
                    growableWriter.WriteZeros(num);
                }

                growableWriter.PatchUInt32(position, (uint)(growableWriter.Position - position));
            }
            else
            {
                growableWriter.PatchUInt32(position, 0u);
            }
        }

        return growableWriter.ToArray();
    }

    private static byte[] SerializeEntry(FsccStreamEntry s)
    {
        var bytes = Encoding.Unicode.GetBytes(":" + s.StreamName + ":$DATA");
        var growableWriter = new GrowableWriter(24 + bytes.Length);
        growableWriter.WriteUInt32(0u);
        growableWriter.WriteUInt32((uint)bytes.Length);
        growableWriter.WriteUInt64((ulong)s.Size);
        growableWriter.WriteUInt64((ulong)s.AllocationSize);
        growableWriter.WriteBytes(bytes);
        return growableWriter.ToArray();
    }

    private static int Align8(int v)
    {
        return (v + 7) & -8;
    }
}
