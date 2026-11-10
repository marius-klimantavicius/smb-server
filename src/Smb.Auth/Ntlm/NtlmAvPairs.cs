using System;
using System.Collections.Generic;
using Smb.Protocol.Wire;

namespace Smb.Auth.Ntlm;

public static class NtlmAvPairs
{
    public static byte[] Encode(IEnumerable<NtlmAvPair> pairs)
    {
        var growableWriter = new GrowableWriter(128);
        foreach (var pair in pairs)
        {
            growableWriter.WriteUInt16((ushort)pair.Id);
            growableWriter.WriteUInt16((ushort)pair.Value.Length);
            growableWriter.WriteBytes(pair.Value);
        }

        growableWriter.WriteUInt16(0);
        growableWriter.WriteUInt16(0);
        return growableWriter.ToArray();
    }

    public static List<NtlmAvPair> Decode(ReadOnlySpan<byte> data)
    {
        var list = new List<NtlmAvPair>();
        var spanReader = new SpanReader(data);
        while (spanReader.Remaining >= 4)
        {
            var ntlmAvId = (NtlmAvId)spanReader.ReadUInt16();
            int num = spanReader.ReadUInt16();
            if (ntlmAvId == NtlmAvId.EOL || num > spanReader.Remaining)
            {
                break;
            }

            list.Add(new NtlmAvPair(ntlmAvId, spanReader.ReadByteArray(num)));
        }

        return list;
    }
}
