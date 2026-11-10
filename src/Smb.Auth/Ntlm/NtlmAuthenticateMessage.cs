using System;
using System.Text;
using Smb.Protocol.Wire;

namespace Smb.Auth.Ntlm;

public sealed class NtlmAuthenticateMessage
{
    public byte[] LmChallengeResponse { get; init; } = Array.Empty<byte>();

    public byte[] NtChallengeResponse { get; init; } = Array.Empty<byte>();

    public string DomainName { get; init; } = string.Empty;

    public string UserName { get; init; } = string.Empty;

    public string Workstation { get; init; } = string.Empty;

    public byte[] EncryptedRandomSessionKey { get; init; } = Array.Empty<byte>();

    public NtlmNegotiateFlags Flags { get; init; }

    public byte[] Mic { get; init; } = new byte[16];

    public ReadOnlySpan<byte> NtProofString => NtChallengeResponse.AsSpan(0, 16);

    public ReadOnlySpan<byte> ClientChallengeBlob => NtChallengeResponse.AsSpan(16);

    public static NtlmAuthenticateMessage Parse(ReadOnlySpan<byte> data)
    {
        if (!NtlmConstants.IsNtlmSsp(data))
        {
            throw new FormatException("Not an NTLMSSP token.");
        }

        var r = new SpanReader(data);
        r.Skip(8);
        if (r.ReadUInt32() != 3)
        {
            throw new FormatException("Not an AUTHENTICATE_MESSAGE.");
        }

        var tuple = ReadField(ref r);
        var item = tuple.len;
        var item2 = tuple.off;
        var tuple2 = ReadField(ref r);
        var item3 = tuple2.len;
        var item4 = tuple2.off;
        var tuple3 = ReadField(ref r);
        var item5 = tuple3.len;
        var item6 = tuple3.off;
        var tuple4 = ReadField(ref r);
        var item7 = tuple4.len;
        var item8 = tuple4.off;
        var tuple5 = ReadField(ref r);
        var item9 = tuple5.len;
        var item10 = tuple5.off;
        var tuple6 = ReadField(ref r);
        var item11 = tuple6.len;
        var item12 = tuple6.off;
        var flags = (NtlmNegotiateFlags)r.ReadUInt32();
        var minimum = flags.HasFlag(NtlmNegotiateFlags.NegotiateVersion) ? 72 : 64;
        if (data.Length < minimum) throw new FormatException("Truncated AUTHENTICATE_MESSAGE Version.");
        ValidateField(data, item4, item3, minimum);
        var ntResponse = Slice(data, item4, item3);
        var hasMic = false;
        if (ntResponse.Length >= 48)
            foreach (var pair in NtlmAvPairs.Decode(ntResponse.AsSpan(44)))
                if (pair.Id == NtlmAvId.Flags && pair.Value.Length >= 4 && (pair.Value[0] & 2) != 0) hasMic = true;
        // An announced MIC occupies the protocol's reserved Version + MIC layout.
        // Without it, a compact message may omit Version and start Payload at 64.
        if (hasMic) minimum = 88;
        ValidateField(data, item2, item, minimum);
        ValidateField(data, item4, item3, minimum);
        ValidateField(data, item6, item5, minimum);
        ValidateField(data, item8, item7, minimum);
        ValidateField(data, item10, item9, minimum);
        var keyExchange = flags.HasFlag(NtlmNegotiateFlags.NegotiateKeyExchange);
        if (keyExchange) ValidateField(data, item12, item11, minimum);
        if (item is not (0 or 24)) throw new FormatException("Invalid LM response size.");
        // Preserve the mechanism's terminal proof-too-short rejection before
        // interpreting the text fields of an unusable authentication attempt.
        if (ntResponse.Length >= 16 && flags.HasFlag(NtlmNegotiateFlags.NegotiateUnicode))
        {
            ValidateUnicodeField(item6, item5);
            ValidateUnicodeField(item8, item7);
            ValidateUnicodeField(item10, item9);
        }
        var mic = hasMic ? Slice(data, 72, 16) : new byte[16];

        return new NtlmAuthenticateMessage
        {
            LmChallengeResponse = Slice(data, item2, item),
            NtChallengeResponse = ntResponse,
            DomainName = Unicode(data, item6, item5),
            UserName = Unicode(data, item8, item7),
            Workstation = Unicode(data, item10, item9),
            EncryptedRandomSessionKey = keyExchange ? Slice(data, item12, item11) : Array.Empty<byte>(),
            Flags = flags,
            Mic = mic,
        };
    }

    private static (int len, int off) ReadField(ref SpanReader r)
    {
        var item = r.ReadUInt16();
        r.Skip(2);
        var item2 = (int)r.ReadUInt32();
        return (len: item, off: item2);
    }

    private static byte[] Slice(ReadOnlySpan<byte> data, int off, int len)
    {
        if (len == 0)
        {
            return Array.Empty<byte>();
        }

        EnsureInBounds(data.Length, off, len);
        return data.Slice(off, len).ToArray();
    }

    private static string Unicode(ReadOnlySpan<byte> data, int off, int len)
    {
        if (len == 0)
        {
            return string.Empty;
        }

        EnsureInBounds(data.Length, off, len);
        return Encoding.Unicode.GetString(data.Slice(off, len));
    }

    private static void EnsureInBounds(int dataLength, int off, int len)
    {
        if (off < 0 || len < 0 || off > dataLength - len)
        {
            throw new FormatException("NTLM AUTHENTICATE field references data outside the message.");
        }
    }

    private static void ValidateField(ReadOnlySpan<byte> data, int off, int len, int minimum)
    {
        // Absent values have no referenced bytes; their suggested offsets and
        // MaxLen fields do not impose a payload or message-length requirement.
        if (len == 0) return;
        if (off < minimum) throw new FormatException("AUTHENTICATE field overlaps its fixed fields.");
        EnsureInBounds(data.Length, off, len);
    }

    private static void ValidateUnicodeField(int off, int len)
    {
        if (len != 0 && ((off | len) & 1) != 0) throw new FormatException("AUTHENTICATE Unicode field is not two-byte aligned.");
    }
}
