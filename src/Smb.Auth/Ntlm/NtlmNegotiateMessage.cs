using System;
using Smb.Protocol.Wire;

namespace Smb.Auth.Ntlm;

public sealed class NtlmNegotiateMessage
{
    public NtlmNegotiateFlags Flags { get; init; }

    public static NtlmNegotiateMessage Parse(ReadOnlySpan<byte> data)
    {
        if (!NtlmConstants.IsNtlmSsp(data))
        {
            throw new FormatException("Not an NTLMSSP token.");
        }

        var spanReader = new SpanReader(data);
        spanReader.Skip(8);
        if (spanReader.ReadUInt32() != 1)
        {
            throw new FormatException("Not a NEGOTIATE_MESSAGE.");
        }

        var flags = (NtlmNegotiateFlags)spanReader.ReadUInt32();
        // MS-NLMP 2.2.1.1: the two security buffers are fixed fields;
        // Version is present only when NEGOTIATE_VERSION is set.
        var minimum = flags.HasFlag(NtlmNegotiateFlags.NegotiateVersion) ? 40 : 32;
        if (data.Length < minimum) throw new FormatException("Truncated NEGOTIATE_MESSAGE.");
        ValidateField(data, 16, minimum, ((uint)flags & 0x1000) != 0);
        ValidateField(data, 24, minimum, ((uint)flags & 0x2000) != 0);
        return new NtlmNegotiateMessage
        {
            Flags = flags,
        };
    }

    private static void ValidateField(ReadOnlySpan<byte> data, int at, int minimum, bool supplied)
    {
        if (!supplied) return;
        var reader = new SpanReader(data.Slice(at, 8));
        var length = reader.ReadUInt16();
        reader.Skip(2); // MaxLen is ignored on receipt.
        var offset = reader.ReadUInt32();
        if (length != 0 && (offset < minimum || offset > data.Length || length > data.Length - offset))
            throw new FormatException("NEGOTIATE field outside payload.");
    }
}
