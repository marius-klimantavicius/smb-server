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
		return new NtlmNegotiateMessage
		{
			Flags = flags,
		};
	}
}
