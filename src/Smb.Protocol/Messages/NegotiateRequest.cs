using System;
using System.Collections.Generic;
using System.Linq;
using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public sealed class NegotiateRequest
{
	public const ushort ExpectedStructureSize = 36;

	public SmbSecurityMode SecurityMode { get; init; }

	public Smb2Capabilities Capabilities { get; init; }

	public byte[] ClientGuid { get; init; } = new byte[16];

	public IReadOnlyList<SmbDialect> Dialects { get; init; } = Array.Empty<SmbDialect>();

	public IReadOnlyList<NegotiateContext> NegotiateContexts { get; init; } = Array.Empty<NegotiateContext>();

	public bool OffersSmb311 => Dialects.Contains(SmbDialect.Smb311);

	public static NegotiateRequest Parse(ReadOnlySpan<byte> message, int bodyOffset)
	{
		var buffer = message.Slice(bodyOffset);
		var spanReader = new SpanReader(buffer);
		var num = spanReader.ReadUInt16();
		if (num != ExpectedStructureSize)
		{
			throw new SmbWireFormatException($"NEGOTIATE Request StructureSize {num} ≠ {ExpectedStructureSize}.");
		}

		int num2 = spanReader.ReadUInt16();
		if (num2 > 64 || num2 == 0)
		{
			throw new SmbWireFormatException($"NEGOTIATE DialectCount {num2} invalid.");
		}

		var securityMode = (SmbSecurityMode)spanReader.ReadUInt16();
		spanReader.Skip(2);
		var capabilities = (Smb2Capabilities)spanReader.ReadUInt32();
		var clientGuid = spanReader.ReadByteArray(16);
		var num3 = spanReader.ReadUInt32();
		var num4 = spanReader.ReadUInt16();
		spanReader.Skip(2);
		var array = new SmbDialect[num2];
		for (var i = 0; i < num2; i++)
		{
			array[i] = (SmbDialect)spanReader.ReadUInt16();
		}

		var list = new List<NegotiateContext>();
		if (Array.IndexOf(array, SmbDialect.Smb311) >= 0 && num3 != 0 && num4 > 0)
		{
			// Validate the unsigned wire offset before converting it for slicing.
			RequestBounds.Buffer(message, num3, 8, bodyOffset + 36 + num2 * 2, "NEGOTIATE contexts");
			if ((num3 & 7) != 0) throw new SmbWireFormatException("NEGOTIATE contexts must be 8-byte aligned.");
			ParseContexts(message, (int)num3, num4, list);
		}

		return new NegotiateRequest
		{
			SecurityMode = securityMode,
			Capabilities = capabilities,
			ClientGuid = clientGuid,
			Dialects = array,
			NegotiateContexts = list,
		};
	}

	private static void ParseContexts(ReadOnlySpan<byte> message, int offset, int count, List<NegotiateContext> sink)
	{
		var num = offset;
		for (var i = 0; i < count; i++)
		{
			if (num < 0 || num > message.Length || message.Length - num < 8)
			{
				throw new SmbWireFormatException("Negotiate context extends past the end of the message.");
			}

			var item = NegotiateContext.Read(message.Slice(num), out var consumed);
			sink.Add(item);
			num += consumed;
			if (i < count - 1)
			{
				num = Align8(num);
			}
		}
	}

	private static int Align8(int value)
	{
		return (value + 7) & -8;
	}
}
