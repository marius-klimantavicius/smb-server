using System;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public static class CancelMessage
{
	public const ushort RequestStructureSize = 4;

	public static void ParseRequest(ReadOnlySpan<byte> message, int bodyOffset)
	{
		if (bodyOffset < 0 || bodyOffset > message.Length || message.Length - bodyOffset < 4) throw new SmbWireFormatException("Incomplete CANCEL fixed request.");

		var num = new SpanReader(message.Slice(bodyOffset)).ReadUInt16();
		if (num != RequestStructureSize)
		{
			throw new SmbWireFormatException($"CANCEL Request StructureSize {num} ≠ {RequestStructureSize}.");
		}
	}
}
