using System;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public static class CancelMessage
{
	public const ushort RequestStructureSize = 4;

	public static void ParseRequest(ReadOnlySpan<byte> message, int bodyOffset)
	{
		var num = new SpanReader(message.Slice(bodyOffset)).ReadUInt16();
		if (num != RequestStructureSize)
		{
			throw new SmbWireFormatException($"CANCEL Request StructureSize {num} ≠ {RequestStructureSize}.");
		}
	}
}
