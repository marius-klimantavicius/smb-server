using System;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public static class EchoMessage
{
	public const ushort StructureSize = 4;

	public static void ValidateRequest(ReadOnlySpan<byte> body)
	{
		var num = new SpanReader(body).ReadUInt16();
		if (num != StructureSize)
		{
			throw new SmbWireFormatException($"ECHO Request StructureSize {num} ≠ {StructureSize}.");
		}
	}

	public static byte[] BuildResponseBody()
	{
		var array = new byte[StructureSize];
		var spanWriter = new SpanWriter(array);
		spanWriter.WriteUInt16(StructureSize);
		spanWriter.WriteUInt16(0);
		return array;
	}
}
