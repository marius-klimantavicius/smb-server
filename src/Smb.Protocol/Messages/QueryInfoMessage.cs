using System;
using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public static class QueryInfoMessage
{
	public readonly record struct Request(InfoType InfoType, byte FileInfoClass, uint OutputBufferLength, uint AdditionalInformation, ulong PersistentId, ulong VolatileId, byte[] InputBuffer);

	public const ushort RequestStructureSize = 41;

	public const ushort ResponseStructureSize = 9;

	public static Request ParseRequest(ReadOnlySpan<byte> message, int bodyOffset)
	{
		var spanReader = new SpanReader(message.Slice(bodyOffset));
		var num = spanReader.ReadUInt16();
		if (num != RequestStructureSize)
		{
			throw new SmbWireFormatException($"QUERY_INFO Request StructureSize {num} ≠ {RequestStructureSize}.");
		}

		var infoType = spanReader.ReadByte();
		var fileInfoClass = spanReader.ReadByte();
		var outputBufferLength = spanReader.ReadUInt32();
		var num2 = spanReader.ReadUInt16();
		spanReader.ReadUInt16();
		var num3 = spanReader.ReadUInt32();
		var additionalInformation = spanReader.ReadUInt32();
		spanReader.ReadUInt32();
		var persistentId = spanReader.ReadUInt64();
		var volatileId = spanReader.ReadUInt64();
		var inputBuffer = Array.Empty<byte>();
		if (num3 != 0 && num2 + num3 <= message.Length)
		{
			inputBuffer = message.Slice(num2, (int)num3).ToArray();
		}

		return new Request((InfoType)infoType, fileInfoClass, outputBufferLength, additionalInformation, persistentId, volatileId, inputBuffer);
	}

	public static byte[] BuildResponseBody(ReadOnlySpan<byte> buffer)
	{
		var array = new byte[8 + buffer.Length];
		var spanWriter = new SpanWriter(array);
		spanWriter.WriteUInt16(ResponseStructureSize);
		spanWriter.WriteUInt16(72);
		spanWriter.WriteUInt32((uint)buffer.Length);
		spanWriter.WriteBytes(buffer);
		return array;
	}
}
