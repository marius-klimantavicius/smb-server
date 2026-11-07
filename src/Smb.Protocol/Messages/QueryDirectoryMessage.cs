using System;
using System.Text;
using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public static class QueryDirectoryMessage
{
	public readonly record struct Request(FileInformationClass InfoClass, byte Flags, ulong PersistentId, ulong VolatileId, string SearchPattern, uint OutputBufferLength);

	public const ushort RequestStructureSize = 33;

	public const ushort ResponseStructureSize = 9;

	public const byte FlagRestartScan = 1;

	public const byte FlagReturnSingleEntry = 2;

	public static Request ParseRequest(ReadOnlySpan<byte> message, int bodyOffset)
	{
		var spanReader = new SpanReader(message.Slice(bodyOffset));
		var num = spanReader.ReadUInt16();
		if (num != RequestStructureSize)
		{
			throw new SmbWireFormatException($"QUERY_DIRECTORY Request StructureSize {num} ≠ {RequestStructureSize}.");
		}

		var infoClass = spanReader.ReadByte();
		var flags = spanReader.ReadByte();
		spanReader.ReadUInt32();
		var persistentId = spanReader.ReadUInt64();
		var volatileId = spanReader.ReadUInt64();
		var num2 = spanReader.ReadUInt16();
		var num3 = spanReader.ReadUInt16();
		var outputBufferLength = spanReader.ReadUInt32();
		var searchPattern = string.Empty;
		if (num3 > 0 && num2 + num3 <= message.Length)
		{
			searchPattern = Encoding.Unicode.GetString(message.Slice(num2, num3));
		}

		return new Request((FileInformationClass)infoClass, flags, persistentId, volatileId, searchPattern, outputBufferLength);
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
