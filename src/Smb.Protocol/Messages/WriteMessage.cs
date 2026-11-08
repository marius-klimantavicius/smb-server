using System;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public static class WriteMessage
{
	public readonly record struct Request(ulong Offset, ulong PersistentId, ulong VolatileId, byte[] Data)
	{
		public ushort DataOffset { get; init; }
		public byte FlagsByte { get; init; }
		public uint Flags { get; init; }
		public uint Channel { get; init; }
		public uint RemainingBytes { get; init; }
		public ushort ChannelInfoOffset { get; init; }
		public ushort ChannelInfoLength { get; init; }
	}

	public const ushort RequestStructureSize = 49;

	public const ushort ResponseStructureSize = 17;

	public static Request ParseRequest(ReadOnlySpan<byte> message, int bodyOffset)
	{
		var spanReader = new SpanReader(message.Slice(bodyOffset));
		var num = spanReader.ReadUInt16();
		if (num != RequestStructureSize)
		{
			throw new SmbWireFormatException($"WRITE Request StructureSize {num} ≠ {RequestStructureSize}.");
		}

		var num2 = spanReader.ReadUInt16();
		var num3 = spanReader.ReadUInt32();
		var offset = spanReader.ReadUInt64();
		var persistentId = spanReader.ReadUInt64();
		var volatileId = spanReader.ReadUInt64();
		var channel = spanReader.ReadUInt32();
		var remaining = spanReader.ReadUInt32();
		var infoOffset = spanReader.ReadUInt16();
		var infoLength = spanReader.ReadUInt16();
		var flags = spanReader.ReadUInt32();
		RequestBounds.Buffer(message, num2, num3, bodyOffset + 48, "WRITE data");
		var data = Array.Empty<byte>();
		if (num3 != 0)
		{
			if (num2 + (long)num3 > message.Length)
			{
				throw new SmbWireFormatException("WRITE data extends past the message.");
			}

			data = message.Slice(num2, (int)num3).ToArray();
		}

		return new Request(offset, persistentId, volatileId, data)
		{
			DataOffset = num2,
			Flags = flags,
			Channel = channel,
			RemainingBytes = remaining,
			ChannelInfoOffset = infoOffset,
			ChannelInfoLength = infoLength
		};
	}

	public static byte[] BuildResponseBody(uint count)
	{
		var array = new byte[16];
		var spanWriter = new SpanWriter(array);
		spanWriter.WriteUInt16(ResponseStructureSize);
		spanWriter.WriteUInt16(0);
		spanWriter.WriteUInt32(count);
		spanWriter.WriteUInt32(0u);
		spanWriter.WriteUInt16(0);
		spanWriter.WriteUInt16(0);
		return array;
	}
}
