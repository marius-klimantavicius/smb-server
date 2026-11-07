using System;
using System.Text;
using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public static class SetInfoMessage
{
	public readonly record struct Request(InfoType InfoType, byte FileInfoClass, uint AdditionalInformation, ulong PersistentId, ulong VolatileId, byte[] Buffer);

	public const ushort RequestStructureSize = 33;

	public const ushort ResponseStructureSize = 2;

	public static Request ParseRequest(ReadOnlySpan<byte> message, int bodyOffset)
	{
		var spanReader = new SpanReader(message.Slice(bodyOffset));
		var num = spanReader.ReadUInt16();
		if (num != RequestStructureSize)
		{
			throw new SmbWireFormatException($"SET_INFO Request StructureSize {num} ≠ {RequestStructureSize}.");
		}

		var infoType = spanReader.ReadByte();
		var fileInfoClass = spanReader.ReadByte();
		var num2 = spanReader.ReadUInt32();
		var num3 = spanReader.ReadUInt16();
		spanReader.ReadUInt16();
		var additionalInformation = spanReader.ReadUInt32();
		var persistentId = spanReader.ReadUInt64();
		var volatileId = spanReader.ReadUInt64();
		var buffer = Array.Empty<byte>();
		if (num2 != 0)
		{
			if (num3 + num2 > message.Length)
			{
				throw new SmbWireFormatException("SET_INFO buffer extends past the message.");
			}

			buffer = message.Slice(num3, (int)num2).ToArray();
		}

		return new Request((InfoType)infoType, fileInfoClass, additionalInformation, persistentId, volatileId, buffer);
	}

	public static byte[] BuildResponseBody()
	{
		var array = new byte[ResponseStructureSize];
		new SpanWriter(array).WriteUInt16(ResponseStructureSize);
		return array;
	}

	public static FileBasicInfoUpdate ParseBasicInfo(ReadOnlySpan<byte> buffer)
	{
		if (buffer.Length < 36)
		{
			throw new SmbWireFormatException($"FileBasicInformation requires 36 bytes, got {buffer.Length}.");
		}

		var spanReader = new SpanReader(buffer);
		var creationTime = Stamp(spanReader.ReadInt64());
		var lastAccessTime = Stamp(spanReader.ReadInt64());
		var lastWriteTime = Stamp(spanReader.ReadInt64());
		var changeTime = Stamp(spanReader.ReadInt64());
		var attributes = spanReader.ReadUInt32();
		return new FileBasicInfoUpdate
		{
			CreationTime = creationTime,
			LastAccessTime = lastAccessTime,
			LastWriteTime = lastWriteTime,
			ChangeTime = changeTime,
			Attributes = attributes != 0 ? attributes : null,
		};

		static long? Stamp(long v)
		{
			if ((ulong)(v - -1) > 1uL)
			{
				return v;
			}

			return null;
		}
	}

	public static (bool replaceIfExists, string newPath) ParseRename(ReadOnlySpan<byte> buffer)
	{
		var spanReader = new SpanReader(buffer);
		var b = spanReader.ReadByte();
		spanReader.Skip(7);
		spanReader.Skip(8);
		var num = (int)spanReader.ReadUInt32();
		var text = ((num > 0) ? Encoding.Unicode.GetString(spanReader.ReadBytes(num)) : string.Empty);
		return (replaceIfExists: b != 0, newPath: text.TrimStart('\\'));
	}
}
