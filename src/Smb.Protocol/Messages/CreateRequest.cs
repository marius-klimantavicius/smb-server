using System;
using System.Collections.Generic;
using System.Text;
using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public sealed class CreateRequest
{
	public const ushort ExpectedStructureSize = 57;

	public OplockLevel RequestedOplockLevel { get; init; }

	public uint DesiredAccess { get; init; }

	public uint FileAttributes { get; init; }

	public uint ShareAccess { get; init; }

	public CreateDisposition Disposition { get; init; }

	public CreateOptions Options { get; init; }

	public string Name { get; init; } = string.Empty;

	public IReadOnlyList<CreateContext> Contexts { get; init; } = Array.Empty<CreateContext>();

	public static CreateRequest Parse(ReadOnlySpan<byte> message, int bodyOffset)
	{
		var spanReader = new SpanReader(message.Slice(bodyOffset));
		var num = spanReader.ReadUInt16();
		if (num != ExpectedStructureSize)
		{
			throw new SmbWireFormatException($"CREATE Request StructureSize {num} ≠ {ExpectedStructureSize}.");
		}

		spanReader.Skip(1);
		var requestedOplockLevel = (OplockLevel)spanReader.ReadByte();
		spanReader.Skip(4);
		spanReader.Skip(8);
		spanReader.Skip(8);
		var desiredAccess = spanReader.ReadUInt32();
		var fileAttributes = spanReader.ReadUInt32();
		var shareAccess = spanReader.ReadUInt32();
		var disposition = (CreateDisposition)spanReader.ReadUInt32();
		var options = (CreateOptions)spanReader.ReadUInt32();
		var num2 = spanReader.ReadUInt16();
		var num3 = spanReader.ReadUInt16();
		var contextsOffset = (int)spanReader.ReadUInt32();
		var contextsLength = (int)spanReader.ReadUInt32();
		var text = string.Empty;
		if (num3 > 0)
		{
			if (num2 + num3 > message.Length)
			{
				throw new SmbWireFormatException("CREATE name extends past the message.");
			}

			text = Encoding.Unicode.GetString(message.Slice(num2, num3));
		}

		var contexts = CreateContextList.Parse(message, contextsOffset, contextsLength);
		return new CreateRequest
		{
			RequestedOplockLevel = requestedOplockLevel,
			DesiredAccess = desiredAccess,
			FileAttributes = fileAttributes,
			ShareAccess = shareAccess,
			Disposition = disposition,
			Options = options,
			Name = text.TrimStart('\\'),
			Contexts = contexts,
		};
	}
}
