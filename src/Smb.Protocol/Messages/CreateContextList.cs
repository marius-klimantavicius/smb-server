using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public static class CreateContextList
{
	public static IReadOnlyList<CreateContext> Parse(ReadOnlySpan<byte> message, int contextsOffset, int contextsLength)
	{
		if (contextsLength <= 0)
		{
			return Array.Empty<CreateContext>();
		}

		if (contextsOffset < 0 || (uint)contextsOffset > (uint)message.Length || contextsLength > message.Length - contextsOffset)
		{
			throw new SmbWireFormatException("CREATE contexts extend past the message.");
		}

		var list = new List<CreateContext>();
		var num = contextsOffset;
		var num2 = contextsOffset + contextsLength;
		while (true)
		{
			if (num + 16 > num2)
			{
				throw new SmbWireFormatException("CREATE context header extends past the context chain.");
			}

			var num3 = num;
			var readOnlySpan = message.Slice(num3, num2 - num3);
			var num4 = BinaryPrimitives.ReadUInt32LittleEndian(readOnlySpan);
			if (num4 != 0)
			{
				if ((num4 & 7) != 0 || num4 < 16 || num4 > (uint)(num2 - num3 - 16)) throw new SmbWireFormatException("CREATE context Next out of range/alignment.");

				readOnlySpan = readOnlySpan.Slice(0, (int)num4);
			}

			int offset = BinaryPrimitives.ReadUInt16LittleEndian(readOnlySpan.Slice(4));
			int length = BinaryPrimitives.ReadUInt16LittleEndian(readOnlySpan.Slice(6));
			if (length < 4) throw new SmbWireFormatException("CREATE context name requires at least four bytes.");
			int offset2 = BinaryPrimitives.ReadUInt16LittleEndian(readOnlySpan.Slice(10));
			var num5 = (int)BinaryPrimitives.ReadUInt32LittleEndian(readOnlySpan.Slice(12));
			if (num5 < 0) throw new SmbWireFormatException("CREATE context data extends past the context.");
			if ((length > 0 && (offset & 7) != 0) || (num5 > 0 && (offset2 & 7) != 0)) throw new SmbWireFormatException("CREATE context name/data must be 8-byte aligned.");

			var name = ReadSlice(readOnlySpan, offset, length, "name");
			var data = ((num5 > 0) ? ReadSlice(readOnlySpan, offset2, num5, "data") : Array.Empty<byte>());
			list.Add(new CreateContext
			{
				Name = name,
				Data = data,
			});
			if (num4 == 0)
			{
				break;
			}

			var num6 = num + num4;
			if (num6 <= num || num6 + 16 > num2)
			{
				throw new SmbWireFormatException("CREATE context Next offset out of range.");
			}

			num = (int)num6;
		}

		return list;
	}

	public static CreateContext? Find(IReadOnlyList<CreateContext> contexts, uint tag)
	{
		foreach (var context in contexts)
		{
			if (context.Tag == tag)
			{
				return context;
			}
		}

		return null;
	}

	public static byte[] Serialize(IReadOnlyList<CreateContext> contexts)
	{
		if (contexts.Count == 0)
		{
			return Array.Empty<byte>();
		}

		var growableWriter = new GrowableWriter(64);
		for (var i = 0; i < contexts.Count; i++)
		{
			var createContext = contexts[i];
			var flag = i == contexts.Count - 1;
			var position = growableWriter.Position;
			growableWriter.WriteUInt32(0u);
			growableWriter.WriteUInt16(0);
			growableWriter.WriteUInt16((ushort)createContext.Name.Length);
			growableWriter.WriteUInt16(0);
			growableWriter.WriteUInt16(0);
			growableWriter.WriteUInt32((uint)createContext.Data.Length);
			var num = growableWriter.Position - position;
			growableWriter.WriteBytes(createContext.Name);
			growableWriter.PatchUInt16(position + 4, (ushort)num);
			var num2 = 0;
			if (createContext.Data.Length != 0)
			{
				growableWriter.AlignTo(8, position);
				num2 = growableWriter.Position - position;
				growableWriter.WriteBytes(createContext.Data);
			}

			growableWriter.PatchUInt16(position + 10, (ushort)num2);
			if (!flag)
			{
				growableWriter.AlignTo(8, position);
				growableWriter.PatchUInt32(position, (uint)(growableWriter.Position - position));
			}
		}

		return growableWriter.ToArray();
	}

	private static byte[] ReadSlice(ReadOnlySpan<byte> ctx, int offset, int length, string what)
	{
		if (length == 0)
		{
			return Array.Empty<byte>();
		}

		if (offset < 16 || length < 0 || offset > ctx.Length || length > ctx.Length - offset)
		{
			throw new SmbWireFormatException("CREATE context " + what + " extends past the context.");
		}

		return ctx.Slice(offset, length).ToArray();
	}
}
