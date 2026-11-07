using System;
using System.Collections.Generic;
using System.Text;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages.Fscc;

public static class FullEaInformation
{
	public static byte[] Build(IReadOnlyList<FsccEaEntry> eas)
	{
		if (eas.Count == 0)
		{
			return Array.Empty<byte>();
		}

		var list = new List<byte[]>(eas.Count);
		foreach (var ea in eas)
		{
			list.Add(SerializeEntry(ea));
		}

		var growableWriter = new GrowableWriter(64);
		for (var i = 0; i < list.Count; i++)
		{
			var position = growableWriter.Position;
			growableWriter.WriteBytes(list[i]);
			if (i != list.Count - 1)
			{
				var num = Align4(growableWriter.Position - position) - (growableWriter.Position - position);
				if (num > 0)
				{
					growableWriter.WriteZeros(num);
				}

				growableWriter.PatchUInt32(position, (uint)(growableWriter.Position - position));
			}
			else
			{
				growableWriter.PatchUInt32(position, 0u);
			}
		}

		return growableWriter.ToArray();
	}

	private static byte[] SerializeEntry(FsccEaEntry ea)
	{
		var bytes = Encoding.ASCII.GetBytes(ea.Name);
		var array = ea.Value ?? Array.Empty<byte>();
		var growableWriter = new GrowableWriter(8 + bytes.Length + 1 + array.Length);
		growableWriter.WriteUInt32(0u);
		growableWriter.WriteByte(ea.Flags);
		growableWriter.WriteByte((byte)bytes.Length);
		growableWriter.WriteUInt16((ushort)array.Length);
		growableWriter.WriteBytes(bytes);
		growableWriter.WriteByte(0);
		growableWriter.WriteBytes(array);
		return growableWriter.ToArray();
	}

	public static IReadOnlyList<FsccEaEntry> Parse(ReadOnlySpan<byte> buffer)
	{
		var list = new List<FsccEaEntry>();
		uint num;
		for (var i = 0; i < buffer.Length; i += (int)num)
		{
			var spanReader = new SpanReader(buffer.Slice(i));
			num = spanReader.ReadUInt32();
			var flags = spanReader.ReadByte();
			int num2 = spanReader.ReadByte();
			int num3 = spanReader.ReadUInt16();
			var name = ((num2 > 0) ? Encoding.ASCII.GetString(spanReader.ReadBytes(num2)) : string.Empty);
			spanReader.ReadByte();
			var value = ((num3 > 0) ? spanReader.ReadByteArray(num3) : Array.Empty<byte>());
			list.Add(new FsccEaEntry(flags, name, value));
			if (num == 0)
			{
				break;
			}

			var position = spanReader.Position;
			if (num < (uint)position || i + num > buffer.Length)
			{
				throw new SmbWireFormatException($"FILE_FULL_EA_INFORMATION NextEntryOffset {num} out of range (entry consumed {position}, at {i}/{buffer.Length}).");
			}
		}

		return list;
	}

	public static uint ComputeEaSize(IReadOnlyList<FsccEaEntry> eas)
	{
		var num = 0L;
		for (var i = 0; i < eas.Count; i++)
		{
			var num2 = 8 + eas[i].Name.Length + 1 + (eas[i].Value?.Length ?? 0);
			num += (i == eas.Count - 1) ? num2 : Align4(num2);
		}

		return (uint)num;
	}

	private static int Align4(int v)
	{
		return (v + 3) & -4;
	}
}
