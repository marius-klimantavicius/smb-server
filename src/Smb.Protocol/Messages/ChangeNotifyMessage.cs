using System;
using System.Collections.Generic;
using System.Text;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public static class ChangeNotifyMessage
{
	public readonly record struct Request(ushort Flags, uint OutputBufferLength, ulong PersistentId, ulong VolatileId, uint CompletionFilter)
	{
		public bool WatchTree => (Flags & FlagWatchTree) != 0;
	}

	public const ushort RequestStructureSize = 32;

	public const ushort ResponseStructureSize = 9;

	public const ushort FlagWatchTree = 1;

	public static Request ParseRequest(ReadOnlySpan<byte> message, int bodyOffset)
	{
		var spanReader = new SpanReader(message.Slice(bodyOffset));
		var num = spanReader.ReadUInt16();
		if (num != RequestStructureSize)
		{
			throw new SmbWireFormatException($"CHANGE_NOTIFY Request StructureSize {num} ≠ {RequestStructureSize}.");
		}

		var flags = spanReader.ReadUInt16();
		var outputBufferLength = spanReader.ReadUInt32();
		var persistentId = spanReader.ReadUInt64();
		var volatileId = spanReader.ReadUInt64();
		var completionFilter = spanReader.ReadUInt32();
		spanReader.Skip(4);
		return new Request(flags, outputBufferLength, persistentId, volatileId, completionFilter);
	}

	public static (byte[] body, bool overflow) BuildResponseBody(IReadOnlyList<(uint Action, string Name)> changes, uint maxBufferLength)
	{
		var growableWriter = new GrowableWriter(64);
		for (var i = 0; i < changes.Count; i++)
		{
			var position = growableWriter.Position;
			var bytes = Encoding.Unicode.GetBytes(changes[i].Name);
			var position2 = growableWriter.Position;
			growableWriter.WriteUInt32(0u);
			growableWriter.WriteUInt32(changes[i].Action);
			growableWriter.WriteUInt32((uint)bytes.Length);
			growableWriter.WriteBytes(bytes);
			if (i < changes.Count - 1)
			{
				var num = (4 - growableWriter.Position % 4) % 4;
				if (num > 0)
				{
					growableWriter.WriteZeros(num);
				}

				growableWriter.PatchUInt32(position2, (uint)(growableWriter.Position - position));
			}
		}

		var array = growableWriter.ToArray();
		if (array.Length > maxBufferLength)
		{
			return (body: BuildEmptyResponseBody(), overflow: true);
		}

		var growableWriter2 = new GrowableWriter(8 + array.Length);
		growableWriter2.WriteUInt16(ResponseStructureSize);
		growableWriter2.WriteUInt16(72);
		growableWriter2.WriteUInt32((uint)array.Length);
		growableWriter2.WriteBytes(array);
		return (body: growableWriter2.ToArray(), overflow: false);
	}

	public static byte[] BuildEmptyResponseBody()
	{
		var array = new byte[8];
		var spanWriter = new SpanWriter(array);
		spanWriter.WriteUInt16(ResponseStructureSize);
		spanWriter.WriteUInt16(0);
		spanWriter.WriteUInt32(0u);
		return array;
	}
}
