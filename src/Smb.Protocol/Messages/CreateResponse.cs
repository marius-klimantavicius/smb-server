using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public sealed class CreateResponse
{
	public const ushort StructureSize = 89;

	private const int ContextsAbsoluteOffset = 152;

	public OplockLevel OplockLevel { get; init; }

	public CreateAction CreateAction { get; init; }

	public long CreationTime { get; init; }

	public long LastAccessTime { get; init; }

	public long LastWriteTime { get; init; }

	public long ChangeTime { get; init; }

	public long AllocationSize { get; init; }

	public long EndOfFile { get; init; }

	public uint FileAttributes { get; init; }

	public ulong PersistentFileId { get; init; }

	public ulong VolatileFileId { get; init; }

	public byte[] ToBody(byte[]? contexts = null)
	{
		var flag = contexts != null && contexts.Length > 0;
		var array = new byte[flag ? (88 + contexts.Length) : 88];
		var spanWriter = new SpanWriter(array);
		spanWriter.WriteUInt16(StructureSize);
		spanWriter.WriteByte((byte)OplockLevel);
		spanWriter.WriteByte(0);
		spanWriter.WriteUInt32((uint)CreateAction);
		spanWriter.WriteInt64(CreationTime);
		spanWriter.WriteInt64(LastAccessTime);
		spanWriter.WriteInt64(LastWriteTime);
		spanWriter.WriteInt64(ChangeTime);
		spanWriter.WriteInt64(AllocationSize);
		spanWriter.WriteInt64(EndOfFile);
		spanWriter.WriteUInt32(FileAttributes);
		spanWriter.WriteUInt32(0u);
		spanWriter.WriteUInt64(PersistentFileId);
		spanWriter.WriteUInt64(VolatileFileId);
		spanWriter.WriteUInt32(flag ? (uint)ContextsAbsoluteOffset : 0u);
		spanWriter.WriteUInt32(flag ? ((uint)contexts.Length) : 0u);
		if (flag)
		{
			spanWriter.WriteBytes(contexts);
		}

		return array;
	}
}
