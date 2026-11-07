using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public sealed class TreeConnectResponse
{
	public const ushort StructureSize = 16;

	public byte ShareType { get; init; }

	public ShareFlags ShareFlags { get; init; }

	public uint Capabilities { get; init; }

	public uint MaximalAccess { get; init; }

	public byte[] ToBody()
	{
		var array = new byte[StructureSize];
		var spanWriter = new SpanWriter(array);
		spanWriter.WriteUInt16(StructureSize);
		spanWriter.WriteByte(ShareType);
		spanWriter.WriteByte(0);
		spanWriter.WriteUInt32((uint)ShareFlags);
		spanWriter.WriteUInt32(Capabilities);
		spanWriter.WriteUInt32(MaximalAccess);
		return array;
	}
}
