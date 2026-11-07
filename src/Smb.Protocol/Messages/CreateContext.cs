using System.Buffers.Binary;

namespace Smb.Protocol.Messages;

public sealed class CreateContext
{
	public required byte[] Name { get; init; }

	public required byte[] Data { get; init; }

	public uint Tag
	{
		get
		{
			if (Name.Length != 4)
			{
				return 0u;
			}

			return BinaryPrimitives.ReadUInt32BigEndian(Name);
		}
	}
}
