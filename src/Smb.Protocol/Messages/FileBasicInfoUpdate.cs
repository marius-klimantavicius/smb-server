namespace Smb.Protocol.Messages;

public sealed class FileBasicInfoUpdate
{
	public bool? SuppressLastWriteTimeUpdates { get; init; }

	public long? CreationTime { get; init; }

	public long? LastAccessTime { get; init; }

	public long? LastWriteTime { get; init; }

	public long? ChangeTime { get; init; }

	public uint? Attributes { get; init; }
}
