namespace Smb.Protocol.Messages.Fscc;

public sealed class FsccFileStat
{
	public bool DeletePending { get; init; }

	public required string Name { get; init; }

	public uint FileAttributes { get; init; }

	public uint EaSize { get; set; }

	public long EndOfFile { get; init; }

	public long AllocationSize { get; init; }

	public long CreationTime { get; init; }

	public long LastAccessTime { get; init; }

	public long LastWriteTime { get; init; }

	public long ChangeTime { get; init; }

	public bool IsDirectory { get; init; }

	public long IndexNumber { get; init; }

	public uint NumberOfLinks { get; init; } = 1u;
}
