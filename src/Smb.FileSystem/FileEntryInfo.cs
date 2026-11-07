namespace Smb.FileSystem;

public sealed class FileEntryInfo
{
	public required string Name { get; init; }

	public SmbFileAttributes Attributes { get; init; }

	public long EndOfFile { get; init; }

	public long AllocationSize { get; init; }

	public long CreationTime { get; init; }

	public long LastAccessTime { get; init; }

	public long LastWriteTime { get; init; }

	public long ChangeTime { get; init; }

	public long IndexNumber { get; init; }

	public bool IsDirectory => Attributes.HasFlag(SmbFileAttributes.Directory);
}
