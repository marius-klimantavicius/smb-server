namespace Smb.FileSystem;

public sealed class Share : IShare
{
	public required string Name { get; init; }

	public ShareType Type { get; init; } = ShareType.Disk;

	public IFileStore? FileStore { get; init; }

	public bool EncryptData { get; init; }

	public bool ContinuousAvailability { get; init; }

	public string Remark { get; init; } = string.Empty;

	public bool IsDfs { get; init; }

	public static Share CreateIpc()
	{
		return new Share
		{
			Name = "IPC$",
			Type = ShareType.Pipe,
			Remark = "Remote IPC",
		};
	}
}
