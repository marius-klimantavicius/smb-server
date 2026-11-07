namespace Smb.FileSystem;

public interface IShare
{
	string Name { get; }

	ShareType Type { get; }

	IFileStore? FileStore { get; }

	bool EncryptData { get; }

	bool ContinuousAvailability { get; }

	string Remark { get; }

	bool IsDfs => false;
}
