namespace Smb.FileSystem;

public readonly record struct FileCreateResult(IFileHandle Handle, CreateOutcome Action);
