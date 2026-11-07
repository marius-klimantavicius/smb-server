namespace Smb.FileSystem;

public readonly record struct SymlinkTarget(string SubstituteName, string? PrintName, int UnparsedPathLength, bool IsRelative);
