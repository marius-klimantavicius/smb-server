namespace Smb.Protocol.Messages.Fscc;

public readonly record struct FsccStreamEntry(string StreamName, long Size, long AllocationSize);
