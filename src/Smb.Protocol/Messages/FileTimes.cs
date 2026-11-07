namespace Smb.Protocol.Messages;

public readonly record struct FileTimes(long Creation, long LastAccess, long LastWrite, long Change);
