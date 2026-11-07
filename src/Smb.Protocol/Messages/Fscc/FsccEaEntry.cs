namespace Smb.Protocol.Messages.Fscc;

public readonly record struct FsccEaEntry(byte Flags, string Name, byte[] Value);
