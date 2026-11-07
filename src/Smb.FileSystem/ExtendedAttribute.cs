namespace Smb.FileSystem;

public readonly record struct ExtendedAttribute(string Name, byte[] Value, byte Flags = 0);
