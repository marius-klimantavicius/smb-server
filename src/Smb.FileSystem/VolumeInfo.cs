namespace Smb.FileSystem;

public readonly record struct VolumeInfo(string Label, uint SerialNumber, long TotalBytes, long AvailableBytes);
