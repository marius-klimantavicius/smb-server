namespace Smb.Protocol.Enums;

public enum FsInformationClass : byte
{
	FileFsVolumeInformation = 1,
	FileFsSizeInformation = 3,
	FileFsDeviceInformation = 4,
	FileFsAttributeInformation = 5,
	FileFsFullSizeInformation = 7,
}
