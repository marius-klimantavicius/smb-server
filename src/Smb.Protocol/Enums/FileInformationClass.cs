namespace Smb.Protocol.Enums;

public enum FileInformationClass : byte
{
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation = 2,
	FileBothDirectoryInformation = 3,
	FileBasicInformation = 4,
	FileStandardInformation = 5,
	FileInternalInformation = 6,
	FileEaInformation = 7,
	FileNameInformation = 9,
	FileFullEaInformation = 15,
	FileRenameInformation = 10,
	FileNamesInformation = 12,
	FileDispositionInformation = 13,
	FilePositionInformation = 14,
	FileAllInformation = 18,
	FileAllocationInformation = 19,
	FileEndOfFileInformation = 20,
	FileAlternateNameInformation = 21,
	FileStreamInformation = 22,
	FileNetworkOpenInformation = 34,
	FileAttributeTagInformation = 35,
	FileIdBothDirectoryInformation = 37,
	FileIdFullDirectoryInformation = 38,
}
