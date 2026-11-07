namespace Smb.Protocol.Enums;

public enum SmbCommand : ushort
{
	Negotiate,
	SessionSetup,
	Logoff,
	TreeConnect,
	TreeDisconnect,
	Create,
	Close,
	Flush,
	Read,
	Write,
	Lock,
	Ioctl,
	Cancel,
	Echo,
	QueryDirectory,
	ChangeNotify,
	QueryInfo,
	SetInfo,
	OplockBreak,
}
