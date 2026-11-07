namespace Smb.Server.Notification;

public readonly record struct FileNotifyEvent(FileNotifyAction Action, string RelativeName);
