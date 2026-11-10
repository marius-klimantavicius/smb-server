namespace Smb.Server.Notification;

public enum FileNotifyAction : uint
{
    Added = 1u,
    Removed,
    Modified,
    RenamedOldName,
    RenamedNewName,
}
