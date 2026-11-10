namespace Smb.Server.Diagnostics;

public enum SmbAuditEventType
{
    ConnectionAccepted = 1000,
    ConnectionClosed = 1001,
    AuthenticationSucceeded = 4624,
    AuthenticationFailed = 4625,
    SessionLogoff = 4634,
    FileClosed = 4658,
    FileDeleted = 4660,
    PermissionChanged = 4670,
    ShareAccessGranted = 5140,
    ShareAccessDenied = 5143,
    FileOpened = 5145,
}
