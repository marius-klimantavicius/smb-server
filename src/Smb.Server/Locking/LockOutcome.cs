namespace Smb.Server.Locking;

public enum LockOutcome
{
    Granted,
    Conflict,
    RangeNotLocked,
    Cancelled,
    InvalidParameter,
}
