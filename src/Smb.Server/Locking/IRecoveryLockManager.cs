using Smb.Server.Recovery;
using Smb.Server.State;

namespace Smb.Server.Locking;

/// <summary>Capture all granted ranges for one owner. Pending requests are not restart state.</summary>
public interface IRecoveryLockManager : ILockManager
{
    RecoveryLock[] CaptureLocks(SmbOpen owner);
}
