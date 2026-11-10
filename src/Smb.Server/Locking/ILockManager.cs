using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Smb.Server.State;

namespace Smb.Server.Locking;

public interface ILockManager
{
    Task<LockOutcome> ApplyAsync(SmbOpen owner, IReadOnlyList<LockElement> elements, bool failImmediately, CancellationToken ct);

    bool IsRangeAccessible(SmbOpen owner, ulong offset, ulong length, bool forWrite);

    // Optional nonmutating preflight. True permits an immediate rejection before
    // cache breaks; false still requires the authoritative atomic ApplyAsync.
    bool HasConflict(SmbOpen owner, IReadOnlyList<LockElement> elements) => false;

    void ReleaseOwner(SmbOpen owner);
}
