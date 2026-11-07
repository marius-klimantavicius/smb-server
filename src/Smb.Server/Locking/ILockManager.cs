using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Smb.Server.State;

namespace Smb.Server.Locking;

public interface ILockManager
{
	Task<LockOutcome> ApplyAsync(SmbOpen owner, IReadOnlyList<LockElement> elements, bool failImmediately, CancellationToken ct);

	bool IsRangeAccessible(SmbOpen owner, ulong offset, ulong length, bool forWrite);

	void ReleaseOwner(SmbOpen owner);
}
