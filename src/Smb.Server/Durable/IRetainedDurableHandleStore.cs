using System;
using Smb.Server.State;

namespace Smb.Server.Durable;

/// <summary>Optional live-registry capabilities required for durable reconnect/replay.
/// Disk recovery journals are separate from this registry of physical opens.</summary>
public interface IRetainedDurableHandleStore : IDurableHandleStore
{
    bool TryGetReplay(Guid clientGuid, Guid createGuid, out DurableHandle handle);
    bool TryGetPersistent(ulong persistentId, out DurableHandle handle);
    void Retire(SmbOpen open);
}
