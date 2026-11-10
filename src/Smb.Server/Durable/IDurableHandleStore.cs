using System;
using System.Collections.Generic;

namespace Smb.Server.Durable;

public interface IDurableHandleStore
{
    void Add(DurableHandle handle);

    bool TryClaim(ulong persistentId, ulong volatileId, out DurableHandle handle);

    IReadOnlyList<DurableHandle> TakeExpired(DateTimeOffset now);

    IReadOnlyList<DurableHandle> TakeAll();
}
