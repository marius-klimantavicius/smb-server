using System;

namespace Smb.Server.Durable;

public sealed record PersistentHandleRecord(ulong PersistentId, ulong VolatileId, string OwnerKey, Guid CreateGuid, string ShareName, string Path, uint GrantedAccess, uint ShareAccess);
