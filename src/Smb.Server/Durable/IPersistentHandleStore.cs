namespace Smb.Server.Durable;

public interface IPersistentHandleStore
{
    ulong HighestPersistentId { get; }

    void Persist(PersistentHandleRecord record);

    void RemovePersisted(ulong persistentId, ulong volatileId);

    bool TryClaimColdRecord(ulong persistentId, ulong volatileId, out PersistentHandleRecord record);

    void ReturnColdRecord(PersistentHandleRecord record);
}
