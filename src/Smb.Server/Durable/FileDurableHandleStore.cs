using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace Smb.Server.Durable;

public sealed class FileDurableHandleStore : IDurableHandleStore, IPersistentHandleStore
{
    private readonly string _directory;

    private readonly ConcurrentDictionary<(ulong, ulong), DurableHandle> _warm = new ConcurrentDictionary<(ulong, ulong), DurableHandle>();

    private readonly ConcurrentDictionary<(ulong, ulong), PersistentHandleRecord> _cold = new ConcurrentDictionary<(ulong, ulong), PersistentHandleRecord>();

    public ulong HighestPersistentId { get; private set; }

    public FileDurableHandleStore(string directory)
    {
        _directory = directory;
        Directory.CreateDirectory(_directory);
        LoadCold();
    }

    public void Add(DurableHandle handle)
    {
        _warm[handle.Key] = handle;
    }

    public bool TryClaim(ulong persistentId, ulong volatileId, out DurableHandle handle)
    {
        return _warm.TryRemove((persistentId, volatileId), out handle);
    }

    public IReadOnlyList<DurableHandle> TakeExpired(DateTimeOffset now)
    {
        var list = new List<DurableHandle>();
        foreach (var value2 in _warm.Values)
        {
            if (!value2.IsPersistent && !(value2.Deadline > now) && _warm.TryRemove(value2.Key, out var value))
            {
                list.Add(value);
            }
        }

        return list;
    }

    public IReadOnlyList<DurableHandle> TakeAll()
    {
        var result = new List<DurableHandle>(_warm.Values);
        _warm.Clear();
        return result;
    }

    public void Persist(PersistentHandleRecord record)
    {
        WriteRecord(record);
        HighestPersistentId = Math.Max(HighestPersistentId, record.PersistentId);
    }

    public void RemovePersisted(ulong persistentId, ulong volatileId)
    {
        _cold.TryRemove((persistentId, volatileId), out _);
        try
        {
            File.Delete(RecordPath(persistentId, volatileId));
        }
        catch (DirectoryNotFoundException)
        {
        }
    }

    public bool TryClaimColdRecord(ulong persistentId, ulong volatileId, out PersistentHandleRecord record)
    {
        return _cold.TryRemove((persistentId, volatileId), out record);
    }

    public void ReturnColdRecord(PersistentHandleRecord record)
    {
        _cold[(record.PersistentId, record.VolatileId)] = record;
    }

    private void LoadCold()
    {
        foreach (var item in Directory.EnumerateFiles(_directory, "*.json"))
        {
            PersistentHandleRecord persistentHandleRecord;
            try
            {
                persistentHandleRecord = JsonSerializer.Deserialize<PersistentHandleRecord>(File.ReadAllBytes(item));
            }
            catch (JsonException)
            {
                continue;
            }

            if ((object)persistentHandleRecord != null)
            {
                _cold[(persistentHandleRecord.PersistentId, persistentHandleRecord.VolatileId)] = persistentHandleRecord;
                HighestPersistentId = Math.Max(HighestPersistentId, persistentHandleRecord.PersistentId);
            }
        }
    }

    private void WriteRecord(PersistentHandleRecord record)
    {
        var text = RecordPath(record.PersistentId, record.VolatileId);
        var text2 = text + ".tmp";
        File.WriteAllBytes(text2, JsonSerializer.SerializeToUtf8Bytes(record));
        File.Move(text2, text, overwrite: true);
    }

    private string RecordPath(ulong persistentId, ulong volatileId)
    {
        return Path.Combine(_directory, $"{persistentId:x16}_{volatileId:x16}.json");
    }
}
