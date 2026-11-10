using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using Smb.FileSystem.Sqlite;
using Smb.Server.Recovery;

namespace Smb.Persistence.Sqlite;

/// <summary>Single-owner FULL-sync recovery journal using the supplied C# engine.
/// Caller-owned: keep alive until the server stops. Use a separate database from file data.</summary>
public sealed class SqliteServerRecoveryStore : IServerRecoveryStore, IDisposable
{
    private readonly object _gate = new();
    private readonly SqliteConnection _db;
    private bool _disposed;
    public Guid ServerGuid { get; }
    public SqliteServerRecoveryStore(string databasePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        try
        {
            _db = new(new SqliteConnectionString(Path.GetFullPath(databasePath), true));
            _db.ExecuteNonQuery("PRAGMA foreign_keys=ON; PRAGMA locking_mode=EXCLUSIVE; PRAGMA synchronous=FULL; BEGIN EXCLUSIVE");
            try
            {
                var version = Convert.ToInt64(Scalar("PRAGMA user_version"));
                var app = Convert.ToInt64(Scalar("PRAGMA application_id"));
                var tables = Convert.ToInt64(Scalar("SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"));
                if (version == 0 && app == 0 && tables == 0)
                {
                    _db.ExecuteNonQuery("""
                        CREATE TABLE identity(key TEXT PRIMARY KEY,value TEXT NOT NULL) WITHOUT ROWID;
                        CREATE TABLE sessions(id TEXT PRIMARY KEY,client TEXT NOT NULL,owner TEXT NOT NULL,authenticated TEXT NOT NULL,retired INTEGER NOT NULL) WITHOUT ROWID;
                        CREATE TABLE handles(id TEXT PRIMARY KEY,session TEXT NOT NULL REFERENCES sessions(id),snapshot BLOB NOT NULL) WITHOUT ROWID;
                        PRAGMA application_id=1397572178; PRAGMA user_version=1;
                        """);
                    Exec("INSERT INTO identity VALUES('server',$v)", ("$v", Guid.NewGuid().ToString("N")));
                    _db.ExecuteNonQuery("INSERT INTO identity VALUES('Session','0'),('PersistentHandle','0')");
                }
                else if (version != 1 || app != 0x534d4252) throw new NotSupportedException("Unsupported SMB recovery database identity/schema.");
                if (!string.Equals((string?)Scalar("PRAGMA journal_mode"), "delete", StringComparison.OrdinalIgnoreCase) || (string?)Scalar("PRAGMA quick_check") != "ok")
                    throw new InvalidDataException("Recovery journal mode or integrity check failed.");
                using (var r = _db.ExecuteReader("PRAGMA foreign_key_check")) if (r.Read()) throw new InvalidDataException("Recovery journal has broken references.");
                ServerGuid = Guid.ParseExact((string)Scalar("SELECT value FROM identity WHERE key='server'")!, "N");
                _db.ExecuteNonQuery("UPDATE sessions SET retired=1; DELETE FROM sessions WHERE NOT EXISTS(SELECT 1 FROM handles WHERE handles.session=sessions.id); COMMIT");
            }
            catch { _db.ExecuteNonQuery("ROLLBACK"); throw; }
        }
        catch (SqliteException e) { _db?.Dispose(); throw new IOException("Cannot acquire or initialize SMB recovery journal.", e); }
        catch { _db?.Dispose(); throw; }
    }
    private SqliteDataReader Query(string sql, params (string Name, object Value)[] values)
        => _db.ExecuteReader(sql, static (in SqliteStatementBinder binder, (string Name, object Value)[] args) =>
        {
            foreach (var (name, value) in args)
            {
                var index = binder.GetParameterIndex(name);
                if (value is byte[] bytes) binder.SetBlob(index, bytes);
                else binder.SetString(index, (string)value);
            }
        }, values);
    private void Exec(string sql, params (string Name, object Value)[] args) { using var r = Query(sql, args); while (r.Read()) { } }
    private object? Scalar(string sql, params (string Name, object Value)[] args) { using var r = Query(sql, args); return r.Read() ? r.GetValue(0) : null; }
    private T Transaction<T>(Func<T> action)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _db.ExecuteNonQuery("BEGIN IMMEDIATE");
        try { var value = action(); _db.ExecuteNonQuery("COMMIT"); return value; }
        catch { _db.ExecuteNonQuery("ROLLBACK"); throw; }
    }
    private static string Id(ulong value) => value.ToString("x16", CultureInfo.InvariantCulture);
    public ulong AllocateId(RecoveryIdKind kind)
    {
        if (!Enum.IsDefined(kind)) throw new ArgumentOutOfRangeException(nameof(kind));
        lock (_gate) return Transaction(() =>
        {
            var value = ulong.Parse((string)Scalar("SELECT value FROM identity WHERE key=$k", ("$k", kind.ToString()))!, CultureInfo.InvariantCulture);
            if (value >= long.MaxValue - 1UL) throw new InvalidOperationException("Recovery ID namespace exhausted.");
            Exec("UPDATE identity SET value=$v WHERE key=$k", ("$v", (++value).ToString(CultureInfo.InvariantCulture)), ("$k", kind.ToString()));
            return value;
        });
    }
    public void SaveSession(RecoverySessionRecord session)
    {
        lock (_gate) Transaction(() =>
        {
            Exec("INSERT INTO sessions VALUES($id,$client,$owner,$at,0) ON CONFLICT(id) DO UPDATE SET client=excluded.client,owner=excluded.owner,authenticated=excluded.authenticated,retired=0",
                ("$id", Id(session.SessionId)), ("$client", session.ClientGuid.ToString("N")), ("$owner", session.OwnerKey), ("$at", session.AuthenticatedAt.ToString("O", CultureInfo.InvariantCulture)));
            return true;
        });
    }
    public void RetireSession(ulong sessionId)
    {
        lock (_gate) Transaction(() =>
        {
            Exec("UPDATE sessions SET retired=1 WHERE id=$id", ("$id", Id(sessionId)));
            Exec("DELETE FROM sessions WHERE id=$id AND NOT EXISTS(SELECT 1 FROM handles WHERE handles.session=sessions.id)", ("$id", Id(sessionId)));
            return true;
        });
    }
    private static void Validate(RecoveryHandleRecord handle)
    {
        if (handle.Version != 1 || handle.PersistentId == 0 || handle.SessionId == 0 || handle.Token == Guid.Empty ||
            handle.TimeoutTicks <= 0 || handle.TimeoutTicks > TimeSpan.FromMilliseconds(uint.MaxValue - 1).Ticks ||
            handle.LeaseKey.Length != 16 || handle.ParentLeaseKey.Length != 16 || handle.LockSequences.Length != 64 || handle.LockSequences.Any(v => v > 16) ||
            string.IsNullOrEmpty(handle.ObjectId) || string.IsNullOrEmpty(handle.BackendIdentity) || string.IsNullOrEmpty(handle.OwnerKey))
            throw new InvalidDataException("Invalid SMB recovery record.");
    }
    public void SaveHandle(RecoveryHandleRecord handle)
    {
        Validate(handle);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(handle, RecoveryJson.Default.RecoveryHandleRecord);
        lock (_gate) Transaction(() =>
        {
            if (Convert.ToInt64(Scalar("SELECT count(*) FROM sessions WHERE id=$id AND owner=$owner AND client=$client", ("$id", Id(handle.SessionId)), ("$owner", handle.OwnerKey), ("$client", handle.ClientGuid.ToString("N")))) != 1)
                throw new InvalidDataException("Recovery handle owner does not match its authenticated session.");
            Exec("INSERT INTO handles VALUES($id,$session,$snapshot) ON CONFLICT(id) DO UPDATE SET session=excluded.session,snapshot=excluded.snapshot",
                ("$id", Id(handle.PersistentId)), ("$session", Id(handle.SessionId)), ("$snapshot", bytes));
            return true;
        });
    }
    public void RemoveHandle(ulong persistentId)
    {
        lock (_gate) Transaction(() =>
        {
            Exec("DELETE FROM handles WHERE id=$id", ("$id", Id(persistentId)));
            _db.ExecuteNonQuery("DELETE FROM sessions WHERE retired=1 AND NOT EXISTS(SELECT 1 FROM handles WHERE handles.session=sessions.id)");
            return true;
        });
    }
    public IReadOnlyList<RecoveryHandleRecord> LoadHandles()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var handles = new List<RecoveryHandleRecord>();
            using var reader = _db.ExecuteReader("SELECT id,snapshot FROM handles ORDER BY id");
            while (reader.Read())
            {
                var record = JsonSerializer.Deserialize(reader.GetBlob(1)!, RecoveryJson.Default.RecoveryHandleRecord) ?? throw new InvalidDataException("Missing recovery snapshot.");
                Validate(record);
                if (Id(record.PersistentId) != reader.GetString(0)) throw new InvalidDataException("Recovery record ID mismatch.");
                handles.Add(record);
            }
            return handles;
        }
    }
    public void Dispose() { lock (_gate) { if (_disposed) return; _disposed = true; _db.Dispose(); } }
}

[JsonSerializable(typeof(RecoveryHandleRecord))]
internal partial class RecoveryJson : JsonSerializerContext { }
