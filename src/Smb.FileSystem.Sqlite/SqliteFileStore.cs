using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Security;

namespace Smb.FileSystem.Sqlite;

/// <summary>
/// A logical, case-insensitive filesystem stored entirely in one SQLite database.
/// One retained exclusive SQLite connection fences other store instances and processes.
/// readOnly restricts filesystem operations; the database itself must be writable to acquire
/// the exclusive lock. SMB handles and per-open timestamp suppression are never persisted.
/// </summary>
public sealed partial class SqliteFileStore : IFileStore, IBasicInfoStore, ICreateMetadataStore, IAuthorizedCreateStore,
    ISharedDeleteFileStore, IVolumeInfoProvider, IDirectoryCursorStore, IFileNamespaceStore, IRecoverableFileStore, IDisposable, IAsyncDisposable
{
    private const int ApplicationId = 0x534D4253;
    private const int SchemaVersion = 1;
    private const int ChunkSize = 65536;
    private const uint SettableAttributes = 0x21A7; // read-only, hidden, system, archive, normal, temporary, not-indexed
    private const NtStatus DeletePendingStatus = (NtStatus)0xc0000056;
    private const NtStatus CannotDelete = (NtStatus)0xc0000121;
    private readonly object _gate = new object();
    private readonly SqliteConnection _db;
    private readonly bool _readOnly;
    private readonly string _databaseId;
    private readonly string _rootId;
    private readonly HashSet<Handle> _handles = [];
    private bool _disposed;

    public SqliteFileStore(string databasePath, bool readOnly = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        _readOnly = readOnly;
        try
        {
            _db = new SqliteConnection(new SqliteConnectionString(Path.GetFullPath(databasePath),
                SqliteOpenFlags.ReadWrite | SqliteOpenFlags.PrivateCache | (readOnly ? 0 : SqliteOpenFlags.Create), true));
            Exec("PRAGMA foreign_keys=ON; PRAGMA locking_mode=EXCLUSIVE; PRAGMA synchronous=FULL;");
            // Taking the lock before inspecting the schema prevents two initializers racing.
            Exec("BEGIN EXCLUSIVE");
            try
            {
                var version = Convert.ToInt32(Scalar("PRAGMA user_version"));
                var app = Convert.ToInt32(Scalar("PRAGMA application_id"));
                var tables = Convert.ToInt64(Scalar("SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"));
                if (version == 0 && app == 0 && tables == 0 && !readOnly) Initialize();
                else if (version != SchemaVersion || app != ApplicationId)
                    throw new NotSupportedException($"Unsupported SQLite filesystem application/schema ({app:x8}/{version}).");

                _databaseId = (string)Scalar("SELECT value FROM store_meta WHERE key='database_id'")!;
                _rootId = (string)Scalar("SELECT value FROM store_meta WHERE key='root_id'")!;
                if (!Guid.TryParseExact(_databaseId, "N", out _) || Get(_rootId) is not { Directory: true, Parent: null })
                    throw new InvalidDataException("Invalid SQLite filesystem identity or root.");

                ValidateDatabase();
                RecoverOrphans();
                Exec("COMMIT");
            }
            catch
            {
                Exec("ROLLBACK");
                throw;
            }

        }
        catch (SqliteException e)
        {
            _db?.Dispose();
            throw new IOException("Cannot acquire or initialize SQLite filesystem.", e);
        }
        catch
        {
            _db?.Dispose();
            throw;
        }
    }

    private void ValidateDatabase()
    {
        // Check before recovery so a rejected database remains byte-for-byte unchanged.
        // A retained rollback-journal lock is the ownership fence; WAL is not supported.
        if (!string.Equals((string?)Scalar("PRAGMA journal_mode"), "delete", StringComparison.OrdinalIgnoreCase))
            throw new NotSupportedException("SQLite filesystem requires DELETE journal mode.");
        if (!string.Equals((string?)Scalar("PRAGMA quick_check"), "ok", StringComparison.Ordinal))
            throw new InvalidDataException("SQLite filesystem failed integrity validation.");

        using var reader = Query("PRAGMA foreign_key_check");
        if (reader.Read()) throw new InvalidDataException("SQLite filesystem has broken references.");
    }

    private void Initialize()
    {
        var database = Guid.NewGuid().ToString("N");
        var root = Guid.NewGuid().ToString("N");
        Exec("""
            CREATE TABLE store_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
            CREATE TABLE objects(
                id TEXT PRIMARY KEY, index_number INTEGER NOT NULL UNIQUE,
                parent TEXT REFERENCES objects(id) ON DELETE RESTRICT,
                name TEXT NOT NULL, name_key TEXT NOT NULL,
                directory INTEGER NOT NULL CHECK(directory IN (0,1)),
                length INTEGER NOT NULL DEFAULT 0 CHECK(length>=0),
                attributes INTEGER NOT NULL, created INTEGER NOT NULL, accessed INTEGER NOT NULL,
                written INTEGER NOT NULL, changed INTEGER NOT NULL, security BLOB NOT NULL,
                pending INTEGER NOT NULL DEFAULT 0 CHECK(pending IN (0,1)),
                UNIQUE(parent,name_key));
            CREATE TABLE chunks(object_id TEXT NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
                number INTEGER NOT NULL CHECK(number>=0), data BLOB NOT NULL CHECK(length(data)=65536),
                PRIMARY KEY(object_id,number)) WITHOUT ROWID;
            """);
        Exec($"PRAGMA application_id={ApplicationId}; PRAGMA user_version={SchemaVersion};");
        Exec("INSERT INTO store_meta VALUES('database_id',$db),('root_id',$root),('next_index','2')", ("$db", database), ("$root", root));
        var now = Now();
        Exec("INSERT INTO objects(id,index_number,parent,name,name_key,directory,attributes,created,accessed,written,changed,security) VALUES($id,1,NULL,'','',1,16,$t,$t,$t,$t,$s)",
            ("$id", root), ("$t", now), ("$s", DefaultDescriptor().ToBytes()));
    }

    // The framework owns preparation/finalization; the binder copies text/blob values
    // into SQLite (SQLITE_TRANSIENT) before managed pins are released.
    private SqliteDataReader Query(string sql, params (string Name, object? Value)[] args)
        => _db.ExecuteReader(sql, static (in binder, values) =>
        {
            foreach (var (name, value) in values)
            {
                var index = binder.GetParameterIndex(name);
                switch (value)
                {
                    case null: binder.SetString(index, null); break;
                    case string text: binder.SetString(index, text); break;
                    case byte[] bytes: binder.SetBlob(index, bytes); break;
                    case bool boolean: binder.SetInt32(index, boolean ? 1 : 0); break;
                    case int number: binder.SetInt32(index, number); break;
                    case long number: binder.SetInt64(index, number); break;
                    case uint number: binder.SetInt64(index, number); break;
                    default: throw new ArgumentException("Unsupported SQLite filesystem parameter type.");
                }
            }
        }, args);

    private void Exec(string sql, params (string Name, object? Value)[] args)
    {
        if (args.Length == 0)
        {
            _db.ExecuteNonQuery(sql);
            return;
        }

        using var reader = Query(sql, args);
        while (reader.Read()) { }
    }

    private object? Scalar(string sql, params (string Name, object? Value)[] args)
    {
        using var reader = Query(sql, args);
        return reader.Read() ? reader.GetValue(0) : null;
    }

    private T Transaction<T>(CancellationToken ct, Func<T> action)
    {
        Exec("BEGIN IMMEDIATE");
        try
        {
            var result = action();
            ct.ThrowIfCancellationRequested();
            Exec("COMMIT");
            return result;
        }
        catch
        {
            Exec("ROLLBACK");
            throw;
        }
    }

    private static NtStatus Error(SqliteException e) => (e.Result & 0xff) switch
    {
        13 => NtStatus.DiskFull, 5 or 6 => NtStatus.SharingViolation, 8 or 3 => NtStatus.AccessDenied,
        7 => NtStatus.InsufficientResources, _ => NtStatus.InvalidParameter,
    };

    private ValueTask<FileStoreResult<T>> Result<T>(CancellationToken ct, Func<FileStoreResult<T>> action)
    {
        lock (_gate)
        {
            ct.ThrowIfCancellationRequested();
            if (_disposed) return new ValueTask<FileStoreResult<T>>(FileStoreResult<T>.Fail(NtStatus.FileClosed));

            try { return new ValueTask<FileStoreResult<T>>(action()); }
            catch (SqliteException e) { return new ValueTask<FileStoreResult<T>>(FileStoreResult<T>.Fail(Error(e))); }
        }
    }

    private ValueTask<NtStatus> Status(CancellationToken ct, Func<NtStatus> action)
    {
        lock (_gate)
        {
            ct.ThrowIfCancellationRequested();
            if (_disposed) return new ValueTask<NtStatus>(NtStatus.FileClosed);

            try { return new ValueTask<NtStatus>(action()); }
            catch (SqliteException e) { return new ValueTask<NtStatus>(Error(e)); }
        }
    }

    private sealed record Node(
        string Id,
        long Index,
        string? Parent,
        string Name,
        bool Directory,
        long Length,
        uint Attributes,
        long Created,
        long Accessed,
        long Written,
        long Changed,
        byte[] Security,
        bool Pending);

    private const string Columns = "id,index_number,parent,name,directory,length,attributes,created,accessed,written,changed,security,pending";
    private static Node NodeFrom(SqliteDataReader r) => new Node(r.GetString(0)!, r.GetInt64(1), r.IsDBNull(2) ? null : r.GetString(2), r.GetString(3)!, r.GetBoolean(4), r.GetInt64(5), (uint)r.GetInt64(6), r.GetInt64(7), r.GetInt64(8), r.GetInt64(9), r.GetInt64(10), r.GetBlob(11)!, r.GetBoolean(12));

    private Node? Find(string where, params (string Name, object? Value)[] args)
    {
        using var reader = Query("SELECT " + Columns + " FROM objects WHERE " + where, args);
        return reader.Read() ? NodeFrom(reader) : null;
    }

    private Node? Get(string id) => Find("id=$id", ("$id", id));
    private static string Key(string name) => name.ToUpperInvariant();

    private static string[]? Parts(string? path)
    {
        if (path is null || path.Length > 32767 || !ValidUnicode(path)) return null;
        if (path.Length == 0 || path == "\\" || path == "/") return [];

        var parts = path.Replace('\\', '/').TrimStart('/').Split('/');
        if (parts.Any(p => p.Length is 0 or > 255 || p is "." or ".." || p.EndsWith(' ') || p.EndsWith('.') || p.Any(c => c < 32 || "\"<>|:*?".Contains(c)))) return null;

        return parts;
    }

    private static bool ValidUnicode(string value)
    {
        for (var i = 0; i < value.Length; i++)
            if (char.IsSurrogate(value[i]))
            {
                if (!char.IsHighSurrogate(value[i]) || i + 1 == value.Length || !char.IsLowSurrogate(value[i + 1])) return false;

                i++;
            }

        return true;
    }

    private (Node? Node, Node? Parent, NtStatus Status) Lookup(string[] parts)
    {
        var current = Get(_rootId)!;
        Node? parent = null;
        for (var i = 0; i < parts.Length; i++)
        {
            var part = parts[i];
            if (!current.Directory) return (null, null, NtStatus.NotADirectory);
            if (current.Pending) return (null, null, DeletePendingStatus);

            parent = current;
            var child = Find("parent=$p AND name_key=$n", ("$p", parent.Id), ("$n", Key(part)));
            if (child is null) return (null, parent, i == parts.Length - 1 ? NtStatus.Success : NtStatus.ObjectPathNotFound);

            current = child;
        }

        return (current, parent, NtStatus.Success);
    }

    private static long Now() => DateTime.UtcNow.ToFileTimeUtc();
    private FileIdentity Identity(Node node) => new FileIdentity("sqlite:" + _databaseId + ":" + node.Id);

    public bool HasExclusiveServerAccess
    {
        get
        {
            lock (_gate) return !_disposed;
        }
    }

    public VolumeInfo GetVolumeInfo()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var size = Convert.ToInt64(Scalar("PRAGMA page_count")) * Convert.ToInt64(Scalar("PRAGMA page_size"));
            var maximum = Convert.ToInt64(Scalar("PRAGMA max_page_count")) * Convert.ToInt64(Scalar("PRAGMA page_size"));
            return new VolumeInfo("SQLite", Convert.ToUInt32(_databaseId[..8], 16), maximum, Math.Max(0, maximum - size));
        }
    }

    public ValueTask<FileIdentity?> ResolveIdentityAsync(string path, string streamName = "", CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_disposed || streamName.Length != 0 || Parts(path) is not { } parts) return new ValueTask<FileIdentity?>((FileIdentity?)null);

            var node = Lookup(parts).Node;
            return new ValueTask<FileIdentity?>(node is null ? null : Identity(node));
        }
    }

    public ValueTask<FileStoreResult<FileCreateResult>> CreateAsync(string path, FileAccessIntent access, CreateDispositionIntent disposition, bool directoryRequired, bool nonDirectoryRequired, CancellationToken cancellationToken = default)
        => CreateWithMetadataAsync(path, access, disposition, directoryRequired, nonDirectoryRequired, 0, cancellationToken);

    public ValueTask<FileStoreResult<FileCreateResult>> CreateWithMetadataAsync(string path, FileAccessIntent access, CreateDispositionIntent disposition, bool directoryRequired, bool nonDirectoryRequired, uint attributes, CancellationToken cancellationToken = default)
        => Result(cancellationToken, () => CreateCore(path, access, disposition, directoryRequired, nonDirectoryRequired, attributes, cancellationToken));

    private FileStoreResult<FileCreateResult> CreateCore(string path, FileAccessIntent access, CreateDispositionIntent disposition, bool directoryRequired, bool nonDirectoryRequired, uint attributes, CancellationToken ct, bool authorized = false)
    {
        static FileStoreResult<FileCreateResult> Fail(NtStatus status) => FileStoreResult<FileCreateResult>.Fail(status);
        if (Parts(path) is not { } parts) return Fail(NtStatus.ObjectNameInvalid);
        if (!Enum.IsDefined(disposition) || directoryRequired && nonDirectoryRequired || (access & ~(FileAccessIntent.ReadWrite | FileAccessIntent.Delete)) != 0 || !ValidAttributes(attributes, directoryRequired)) return Fail(NtStatus.InvalidParameter);

        var (node, parent, status) = Lookup(parts);
        if (status != NtStatus.Success) return Fail(status);
        if (node?.Pending == true) return Fail(DeletePendingStatus);
        if (node is not null && disposition == CreateDispositionIntent.Create) return Fail(NtStatus.ObjectNameCollision);
        if (node is not null && directoryRequired && !node.Directory) return Fail(NtStatus.NotADirectory);
        if (node?.Directory == true && nonDirectoryRequired) return Fail(NtStatus.FileIsADirectory);

        var destructive = disposition is CreateDispositionIntent.Supersede or CreateDispositionIntent.Overwrite or CreateDispositionIntent.OverwriteIf;
        if ((node?.Directory == true || directoryRequired) && destructive) return Fail(NtStatus.InvalidParameter);
        if (node is null && disposition is CreateDispositionIntent.Open or CreateDispositionIntent.Overwrite) return Fail(NtStatus.ObjectNameNotFound);
        if (_readOnly && (node is null || destructive || (access & (FileAccessIntent.Write | FileAccessIntent.Delete)) != 0)) return Fail(NtStatus.AccessDenied);
        if (destructive && !authorized && (access & FileAccessIntent.Write) == 0) return Fail(NtStatus.AccessDenied);
        if (node is { Directory: false } && (node.Attributes & 1) != 0 && (destructive || (access & FileAccessIntent.Write) != 0)) return Fail(NtStatus.AccessDenied);
        if (destructive && node is not null && (node.Attributes & 6u & ~attributes) != 0) return Fail(NtStatus.AccessDenied);

        ct.ThrowIfCancellationRequested();
        var outcome = node is null ? CreateOutcome.Created : !destructive ? CreateOutcome.Opened : disposition == CreateDispositionIntent.Supersede ? CreateOutcome.Superseded : CreateOutcome.Overwritten;
        var id = node?.Id ?? Guid.NewGuid().ToString("N");
        if (node is null || destructive)
            Transaction(ct, () =>
            {
                var now = Now();
                if (node is null)
                {
                    var index = Convert.ToInt64(Scalar("SELECT value FROM store_meta WHERE key='next_index'"));
                    if (index == long.MaxValue) throw new IOException("SQLite filesystem identity space exhausted.");

                    Exec("UPDATE store_meta SET value=$i WHERE key='next_index'", ("$i", (index + 1).ToString(System.Globalization.CultureInfo.InvariantCulture)));
                    var security = AclInheritance.ComputeInherited(SecurityDescriptor.Parse(parent!.Security), directoryRequired) ?? DefaultDescriptor();
                    Exec("INSERT INTO objects(id,index_number,parent,name,name_key,directory,attributes,created,accessed,written,changed,security) VALUES($id,$i,$p,$n,$k,$d,$a,$t,$t,$t,$t,$s)",
                        ("$id", id), ("$i", index), ("$p", parent.Id), ("$n", parts[^1]), ("$k", Key(parts[^1])), ("$d", directoryRequired), ("$a", StoredAttributes(attributes, directoryRequired)), ("$t", now), ("$s", security.ToBytes()));
                    TouchParent(parent.Id, now);
                }
                else
                {
                    Exec("DELETE FROM chunks WHERE object_id=$id", ("$id", id));
                    Exec("UPDATE objects SET length=0,attributes=$a,written=$t,changed=$t WHERE id=$id", ("$id", id), ("$a", StoredAttributes(attributes, false)), ("$t", now));
                }

                return true;
            });
        var handle = new Handle(this, id, access);
        _handles.Add(handle);
        return FileStoreResult<FileCreateResult>.Ok(new FileCreateResult(handle, outcome));
    }

    private static bool ValidAttributes(uint attributes, bool directory) => (attributes & ~(SettableAttributes | 16u)) == 0 && !(directory && (attributes & 0x100) != 0);
    private static uint StoredAttributes(uint attributes, bool directory) => (attributes & SettableAttributes & ~0x80u) | (directory ? 16u : 32u);
    private void TouchParent(string id, long now) => Exec("UPDATE objects SET attributes=attributes|32,written=$t,changed=$t WHERE id=$id", ("$id", id), ("$t", now));

    private NtStatus Validate(IFileHandle handle, out Handle? own, out Node? node)
    {
        own = handle as Handle ?? null;
        node = null;
        if (own is null || !ReferenceEquals(own.Store, this)) return NtStatus.InvalidParameter;
        if (own.Closed || !_handles.Contains(own)) return NtStatus.FileClosed;

        node = Get(own.Id);
        return node is null ? NtStatus.FileClosed : NtStatus.Success;
    }

    private byte[] Chunk(string id, long number) => Scalar("SELECT data FROM chunks WHERE object_id=$id AND number=$n", ("$id", id), ("$n", number)) as byte[] ?? new byte[ChunkSize];
    private void PutChunk(string id, long number, byte[] data) => Exec("INSERT INTO chunks VALUES($id,$n,$b) ON CONFLICT(object_id,number) DO UPDATE SET data=excluded.data", ("$id", id), ("$n", number), ("$b", data));

    public ValueTask<FileStoreResult<int>> ReadAsync(IFileHandle handle, long offset, Memory<byte> buffer, CancellationToken cancellationToken = default)
        => Result(cancellationToken, () =>
        {
            var status = Validate(handle, out var h, out var n);
            if (status != NtStatus.Success) return FileStoreResult<int>.Fail(status);
            if (n.Directory) return FileStoreResult<int>.Fail(NtStatus.FileIsADirectory);
            if ((h.Access & FileAccessIntent.Read) == 0) return FileStoreResult<int>.Fail(NtStatus.AccessDenied);
            if (offset < 0) return FileStoreResult<int>.Fail(NtStatus.InvalidParameter);

            var count = (int)Math.Min(buffer.Length, Math.Max(0, n.Length - offset));
            var done = 0;
            while (done < count)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var position = offset + done;
                var start = (int)(position % ChunkSize);
                var size = Math.Min(count - done, ChunkSize - start);
                Chunk(n.Id, position / ChunkSize).AsMemory(start, size).CopyTo(buffer[done..]);
                done += size;
            }

            return FileStoreResult<int>.Ok(count);
        });

    public ValueTask<FileStoreResult<int>> WriteAsync(IFileHandle handle, long offset, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
        => Result(cancellationToken, () =>
        {
            var status = Validate(handle, out var h, out var n);
            if (status != NtStatus.Success) return FileStoreResult<int>.Fail(status);
            if (n.Directory) return FileStoreResult<int>.Fail(NtStatus.FileIsADirectory);
            if (_readOnly || (h.Access & FileAccessIntent.Write) == 0 || (n.Attributes & 1) != 0) return FileStoreResult<int>.Fail(NtStatus.AccessDenied);
            if (offset < 0 || offset > long.MaxValue - data.Length) return FileStoreResult<int>.Fail(NtStatus.InvalidParameter);
            if (data.Length == 0) return FileStoreResult<int>.Ok(0);

            return Transaction(cancellationToken, () =>
            {
                var done = 0;
                while (done < data.Length)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var position = offset + done;
                    var start = (int)(position % ChunkSize);
                    var size = Math.Min(data.Length - done, ChunkSize - start);
                    var chunk = Chunk(n.Id, position / ChunkSize);
                    data.Slice(done, size).CopyTo(chunk.AsMemory(start));
                    PutChunk(n.Id, position / ChunkSize, chunk);
                    done += size;
                }

                UpdateContent(h, Math.Max(n.Length, offset + done));
                return FileStoreResult<int>.Ok(done);
            });
        });

    public ValueTask<FileStoreResult<int>> WriteWithOptionsAsync(IFileHandle handle, long offset, ReadOnlyMemory<byte> data, FileIoOptions options, CancellationToken cancellationToken = default)
        => WriteAsync(handle, offset, data, cancellationToken); // Every successful mutation is already a FULL synchronous commit.

    private void UpdateContent(Handle h, long length)
        => Exec("UPDATE objects SET length=$l,attributes=attributes|32,written=CASE WHEN $s THEN written ELSE $t END,changed=$t WHERE id=$id", ("$id", h.Id), ("$l", length), ("$s", h.SuppressWriteTime), ("$t", Now()));

    public ValueTask<NtStatus> SetEndOfFileAsync(IFileHandle handle, long length, CancellationToken cancellationToken = default)
        => Status(cancellationToken, () =>
        {
            var status = Validate(handle, out var h, out var n);
            if (status != NtStatus.Success) return status;
            if (n.Directory) return NtStatus.FileIsADirectory;
            if (_readOnly || (h.Access & FileAccessIntent.Write) == 0 || (n.Attributes & 1) != 0) return NtStatus.AccessDenied;
            if (length < 0) return NtStatus.InvalidParameter;

            return Transaction(cancellationToken, () =>
            {
                if (length < n.Length)
                {
                    var number = length / ChunkSize;
                    var tail = (int)(length % ChunkSize);
                    Exec("DELETE FROM chunks WHERE object_id=$id AND number >= $n", ("$id", n.Id), ("$n", number + (tail == 0 ? 0 : 1)));
                    if (tail != 0)
                    {
                        var chunk = Chunk(n.Id, number);
                        Array.Clear(chunk, tail, ChunkSize - tail);
                        PutChunk(n.Id, number, chunk);
                    }
                }

                UpdateContent(h, length);
                return NtStatus.Success;
            });
        });

    public ValueTask<NtStatus> FlushAsync(IFileHandle handle, CancellationToken cancellationToken = default)
        => Status(cancellationToken, () => Validate(handle, out _, out _)); // No dirty buffers survive FULL commits.

    public ValueTask<NtStatus> SetBasicInfoAsync(IFileHandle handle, FileBasicInfoUpdate update, CancellationToken cancellationToken = default)
        => Status(cancellationToken, () =>
        {
            var status = Validate(handle, out var h, out var n);
            if (status != NtStatus.Success) return status;
            if (_readOnly) return NtStatus.AccessDenied;
            if (update.Attributes is { } attributes && !ValidAttributes(attributes, n.Directory)) return NtStatus.InvalidParameter;

            foreach (var time in new[] { update.CreationTime, update.LastAccessTime, update.LastWriteTime, update.ChangeTime })
                if (time is { } t && (t < 0 || t > DateTime.MaxValue.ToFileTimeUtc()))
                    return NtStatus.InvalidParameter;

            var result = Transaction(cancellationToken, () =>
            {
                var attr = update.Attributes is { } a && a != 0 ? (a & SettableAttributes & ~0x80u) | (n.Directory ? 16u : 0u) : n.Attributes;
                Exec("UPDATE objects SET attributes=$a,created=$c,accessed=$r,written=$w,changed=$t WHERE id=$id", ("$id", n.Id), ("$a", attr),
                    ("$c", update.CreationTime ?? n.Created), ("$r", update.LastAccessTime ?? n.Accessed), ("$w", update.LastWriteTime ?? n.Written), ("$t", update.ChangeTime ?? Now()));
                return NtStatus.Success;
            });
            if (update.SuppressLastWriteTimeUpdates is { } suppress) h.SuppressWriteTime = suppress;
            return result;
        });

    public ValueTask<FileStoreResult<SecurityDescriptor>> GetSecurityAsync(IFileHandle handle, CancellationToken cancellationToken = default)
        => Result(cancellationToken, () => Validate(handle, out _, out var n) is var status && status != NtStatus.Success ? FileStoreResult<SecurityDescriptor>.Fail(status) : FileStoreResult<SecurityDescriptor>.Ok(SecurityDescriptor.Parse(n.Security)));

    public ValueTask<NtStatus> SetSecurityAsync(IFileHandle handle, SecurityDescriptor descriptor, CancellationToken cancellationToken = default)
        => Status(cancellationToken, () =>
        {
            var status = Validate(handle, out _, out var n);
            if (status != NtStatus.Success) return status;
            if (_readOnly) return NtStatus.AccessDenied;
            if (descriptor.Dacl is { } dacl && dacl.Aces.Any(a => a.Type is not (AceType.AccessAllowed or AceType.AccessDenied) ||
                    (a.Flags & (AceFlags.ObjectInherit | AceFlags.ContainerInherit)) != 0 && (a.Sid == WellKnownSids.CreatorOwner || a.Sid == WellKnownSids.CreatorGroup))) return NtStatus.NotSupported;

            if (descriptor.Dacl is { } acl)
                descriptor = SecurityDescriptor.Create(descriptor.Owner, descriptor.Group, new Acl { Aces = acl.Aces.Select(a => new Ace { Type = a.Type, Flags = a.Flags, Sid = a.Sid, AccessMask = AccessMask.MapGenericToSpecific(a.AccessMask) }).ToList() }, descriptor.Sacl, descriptor.Control);
            var bytes = descriptor.ToBytes();
            return Transaction(cancellationToken, () =>
            {
                Exec("UPDATE objects SET security=$s,changed=$t WHERE id=$id", ("$id", n.Id), ("$s", bytes), ("$t", Now()));
                return NtStatus.Success;
            });
        });

    private static SecurityDescriptor DefaultDescriptor() => SecurityDescriptor.Create(WellKnownSids.LocalSystem, WellKnownSids.BuiltinUsers, new Acl { Aces = [Ace.Allow(WellKnownSids.Everyone, AccessMask.FileAllAccess)] });

    private FileEntryInfo Info(Node n) =>
        new FileEntryInfo
        {
            Name = n.Name, EndOfFile = n.Length, AllocationSize = Convert.ToInt64(Scalar("SELECT COUNT(*) FROM chunks WHERE object_id=$id", ("$id", n.Id))) * ChunkSize,
            Attributes = (SmbFileAttributes)n.Attributes, CreationTime = n.Created, LastAccessTime = n.Accessed, LastWriteTime = n.Written, ChangeTime = n.Changed, IndexNumber = n.Index, DeletePending = n.Pending,
        };

    private string LogicalPath(Node n) => n.Parent is null ? n.Name : JoinPath(LogicalPath(Get(n.Parent)!), n.Name);
    private static string JoinPath(string parent, string name) => parent.Length == 0 ? name : parent + "\\" + name;

    private sealed class Handle(SqliteFileStore store, string id, FileAccessIntent access) : IFileHandle
    {
        internal SqliteFileStore Store => store;
        internal string Id => id;
        internal FileAccessIntent Access => access;
        internal bool Closed;
        internal bool SuppressWriteTime;
        internal string? DetachedPath;
        internal NtStatus CloseStatus;
        private Node Node => store.Get(id) ?? throw new ObjectDisposedException(nameof(Handle));
        public FileIdentity? Identity => new FileIdentity("sqlite:" + store._databaseId + ":" + id);

        public string Path
        {
            get
            {
                lock (store._gate)
                {
                    EnsureOpen();
                    return DetachedPath ?? store.LogicalPath(Node);
                }
            }
        }

        public bool IsDirectory
        {
            get
            {
                lock (store._gate)
                {
                    EnsureOpen();
                    return Node.Directory;
                }
            }
        }

        public bool DeletePending
        {
            get
            {
                lock (store._gate)
                {
                    EnsureOpen();
                    return Node.Pending;
                }
            }
        }

        public FileEntryInfo GetInfo()
        {
            lock (store._gate)
            {
                EnsureOpen();
                return store.Info(Node);
            }
        }

        public ValueTask<FileEntryInfo> GetInfoAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return new ValueTask<FileEntryInfo>(GetInfo());
        }

        private void EnsureOpen() => ObjectDisposedException.ThrowIf(Closed || store._disposed, this);
        public ValueTask<NtStatus> CloseAsync() => new ValueTask<NtStatus>(store.Close(this));
        public void Dispose() => store.Close(this);

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }

    private NtStatus Close(Handle handle)
    {
        lock (_gate)
        {
            if (handle.Closed) return handle.CloseStatus;

            handle.Closed = true;
            _handles.Remove(handle);
            if (_disposed || _handles.Any(other => other.Id == handle.Id) || IsRetained(handle.Id)) return handle.CloseStatus = NtStatus.Success;

            try
            {
                var node = Get(handle.Id);
                if (node is null || node.Id == _rootId || !node.Pending && node.Parent is not null) return handle.CloseStatus = NtStatus.Success;

                handle.CloseStatus = Transaction(CancellationToken.None, () =>
                {
                    if (node.Directory && HasChildren(node.Id))
                    {
                        Exec("UPDATE objects SET pending=0 WHERE id=$id", ("$id", node.Id));
                        return NtStatus.DirectoryNotEmpty;
                    }

                    Exec("DELETE FROM objects WHERE id=$id", ("$id", node.Id));
                    if (node.Parent is not null) TouchParent(node.Parent, Now());
                    return NtStatus.Success;
                });
            }
            catch (SqliteException e) { handle.CloseStatus = Error(e); }

            return handle.CloseStatus;
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;

            foreach (var handle in _handles.ToArray()) Close(handle);
            _disposed = true;
            _db.Dispose();
        }
    }

    public ValueTask DisposeAsync()
    {
        Dispose();
        return ValueTask.CompletedTask;
    }
}
