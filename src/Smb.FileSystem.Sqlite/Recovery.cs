using Smb.Protocol.Enums;

namespace Smb.FileSystem.Sqlite;

public sealed partial class SqliteFileStore
{
    public string RecoveryStoreIdentity => "sqlite:" + _databaseId;
    private bool HasRecoveryTable => Convert.ToInt64(Scalar("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='smb_recovery_retention'")) != 0;
    private bool IsRetained(string id) => HasRecoveryTable && Convert.ToInt64(Scalar("SELECT count(*) FROM smb_recovery_retention WHERE object_id=$id", ("$id", id))) != 0;

    public RecoveryFileState CaptureRecoveryState(IFileHandle handle)
    {
        lock (_gate)
        {
            if (Validate(handle, out var h, out _) != NtStatus.Success) throw new ObjectDisposedException(nameof(handle));

            return new(h.Path, h.SuppressWriteTime);
        }
    }

    public NtStatus RetainForRecovery(IFileHandle handle, Guid token)
    {
        lock (_gate)
        {
            var status = Validate(handle, out var h, out var node);
            if (status != NtStatus.Success) return status;
            if (_readOnly || token == Guid.Empty || node.Directory) return NtStatus.NotSupported;

            return Transaction(CancellationToken.None, () =>
            {
                Exec("CREATE TABLE IF NOT EXISTS smb_recovery_retention(token TEXT PRIMARY KEY,object_id TEXT NOT NULL REFERENCES objects(id) ON DELETE RESTRICT) WITHOUT ROWID");
                var prior = Scalar("SELECT object_id FROM smb_recovery_retention WHERE token=$token", ("$token", token.ToString("N"))) as string;
                if (prior != null) return prior == h.Id ? NtStatus.Success : NtStatus.InvalidParameter;

                Exec("INSERT INTO smb_recovery_retention VALUES($token,$id)", ("$token", token.ToString("N")), ("$id", h.Id));
                return NtStatus.Success;
            });
        }
    }

    public NtStatus ReleaseRecovery(Guid token)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (!HasRecoveryTable) return NtStatus.Success;

            var id = Scalar("SELECT object_id FROM smb_recovery_retention WHERE token=$token", ("$token", token.ToString("N"))) as string;
            if (id == null) return NtStatus.Success;

            Transaction(CancellationToken.None, () =>
            {
                Exec("DELETE FROM smb_recovery_retention WHERE token=$token", ("$token", token.ToString("N")));
                return true;
            });
            if (_handles.Any(h => h.Id == id) || IsRetained(id)) return NtStatus.Success;

            var terminal = new Handle(this, id, FileAccessIntent.None);
            _handles.Add(terminal);
            return Close(terminal);
        }
    }

    public IReadOnlyList<Guid> GetRecoveryTokens()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (!HasRecoveryTable) return [];

            var tokens = new List<Guid>();
            using var r = Query("SELECT token FROM smb_recovery_retention ORDER BY token");
            while (r.Read()) tokens.Add(Guid.ParseExact(r.GetString(0)!, "N"));
            return tokens;
        }
    }

    public ValueTask<FileStoreResult<IFileHandle>> ReopenForRecoveryAsync(Guid token, FileIdentity identity, FileAccessIntent access, RecoveryFileState? state = null, CancellationToken cancellationToken = default)
        => Result(cancellationToken, () =>
        {
            if (!HasRecoveryTable) return FileStoreResult<IFileHandle>.Fail(NtStatus.ObjectNameNotFound);

            var id = Scalar("SELECT object_id FROM smb_recovery_retention WHERE token=$token", ("$token", token.ToString("N"))) as string;
            var node = id is null ? null : Get(id);
            if (node is null || node.Directory || Identity(node) != identity) return FileStoreResult<IFileHandle>.Fail(NtStatus.ObjectNameNotFound);
            if (_readOnly && (access & (FileAccessIntent.Write | FileAccessIntent.Delete)) != 0) return FileStoreResult<IFileHandle>.Fail(NtStatus.AccessDenied);

            var handle = new Handle(this, id!, access)
            {
                SuppressWriteTime = state?.SuppressWriteTimeUpdates == true,
                DetachedPath = node.Parent is null ? state?.Path ?? node.Name : null
            };
            _handles.Add(handle);
            return FileStoreResult<IFileHandle>.Ok(handle);
        });
}
