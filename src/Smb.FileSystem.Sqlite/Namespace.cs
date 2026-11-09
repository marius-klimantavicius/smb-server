using System.IO.Enumeration;
using Smb.Protocol.Enums;
using Smb.Protocol.Security;

namespace Smb.FileSystem.Sqlite;

public sealed partial class SqliteFileStore
{
    public ValueTask<FileStoreResult<FileCreateResult>> CreateAuthorizedAsync(string path, string streamName,
        FileAccessIntent access, CreateDispositionIntent disposition, bool directoryRequired, bool nonDirectoryRequired, uint attributes,
        Func<SecurityDescriptor, bool> authorizeExisting, Func<SecurityDescriptor, bool, bool> authorizeParent,
        Func<FileIdentity?, bool> validateIdentity, CancellationToken cancellationToken = default)
        => CreateAuthorizedAsync(path, streamName, access, disposition, directoryRequired, nonDirectoryRequired, attributes,
            (descriptor, _) => authorizeExisting(descriptor) ? access : null, authorizeParent, validateIdentity, cancellationToken);

    public ValueTask<FileStoreResult<FileCreateResult>> CreateAuthorizedAsync(string path, string streamName,
        FileAccessIntent access, CreateDispositionIntent disposition, bool directoryRequired, bool nonDirectoryRequired, uint attributes,
        Func<SecurityDescriptor, uint, FileAccessIntent?> authorizeExisting, Func<SecurityDescriptor, bool, bool> authorizeParent,
        Func<FileIdentity?, bool> validateIdentity, CancellationToken cancellationToken = default)
        => Result(cancellationToken, () =>
        {
            FileStoreResult<FileCreateResult> Fail(NtStatus status) => FileStoreResult<FileCreateResult>.Fail(status);
            if (streamName.Length != 0) return Fail(NtStatus.NotSupported);
            if (Parts(path) is not { } parts) return Fail(NtStatus.ObjectNameInvalid);
            var (node, parent, status) = Lookup(parts); if (status != NtStatus.Success) return Fail(status);
            if (!validateIdentity(node is null ? null : Identity(node))) return Fail(NtStatus.Retry);
            if (node is not null)
            {
                if (disposition == CreateDispositionIntent.Create) return Fail(NtStatus.ObjectNameCollision);
                var mask = AccessMask.FileAllAccess;
                if (_readOnly) mask &= ~(AccessMask.FileWriteData | AccessMask.FileAppendData | AccessMask.FileWriteEa |
                    AccessMask.FileDeleteChild | AccessMask.FileWriteAttributes | AccessMask.Delete | AccessMask.WriteDac | AccessMask.WriteOwner);
                if (!node.Directory && (node.Attributes & 1) != 0)
                    mask &= ~(AccessMask.FileWriteData | AccessMask.FileAppendData | AccessMask.FileDeleteChild);
                var granted = authorizeExisting(SecurityDescriptor.Parse(node.Security), mask);
                if (!granted.HasValue) return Fail(NtStatus.AccessDenied);
                access = granted.Value;
            }
            else if (disposition is not (CreateDispositionIntent.Open or CreateDispositionIntent.Overwrite) &&
                !authorizeParent(SecurityDescriptor.Parse(parent!.Security), directoryRequired)) return Fail(NtStatus.AccessDenied);
            // Synchronous predicates may cancel or throw; neither can commit any mutation.
            cancellationToken.ThrowIfCancellationRequested();
            // Disposition rights were separately approved by the predicate. They need not
            // become data rights on the returned handle (e.g. a read-only overwrite open).
            return CreateCore(path, access, disposition, directoryRequired, nonDirectoryRequired, attributes, cancellationToken, authorized: true);
        });

    public ValueTask<NtStatus> RenameAsync(IFileHandle handle, string newPath, bool replaceIfExists, CancellationToken cancellationToken = default)
        => Status(cancellationToken, () => RenameCore(handle, newPath, replaceIfExists, false, cancellationToken));
    public ValueTask<NtStatus> RenameDirectoryAsync(IFileHandle directory, string newPath, bool replaceIfExists, CancellationToken cancellationToken = default)
        => Status(cancellationToken, () => RenameCore(directory, newPath, replaceIfExists, true, cancellationToken));
    private NtStatus RenameCore(IFileHandle handle, string newPath, bool replaceIfExists, bool strictDirectory, CancellationToken ct)
    {
        var status = Validate(handle, out var h, out var n); if (status != NtStatus.Success) return status;
        if (strictDirectory && !n.Directory) return NtStatus.NotADirectory;
        if (_readOnly || (h.Access & FileAccessIntent.Delete) == 0 || n.Id == _rootId) return NtStatus.AccessDenied;
        if (n.Pending) return DeletePendingStatus;
        if (n.Parent is null) return NtStatus.ObjectNameNotFound;
        if (Parts(newPath) is not { } parts) return NtStatus.ObjectNameInvalid;
        if (parts.Length == 0) return NtStatus.AccessDenied;
        var (target, parent, found) = Lookup(parts); if (found != NtStatus.Success) return found;
        if (parent is null) return NtStatus.AccessDenied;
        for (var ancestor = parent; ancestor is not null; ancestor = ancestor.Parent is null ? null : Get(ancestor.Parent))
            if (ancestor.Id == n.Id) return NtStatus.InvalidParameter;
        if (strictDirectory && Descendants(n).Count != 0) return NtStatus.AccessDenied;
        if (target is not null && target.Id != n.Id)
        {
            if (!replaceIfExists) return NtStatus.ObjectNameCollision;
            if (target.Pending) return DeletePendingStatus;
            if ((target.Attributes & 1) != 0) return CannotDelete;
            if (target.Directory != n.Directory) return target.Directory ? NtStatus.FileIsADirectory : NtStatus.NotADirectory;
            if (target.Directory && HasChildren(target.Id)) return NtStatus.DirectoryNotEmpty;
        }
        var detachedPath = target is not null && target.Id != n.Id ? LogicalPath(target) : null;
        var result = Transaction(ct, () =>
        {
            if (target is not null && target.Id != n.Id)
            {
                if (_handles.Any(open => open.Id == target.Id)) Exec("UPDATE objects SET parent=NULL WHERE id=$id", ("$id", target.Id));
                else Exec("DELETE FROM objects WHERE id=$id", ("$id", target.Id));
            }
            Exec("UPDATE objects SET parent=$p,name=$n,name_key=$k,changed=$t WHERE id=$id", ("$id", n.Id), ("$p", parent.Id), ("$n", parts[^1]), ("$k", Key(parts[^1])), ("$t", Now()));
            TouchParent(n.Parent, Now()); if (n.Parent != parent.Id) TouchParent(parent.Id, Now());
            return NtStatus.Success;
        });
        // Publish process-local path state only after the replacement transaction commits.
        if (detachedPath is not null)
            foreach (var open in _handles.Where(open => open.Id == target!.Id)) open.DetachedPath = detachedPath;
        return result;
    }
    private List<FileIdentity> Descendants(Node directory)
    {
        var result = new HashSet<FileIdentity>();
        foreach (var handle in _handles)
            for (var node = Get(handle.Id); node?.Parent is { } parent; node = Get(parent))
                if (parent == directory.Id) { result.Add(handle.Identity!.Value); break; }
        return result.ToList();
    }
    public ValueTask<IReadOnlyList<FileIdentity>> GetOpenDescendantsAsync(IFileHandle directory, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            cancellationToken.ThrowIfCancellationRequested(); ObjectDisposedException.ThrowIf(_disposed, this);
            var status = Validate(directory, out _, out var n);
            if (status != NtStatus.Success) throw new ArgumentException("A live directory handle from this store is required.", nameof(directory));
            if (!n.Directory) throw new ArgumentException("Handle is not a directory.", nameof(directory));
            return new((IReadOnlyList<FileIdentity>)Descendants(n));
        }
    }
    private bool HasChildren(string id) => Scalar("SELECT 1 FROM objects WHERE parent=$id LIMIT 1", ("$id", id)) is not null;
    public ValueTask<NtStatus> SetDeleteOnCloseAsync(IFileHandle handle, bool delete, CancellationToken cancellationToken = default)
        => Status(cancellationToken, () =>
        {
            var status = Validate(handle, out var h, out var n); if (status != NtStatus.Success) return status;
            if (_readOnly || (h.Access & FileAccessIntent.Delete) == 0 || n.Id == _rootId) return NtStatus.AccessDenied;
            if (delete && (n.Attributes & 1) != 0) return CannotDelete;
            if (delete && n.Directory && HasChildren(n.Id)) return NtStatus.DirectoryNotEmpty;
            return Transaction(cancellationToken, () => { Exec("UPDATE objects SET pending=$p WHERE id=$id", ("$id", n.Id), ("$p", delete)); return NtStatus.Success; });
        });

    // Startup finalizes committed dispositions and abandoned replacement rows. A pending
    // directory with surviving children is made accessible again; children are never deleted
    // recursively. A read-only open requiring recovery fails and must be opened writable once.
    private void RecoverOrphans()
    {
        var dirty = Convert.ToInt64(Scalar("SELECT COUNT(*) FROM objects WHERE pending=1 OR (parent IS NULL AND id<>$root)", ("$root", _rootId)));
        if (dirty == 0) return;
        if (_readOnly) throw new InvalidDataException("SQLite filesystem requires writable startup recovery.");
        Exec("DELETE FROM objects WHERE directory=0 AND (pending=1 OR (parent IS NULL AND id<>$root))", ("$root", _rootId));
        // Only empty directories may be reclaimed, even if the database was interrupted.
        Exec("DELETE FROM objects WHERE id<>$root AND (pending=1 OR parent IS NULL) AND NOT EXISTS(SELECT 1 FROM objects AS child WHERE child.parent=objects.id)", ("$root", _rootId));
        Exec("UPDATE objects SET pending=0 WHERE pending=1");
        if (Convert.ToInt64(Scalar("SELECT COUNT(*) FROM objects WHERE parent IS NULL AND id<>$root", ("$root", _rootId))) != 0)
            throw new InvalidDataException("Unlinked directory has children; refusing recursive recovery.");
    }

    private static string? Pattern(string pattern)
    {
        if (string.IsNullOrEmpty(pattern)) pattern = "*";
        if (pattern.Length > 255 || !ValidUnicode(pattern) || pattern.Any(c => c < 32 || c is '/' or '\\' or ':')) return null;
        return pattern == "*.*" ? "*" : pattern; // SMB expressions already contain raw DOS wildcard tokens.
    }
    public ValueTask<FileStoreResult<IDirectoryCursor>> OpenDirectoryCursorAsync(IFileHandle handle, string pattern, CancellationToken cancellationToken = default)
        => Result(cancellationToken, () =>
        {
            var status = Validate(handle, out var h, out var n); if (status != NtStatus.Success) return FileStoreResult<IDirectoryCursor>.Fail(status);
            if (!n.Directory) return FileStoreResult<IDirectoryCursor>.Fail(NtStatus.NotADirectory);
            if ((h.Access & FileAccessIntent.Read) == 0) return FileStoreResult<IDirectoryCursor>.Fail(NtStatus.AccessDenied);
            var translated = Pattern(pattern); if (translated is null) return FileStoreResult<IDirectoryCursor>.Fail(NtStatus.ObjectNameInvalid);
            return FileStoreResult<IDirectoryCursor>.Ok(new Cursor(this, h, translated));
        });
    public async ValueTask<FileStoreResult<IReadOnlyList<FileEntryInfo>>> QueryDirectoryAsync(IFileHandle handle, string searchPattern, CancellationToken cancellationToken = default)
    {
        var opened = await OpenDirectoryCursorAsync(handle, searchPattern, cancellationToken).ConfigureAwait(false);
        if (!opened.IsSuccess) return FileStoreResult<IReadOnlyList<FileEntryInfo>>.Fail(opened.Status);
        using var cursor = opened.Value!; var entries = new List<FileEntryInfo>();
        while (true)
        {
            var page = await cursor.ReadAsync(256, cancellationToken).ConfigureAwait(false);
            if (!page.IsSuccess) return FileStoreResult<IReadOnlyList<FileEntryInfo>>.Fail(page.Status);
            entries.AddRange(page.Value.Entries); if (!page.Value.Truncated) return FileStoreResult<IReadOnlyList<FileEntryInfo>>.Ok(entries);
        }
    }
    public async ValueTask<FileStoreResult<BoundedDirectoryListing>> QueryDirectoryAsync(IFileHandle handle, string searchPattern, int maxEntries, CancellationToken cancellationToken = default)
    {
        if (maxEntries <= 0)
        {
            var all = await QueryDirectoryAsync(handle, searchPattern, cancellationToken).ConfigureAwait(false);
            return all.IsSuccess ? FileStoreResult<BoundedDirectoryListing>.Ok(new(all.Value!, false)) : FileStoreResult<BoundedDirectoryListing>.Fail(all.Status);
        }
        var opened = await OpenDirectoryCursorAsync(handle, searchPattern, cancellationToken).ConfigureAwait(false);
        if (!opened.IsSuccess) return FileStoreResult<BoundedDirectoryListing>.Fail(opened.Status);
        using var cursor = opened.Value!; return await cursor.ReadAsync(maxEntries, cancellationToken).ConfigureAwait(false);
    }
    // Keyset enumeration holds no database reader or unbounded in-memory listing across
    // calls. New/renamed names after the key may appear; names before it are not revisited.
    private sealed class Cursor(SqliteFileStore store, Handle directory, string pattern) : IDirectoryCursor
    {
        private string _after = "";
        private Node? _lookahead;
        private bool _closed;
        private bool _exhausted;
        public ValueTask<FileStoreResult<BoundedDirectoryListing>> ReadAsync(int maxEntries, CancellationToken cancellationToken = default)
            => store.Result(cancellationToken, () =>
            {
                if (_closed) return FileStoreResult<BoundedDirectoryListing>.Fail(NtStatus.FileClosed);
                var status = store.Validate(directory, out _, out _);
                if (status != NtStatus.Success) return FileStoreResult<BoundedDirectoryListing>.Fail(status);
                if (maxEntries <= 0) return FileStoreResult<BoundedDirectoryListing>.Fail(NtStatus.InvalidParameter);
                // Bound each allocation even when a caller supplies an unreasonable maximum.
                var limit = Math.Min(maxEntries, 4096); var entries = new List<FileEntryInfo>();
                while (entries.Count < limit)
                {
                    var next = Next(cancellationToken); if (next is null) break;
                    entries.Add(store.Info(next));
                }
                _lookahead = Next(cancellationToken);
                return FileStoreResult<BoundedDirectoryListing>.Ok(new(entries, _lookahead is not null));
            });
        private Node? Next(CancellationToken ct)
        {
            if (_lookahead is { } buffered)
            {
                _lookahead = null;
                var current = store.Get(buffered.Id);
                if (current?.Parent == directory.Id && Key(current.Name) == Key(buffered.Name)) return current;
            }
            while (!_exhausted)
            {
                ct.ThrowIfCancellationRequested();
                var n = store.Find("parent=$p AND name_key>$after ORDER BY name_key LIMIT 1", ("$p", directory.Id), ("$after", _after));
                if (n is null) { _exhausted = true; return null; }
                _after = Key(n.Name);
                if (FileSystemName.MatchesWin32Expression(pattern, n.Name, true)) return n;
            }
            return null;
        }
        public void Dispose() { lock (store._gate) { _closed = true; _lookahead = null; } }
    }
}
