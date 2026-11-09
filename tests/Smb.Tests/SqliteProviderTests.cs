using System.Buffers;
using Smb.FileSystem;
using Smb.FileSystem.Sqlite;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Security;
using Smb.Testing;

internal static class SqliteProviderTests
{
    public static IEnumerable<(string Name, Func<Task> Run)> Cases()
    {
        yield return ("sqlite.core.persistence-identity", Persistence);
        yield return ("sqlite.core.tree-case-names", Tree);
        yield return ("sqlite.core.dispositions", Dispositions);
        yield return ("sqlite.core.sparse-chunks-truncate", Sparse);
        yield return ("sqlite.core.metadata-security", Metadata);
        yield return ("sqlite.core.ownership-alias", Ownership);
        yield return ("sqlite.core.unsupported-schema", Version);
        yield return ("sqlite.lifecycle.rename-replacement", Rename);
        yield return ("sqlite.lifecycle.directory-descendants", Descendants);
        yield return ("sqlite.lifecycle.shared-delete", SharedDelete);
        yield return ("sqlite.lifecycle.directory-delete", DirectoryDelete);
        yield return ("sqlite.lifecycle.bounded-wildcard-cursor", Enumeration);
        yield return ("sqlite.lifecycle.authorization", Authorization);
        yield return ("sqlite.lifecycle.authorization-gate", AuthorizationGate);
        yield return ("sqlite.lifecycle.cancel-handles-readonly", HandleValidation);
        yield return ("sqlite.lifecycle.startup-orphans", Orphans);
        yield return ("sqlite.lifecycle.repeated-missing-parent", RepeatedParent);
        yield return ("sqlite.edges.cancel-write-rollback", CancelWrite);
        yield return ("sqlite.edges.raw-smb-wildcards", Wildcards);
        yield return ("sqlite.edges.unlimited-bounded-overload", UnlimitedListing);
        yield return ("sqlite.edges.corruption-reject-no-mutation", Corruption);
        yield return ("sqlite.edges.invalid-unicode-names", InvalidUnicode);
        yield return ("sqlite.edges.validation-before-truncate", FailureSideEffects);
        yield return ("sqlite.edges.security-inheritance", Inheritance);
        yield return ("sqlite.edges.concurrent-disjoint-writes", ConcurrentWrites);
        yield return ("sqlite.edges.identity-space-reopen", IdentitySpace);
        yield return ("sqlite.edges.unsupported-application", WrongApplication);
        yield return ("sqlite.edges.cursor-move-lookahead", CursorMutation);
        yield return ("sqlite.validation.detached-handle-path", DetachedPath);
        yield return ("sqlite.grants.destructive-implicit-read-grant", ImplicitGrant);
        foreach (var disposition in Enum.GetValues<CreateDispositionIntent>())
            foreach (var exists in new[] { false, true })
            {
                var d = disposition; var e = exists;
                yield return ($"sqlite.validation.file-disposition.{d}.{e}", () => DispositionMatrix(d, e, false));
                yield return ($"sqlite.validation.directory-disposition.{d}.{e}", () => DispositionMatrix(d, e, true));
            }
    }
    private sealed class Fixture : IDisposable
    {
        public string DirectoryPath { get; } = Path.Combine(Path.GetTempPath(), "smb-sqlite-" + Guid.NewGuid().ToString("N"));
        public string Database => Path.Combine(DirectoryPath, "files.db");
        public Fixture() => Directory.CreateDirectory(DirectoryPath);
        public void Dispose() => Directory.Delete(DirectoryPath, true);
    }
    private static async Task<IFileHandle> Open(SqliteFileStore store, string path, bool dir = false, CreateDispositionIntent disposition = CreateDispositionIntent.OpenIf, FileAccessIntent access = FileAccessIntent.ReadWrite | FileAccessIntent.Delete)
    {
        var result = await store.CreateAsync(path, access, disposition, dir, !dir);
        Check.Equal(NtStatus.Success, result.Status, "open " + path);
        return result.Value.Handle;
    }
    private static async Task<byte[]> Read(SqliteFileStore store, IFileHandle handle, long offset, int length)
    {
        var data = new byte[length]; var result = await store.ReadAsync(handle, offset, data);
        Check.Equal(NtStatus.Success, result.Status, "read status"); return data[..result.Value];
    }
    private static async Task Persistence()
    {
        using var f = new Fixture(); FileIdentity id; long index; VolumeInfo volume;
        using (var store = new SqliteFileStore(f.Database))
        {
            Check.That(store.HasExclusiveServerAccess, "exclusive ownership advertised only while held");
            using var h = await Open(store, "persist.txt");
            Check.Equal(4, (await store.WriteAsync(h, 0, "data"u8.ToArray())).Value, "written");
            Check.Equal(NtStatus.Success, await store.FlushAsync(h), "durable flush");
            id = h.Identity!.Value; index = h.GetInfo().IndexNumber; volume = store.GetVolumeInfo();
            Check.That(h.PhysicalPath is null, "logical object has no host path");
        }
        using (var store = new SqliteFileStore(f.Database))
        {
            using var h = await Open(store, "PERSIST.TXT", disposition: CreateDispositionIntent.Open);
            Check.Equal(id, h.Identity!.Value, "persistent identity"); Check.Equal(index, h.GetInfo().IndexNumber, "stable index");
            Check.Equal(volume.SerialNumber, store.GetVolumeInfo().SerialNumber, "database identity");
            Check.That((await Read(store, h, 0, 9)).SequenceEqual("data"u8.ToArray()), "persistent bytes");
        }
        Check.That(!File.Exists(Path.Combine(f.DirectoryPath, "persist.txt")), "no host-backed content");
    }
    private static async Task Tree()
    {
        using var f = new Fixture(); using var s = new SqliteFileStore(f.Database);
        using var root = await Open(s, "", true); using var d = await Open(s, "Dir", true); using var h = await Open(s, "dir\\File.txt");
        Check.Equal(h.Identity!.Value, (await s.ResolveIdentityAsync("DIR/file.TXT"))!.Value, "host independent casing");
        Check.Equal(NtStatus.ObjectNameCollision, (await s.CreateAsync("DIR", FileAccessIntent.ReadWrite, CreateDispositionIntent.Create, true, false)).Status, "case uniqueness");
        Check.Equal(NtStatus.ObjectPathNotFound, (await s.CreateAsync("missing/child", FileAccessIntent.ReadWrite, CreateDispositionIntent.OpenIf, false, true)).Status, "no implicit parents");
        Check.Equal(NtStatus.NotADirectory, (await s.CreateAsync("Dir/File.txt/child", FileAccessIntent.ReadWrite, CreateDispositionIntent.OpenIf, false, true)).Status, "file parent");
        foreach (var bad in new[] { "../escape", "Dir/../escape", "a//b", "a/./b", "bad:name", "bad*name", "bad\0name", "a/", "trail ", "trail.", new string('a', 256) })
            Check.Equal(NtStatus.ObjectNameInvalid, (await s.CreateAsync(bad, FileAccessIntent.ReadWrite, CreateDispositionIntent.OpenIf, false, true)).Status, "invalid " + bad);
        Check.Equal(NtStatus.FileIsADirectory, (await s.CreateAsync("Dir", FileAccessIntent.Read, CreateDispositionIntent.Open, false, true)).Status, "strict file");
        Check.Equal(NtStatus.NotADirectory, (await s.CreateAsync("dir/File.txt", FileAccessIntent.Read, CreateDispositionIntent.Open, true, false)).Status, "strict directory");
    }
    private static async Task Dispositions()
    {
        using var f = new Fixture(); using var s = new SqliteFileStore(f.Database);
        foreach (var disposition in Enum.GetValues<CreateDispositionIntent>())
        {
            var name = disposition.ToString(); var first = await s.CreateAsync(name, FileAccessIntent.ReadWrite, disposition, false, true);
            if (disposition is CreateDispositionIntent.Open or CreateDispositionIntent.Overwrite)
            { Check.Equal(NtStatus.ObjectNameNotFound, first.Status, "missing open/overwrite"); continue; }
            Check.Equal(NtStatus.Success, first.Status, "create disposition"); Check.Equal(CreateOutcome.Created, first.Value.Action, "created action");
            using var h = first.Value.Handle; await s.WriteAsync(h, 0, new byte[] { 7, 8 });
            var again = await s.CreateAsync(name, FileAccessIntent.ReadWrite, disposition, false, true);
            if (disposition == CreateDispositionIntent.Create) { Check.Equal(NtStatus.ObjectNameCollision, again.Status, "collision"); Check.Equal(2L, h.GetInfo().EndOfFile, "no truncate on collision"); continue; }
            Check.Equal(NtStatus.Success, again.Status, "repeat"); using var h2 = again.Value.Handle;
            var expected = disposition == CreateDispositionIntent.OpenIf ? CreateOutcome.Opened : disposition == CreateDispositionIntent.Supersede ? CreateOutcome.Superseded : CreateOutcome.Overwritten;
            Check.Equal(expected, again.Value.Action, "existing action"); Check.Equal(expected == CreateOutcome.Opened ? 2L : 0L, h.GetInfo().EndOfFile, "truncate only destructive");
        }
        using var file = await Open(s, "denied"); await s.WriteAsync(file, 0, new byte[] { 4 });
        Check.Equal(NtStatus.AccessDenied, (await s.CreateAsync("denied", FileAccessIntent.Read, CreateDispositionIntent.Overwrite, false, true)).Status, "destructive read access denied");
        Check.Equal(1L, file.GetInfo().EndOfFile, "denied preserves data");
    }
    private static async Task Sparse()
    {
        using var f = new Fixture(); using var s = new SqliteFileStore(f.Database); using var h = await Open(s, "sparse");
        var data = Enumerable.Range(0, 140000).Select(i => (byte)(i % 251)).ToArray();
        Check.Equal(data.Length, (await s.WriteAsync(h, 65530, data)).Value, "cross chunks");
        Check.That((await Read(s, h, 65530, data.Length)).SequenceEqual(data), "cross chunk bytes");
        Check.That((await Read(s, h, 0, 65530)).All(b => b == 0), "hole zeros");
        const long high = (long)int.MaxValue + 1048576;
        await s.WriteAsync(h, high, new byte[] { 9, 8, 7 }); Check.Equal(high + 3, h.GetInfo().EndOfFile, "64 bit EOF");
        Check.That((await Read(s, h, high - 3, 8)).SequenceEqual(new byte[] { 0, 0, 0, 9, 8, 7 }), "64 bit sparse offset");
        Check.Equal(NtStatus.Success, await s.SetEndOfFileAsync(h, 65535), "shrink");
        Check.Equal(NtStatus.Success, await s.SetEndOfFileAsync(h, high + 3), "grow cheaply");
        Check.That((await Read(s, h, 65535, 140000)).All(b => b == 0), "truncated tail cleared");
        Check.That((await Read(s, h, high, 3)).All(b => b == 0), "deleted chunks never return");
        Check.Equal(NtStatus.InvalidParameter, (await s.WriteAsync(h, long.MaxValue, new byte[] { 1 })).Status, "overflow");
        Check.Equal(NtStatus.InvalidParameter, (await s.ReadAsync(h, -1, new byte[1])).Status, "negative");
        Check.Equal(NtStatus.InvalidParameter, await s.SetEndOfFileAsync(h, -1), "negative EOF");
        Check.That(new FileInfo(f.Database).Length < 2_000_000, "sparse growth bounded storage");
    }
    private static async Task Metadata()
    {
        using var f = new Fixture(); byte[] security;
        var time = DateTime.UtcNow.AddDays(-2).ToFileTimeUtc();
        using (var s = new SqliteFileStore(f.Database))
        {
            using var h = await Open(s, "meta");
            var descriptor = SecurityDescriptor.Create(WellKnownSids.BuiltinUsers, WellKnownSids.Everyone, new Acl { Aces = [Ace.Allow(WellKnownSids.Everyone, AccessMask.GenericRead)] });
            Check.Equal(NtStatus.Success, await s.SetSecurityAsync(h, descriptor), "set security"); security = (await s.GetSecurityAsync(h)).Value!.ToBytes();
            Check.Equal(NtStatus.Success, await s.SetBasicInfoAsync(h, new() { CreationTime = time, LastAccessTime = time + 1, LastWriteTime = time + 2, ChangeTime = time + 3, Attributes = 2, SuppressLastWriteTimeUpdates = true }), "basic info");
            await s.WriteAsync(h, 0, new byte[] { 42 }); Check.Equal(time + 2, h.GetInfo().LastWriteTime, "write suppression per handle");
        }
        using (var s = new SqliteFileStore(f.Database))
        {
            using var h = await Open(s, "meta"); var info = h.GetInfo();
            Check.Equal(time, info.CreationTime, "creation persistent"); Check.Equal(time + 1, info.LastAccessTime, "access persistent");
            Check.That(info.Attributes.HasFlag(SmbFileAttributes.Hidden | SmbFileAttributes.Archive), "attributes plus archive");
            Check.That((await s.GetSecurityAsync(h)).Value!.ToBytes().SequenceEqual(security), "security persistent");
            await s.WriteAsync(h, 0, new byte[] { 43 }); Check.That(h.GetInfo().LastWriteTime != time + 2, "suppression is process local");
        }
    }
    private static Task Ownership()
    {
        using var f = new Fixture();
        using (var s = new SqliteFileStore(f.Database))
        {
            foreach (var path in new[] { f.Database, Path.Combine(f.DirectoryPath, ".", "files.db") })
            {
                var rejected = false; try { using var duplicate = new SqliteFileStore(path); } catch (IOException) { rejected = true; }
                Check.That(rejected, "duplicate ownership rejected");
            }
            if (!OperatingSystem.IsWindows())
            {
                var link = Path.Combine(f.DirectoryPath, "alias.db"); File.CreateSymbolicLink(link, f.Database);
                var rejected = false; try { using var duplicate = new SqliteFileStore(link); } catch (IOException) { rejected = true; }
                Check.That(rejected, "symlink ownership rejected");
            }
        }
        using var reopened = new SqliteFileStore(f.Database); return Task.CompletedTask;
    }
    private static Task Version()
    {
        using var f = new Fixture(); using (var s = new SqliteFileStore(f.Database)) { }
        using (var db = new SqliteConnection(new SqliteConnectionString(f.Database, true)))
        { db.ExecuteNonQuery("PRAGMA user_version=999; CREATE TABLE sentinel(value TEXT); INSERT INTO sentinel VALUES('untouched');"); }
        var before = File.ReadAllBytes(f.Database); var rejected = false;
        try { using var s = new SqliteFileStore(f.Database); } catch (NotSupportedException) { rejected = true; }
        Check.That(rejected, "future schema rejected"); Check.That(before.SequenceEqual(File.ReadAllBytes(f.Database)), "unsupported DB byte unchanged");
        return Task.CompletedTask;
    }

    private static async Task Rename()
    {
        using var f = new Fixture(); using var s = new SqliteFileStore(f.Database);
        using var src = await Open(s, "source"); using var dst = await Open(s, "target");
        await s.WriteAsync(src, 0, new byte[] { 1, 2 }); await s.WriteAsync(dst, 0, new byte[] { 9 });
        var id = src.Identity!.Value; var old = dst.Identity!.Value;
        Check.Equal(NtStatus.ObjectNameCollision, await s.RenameAsync(src, "target", false), "replace denied");
        Check.Equal(NtStatus.Success, await s.RenameAsync(src, "target", true), "replace succeeds");
        Check.Equal(id, (await s.ResolveIdentityAsync("target"))!.Value, "name now source identity");
        Check.That(await s.ResolveIdentityAsync("source") is null, "old name gone");
        Check.That((await Read(s, dst, 0, 3)).SequenceEqual(new byte[] { 9 }), "replaced target pinned");
        Check.Equal(old, dst.Identity!.Value, "old target identity retained");
        Check.That((await Read(s, src, 0, 3)).SequenceEqual(new byte[] { 1, 2 }), "source bytes retained");
        Check.Equal(NtStatus.Success, await s.RenameAsync(src, "TARGET", false), "case only rename"); Check.Equal("TARGET", src.Path, "current path");
        Check.Equal(NtStatus.Success, await s.RenameAsync(src, "TARGET", false), "same name rename");
        await dst.DisposeAsync(); using var fresh = await Open(s, "fresh"); Check.That(fresh.Identity != old, "no deleted ID reuse");
        Check.Equal(id, src.Identity!.Value, "rename keeps identity");
    }
    private static async Task Descendants()
    {
        using var f = new Fixture(); using var s = new SqliteFileStore(f.Database);
        using var dir = await Open(s, "parent", true); using var nested = await Open(s, "parent/nested", true);
        using var child = await Open(s, "parent/nested/child"); await s.WriteAsync(child, 0, new byte[] { 42 });
        Check.That((await s.GetOpenDescendantsAsync(dir)).Contains(child.Identity!.Value), "acquired descendant identity");
        Check.Equal(NtStatus.AccessDenied, await s.RenameDirectoryAsync(dir, "moved", false), "atomic SMB descendant denial");
        Check.Equal(NtStatus.Success, await s.RenameAsync(dir, "moved", false), "generic relocation with open child");
        Check.Equal("moved\\nested\\child", child.Path, "child path follows acquired parent");
        Check.That((await Read(s, child, 0, 1)).SequenceEqual(new byte[] { 42 }), "child usable");
        Check.Equal(NtStatus.InvalidParameter, await s.RenameAsync(dir, "moved/nested/loop", false), "cycle prevented");
        child.Dispose(); nested.Dispose(); Check.Equal(NtStatus.Success, await s.RenameDirectoryAsync(dir, "final", false), "strict rename after close");
    }
    private static async Task SharedDelete()
    {
        using var f = new Fixture(); FileIdentity old;
        using (var s = new SqliteFileStore(f.Database))
        {
            using var a = await Open(s, "delete"); using var b = await Open(s, "DELETE"); old = a.Identity!.Value;
            Check.Equal(NtStatus.Success, await s.SetDeleteOnCloseAsync(a, true), "mark"); Check.That(b.DeletePending, "shared pending");
            Check.Equal((NtStatus)0xc0000056, (await s.CreateAsync("delete", FileAccessIntent.Read, CreateDispositionIntent.Open, false, true)).Status, "no opens pending");
            Check.Equal(NtStatus.Success, await s.SetDeleteOnCloseAsync(b, false), "clear from another handle"); Check.That(!a.DeletePending, "shared clear");
            Check.Equal(NtStatus.Success, await s.SetDeleteOnCloseAsync(a, true), "remark"); await a.CloseAsync();
            Check.That(await s.ResolveIdentityAsync("delete") is not null, "retained until last close");
            Check.Equal(NtStatus.Success, await b.CloseAsync(), "final close"); Check.That(await s.ResolveIdentityAsync("delete") is null, "unlinked final");
            Check.Equal(NtStatus.Success, await b.CloseAsync(), "idempotent close"); using var replacement = await Open(s, "delete"); Check.That(replacement.Identity != old, "unique replacement");
            using var clean = await Open(s, "dispose-delete"); await s.SetDeleteOnCloseAsync(clean, true);
        }
        using var reopened = new SqliteFileStore(f.Database);
        Check.That(await reopened.ResolveIdentityAsync("dispose-delete") is null, "store disposal drains handles");
        using var h = await Open(reopened, "delete", disposition: CreateDispositionIntent.Open); Check.That(h.Identity != old, "reopen replacement");
    }
    private static async Task DirectoryDelete()
    {
        using var f = new Fixture(); using var s = new SqliteFileStore(f.Database);
        using var root = await Open(s, "", true); Check.Equal(NtStatus.AccessDenied, await s.SetDeleteOnCloseAsync(root, true), "root protected");
        using var d = await Open(s, "dir", true); using var child = await Open(s, "dir/child");
        Check.Equal(NtStatus.DirectoryNotEmpty, await s.SetDeleteOnCloseAsync(d, true), "nonrecursive"); Check.That(!d.DeletePending, "failed disposition no side effect");
        await s.SetDeleteOnCloseAsync(child, true); await child.CloseAsync();
        Check.Equal(NtStatus.Success, await s.SetDeleteOnCloseAsync(d, true), "empty dir mark"); Check.Equal(NtStatus.Success, await d.CloseAsync(), "empty dir close");
        Check.That(await s.ResolveIdentityAsync("dir") is null, "empty dir removed");
    }
    private static async Task Enumeration()
    {
        using var f = new Fixture(); using var s = new SqliteFileStore(f.Database); using var root = await Open(s, "", true);
        var names = Enumerable.Range(0, 75).Select(i => $"item-{i:000}.TXT").Concat(["no-extension", "other.bin"]).ToArray();
        foreach (var name in names) { using var h = await Open(s, name); }
        var opened = await s.OpenDirectoryCursorAsync(root, "*.txt"); Check.Equal(NtStatus.Success, opened.Status, "cursor"); using var cursor = opened.Value!;
        var entries = new List<FileEntryInfo>(); bool truncated;
        do { var page = await cursor.ReadAsync(7); Check.Equal(NtStatus.Success, page.Status, "page"); Check.That(page.Value.Entries.Count <= 7, "bounded page"); entries.AddRange(page.Value.Entries); truncated = page.Value.Truncated; } while (truncated);
        Check.That(entries.Select(e => e.Name).SequenceEqual(names.Take(75)), "all wildcard entries once in stable order");
        foreach (var e in entries) { using var h = await Open(s, e.Name); Check.Equal(h.GetInfo().IndexNumber, e.IndexNumber, "listing stable index"); }
        var all = await s.QueryDirectoryAsync(root, "*.*"); Check.Equal(77, all.Value!.Count, "Win32 star-dot-star includes dotless");
        var bounded = await ((IFileStore)s).QueryDirectoryAsync(root, "*", 4); Check.Equal(4, bounded.Value.Entries.Count, "bounded listing"); Check.That(bounded.Value.Truncated, "bounded continuation signal");
        cursor.Dispose(); Check.Equal(NtStatus.FileClosed, (await cursor.ReadAsync(1)).Status, "closed cursor");
        Check.Equal(NtStatus.ObjectNameInvalid, (await s.OpenDirectoryCursorAsync(root, "../*")).Status, "invalid pattern");
    }
    private static async Task Authorization()
    {
        using var f = new Fixture(); using var s = new SqliteFileStore(f.Database); using var h = await Open(s, "auth");
        await s.WriteAsync(h, 0, new byte[] { 8, 9 }); var id = h.Identity; var calls = 0;
        var denied = await s.CreateAuthorizedAsync("auth", "", FileAccessIntent.ReadWrite, CreateDispositionIntent.Overwrite, false, true, 0, _ => { calls++; return false; }, (_, _) => true, _ => true);
        Check.Equal(NtStatus.AccessDenied, denied.Status, "existing deny"); Check.Equal(1, calls, "existing predicate called"); Check.Equal(2L, h.GetInfo().EndOfFile, "denial preserves EOF");
        var stale = await s.CreateAuthorizedAsync("auth", "", FileAccessIntent.ReadWrite, CreateDispositionIntent.Supersede, false, true, 0, _ => true, (_, _) => true, _ => false);
        Check.Equal(NtStatus.Retry, stale.Status, "identity retry"); Check.Equal(2L, h.GetInfo().EndOfFile, "retry preserves bytes");
        var missing = await s.CreateAuthorizedAsync("missing", "", FileAccessIntent.ReadWrite, CreateDispositionIntent.Create, false, true, 0, _ => true, (_, _) => false, _ => true);
        Check.Equal(NtStatus.AccessDenied, missing.Status, "parent deny"); Check.That(await s.ResolveIdentityAsync("missing") is null, "no denied child");
        var grant = await s.CreateAuthorizedAsync("auth", "", FileAccessIntent.ReadWrite, CreateDispositionIntent.Open, false, true, 0, (_, mask) => { Check.That((mask & AccessMask.FileReadData) != 0, "supported access"); return FileAccessIntent.Read; }, (_, _) => true, actual => actual == id);
        Check.Equal(NtStatus.Success, grant.Status, "grant reduction"); using var read = grant.Value.Handle;
        Check.Equal(NtStatus.AccessDenied, (await s.WriteAsync(read, 0, new byte[] { 1 })).Status, "fixed reduced grant");
        using var cts = new CancellationTokenSource();
        try { await s.CreateAuthorizedAsync("auth", "", FileAccessIntent.ReadWrite, CreateDispositionIntent.Overwrite, false, true, 0, _ => { cts.Cancel(); return true; }, (_, _) => true, _ => true, cts.Token); throw new InvalidOperationException("missing cancellation"); } catch (OperationCanceledException) { }
        Check.Equal(2L, h.GetInfo().EndOfFile, "cancellation after authorization prevents mutation");
        var ads = await s.CreateAuthorizedAsync("new-base", ":ads", FileAccessIntent.ReadWrite, CreateDispositionIntent.OpenIf, false, true, 0, _ => true, (_, _) => true, _ => true);
        Check.Equal(NtStatus.NotSupported, ads.Status, "ADS honestly unsupported"); Check.That(await s.ResolveIdentityAsync("new-base") is null, "unsupported stream no base creation");
    }
    private static async Task AuthorizationGate()
    {
        using var f = new Fixture(); using var s = new SqliteFileStore(f.Database); using var h = await Open(s, "gate");
        using var entered = new ManualResetEventSlim(); using var release = new ManualResetEventSlim(); using var setterStarted = new ManualResetEventSlim();
        var auth = Task.Run(async () => await s.CreateAuthorizedAsync("gate", "", FileAccessIntent.ReadWrite, CreateDispositionIntent.Overwrite, false, true, 0,
            _ => { entered.Set(); Check.That(release.Wait(Check.Timeout), "release predicate"); return true; }, (_, _) => true, _ => true));
        Check.That(entered.Wait(Check.Timeout), "authorization reached controlled predicate");
        var setter = Task.Run(async () => { setterStarted.Set(); return await s.SetBasicInfoAsync(h, new() { Attributes = 1 }); });
        try { Check.That(setterStarted.Wait(Check.Timeout), "setter started"); Check.That(!setter.IsCompleted, "mutation blocked by auth guard"); }
        finally { release.Set(); }
        var result = await auth.WaitAsync(Check.Timeout); Check.Equal(NtStatus.Success, result.Status, "guarded auth complete"); result.Value.Handle.Dispose();
        Check.Equal(NtStatus.Success, await setter.WaitAsync(Check.Timeout), "ordered setter");
        uint supported = uint.MaxValue;
        var reduced = await s.CreateAuthorizedAsync("gate", "", FileAccessIntent.ReadWrite, CreateDispositionIntent.Open, false, true, 0, (_, mask) => { supported = mask; return FileAccessIntent.Read; }, (_, _) => true, _ => true);
        Check.Equal(NtStatus.Success, reduced.Status, "read-only DOS reduced open"); reduced.Value.Handle.Dispose();
        Check.That((supported & AccessMask.FileWriteData) == 0, "DOS restriction in atomic grant mask");
    }
    private static async Task HandleValidation()
    {
        using var f = new Fixture(); using var f2 = new Fixture();
        using (var s = new SqliteFileStore(f.Database))
        using (var other = new SqliteFileStore(f2.Database))
        {
            using var h = await Open(s, "handle"); Check.Equal(NtStatus.InvalidParameter, (await other.ReadAsync(h, 0, new byte[1])).Status, "foreign handle");
            using var cts = new CancellationTokenSource(); cts.Cancel();
            try { await s.WriteAsync(h, 0, new byte[] { 1 }, cts.Token); throw new InvalidOperationException("canceled write ran"); } catch (OperationCanceledException) { }
            Check.Equal(0L, h.GetInfo().EndOfFile, "canceled write unchanged");
            await h.CloseAsync(); Check.Equal(NtStatus.FileClosed, (await s.ReadAsync(h, 0, new byte[1])).Status, "closed read"); Check.Equal(NtStatus.FileClosed, await s.RenameAsync(h, "bad", false), "closed rename");
        }
        using var ro = new SqliteFileStore(f.Database, true); using var r = await Open(ro, "handle", disposition: CreateDispositionIntent.Open, access: FileAccessIntent.Read);
        Check.Equal(NtStatus.AccessDenied, (await ro.WriteAsync(r, 0, new byte[] { 1 })).Status, "readOnly write");
        Check.Equal(NtStatus.AccessDenied, (await ro.CreateAsync("absent", FileAccessIntent.Read, CreateDispositionIntent.OpenIf, false, true)).Status, "readOnly create");
        Check.Equal(NtStatus.AccessDenied, await ro.SetDeleteOnCloseAsync(r, true), "readOnly delete"); Check.Equal(NtStatus.AccessDenied, await ro.RenameAsync(r, "new", false), "readOnly rename");
        Check.Equal(NtStatus.AccessDenied, await ro.SetBasicInfoAsync(r, new() { Attributes = 2 }), "readOnly metadata");
    }
    private static async Task Orphans()
    {
        using var f = new Fixture();
        using (var s = new SqliteFileStore(f.Database))
        { using var a = await Open(s, "orphan"); using var b = await Open(s, "pending"); using var c = await Open(s, "keep"); using var d = await Open(s, "nonempty", true); using var child = await Open(s, "nonempty/child"); }
        // Independent interruption fixture: simulate committed replacement/disposition followed by process loss.
        using (var db = new SqliteConnection(new SqliteConnectionString(f.Database, true)))
        { db.ExecuteNonQuery("UPDATE objects SET parent=NULL WHERE name='orphan'; UPDATE objects SET pending=1 WHERE name IN ('pending','nonempty');"); }
        using (var s = new SqliteFileStore(f.Database))
        {
            Check.That(await s.ResolveIdentityAsync("pending") is null, "pending file finalized on restart");
            using var d = await Open(s, "nonempty", true, CreateDispositionIntent.Open); Check.That(!d.DeletePending, "nonempty pending reset rather than inaccessible");
            using var child = await Open(s, "nonempty/child", disposition: CreateDispositionIntent.Open); using var keep = await Open(s, "keep", disposition: CreateDispositionIntent.Open);
        }
        using (var db = new SqliteConnection(new SqliteConnectionString(f.Database, true)))
        { using var reader = db.ExecuteReader("SELECT COUNT(*) FROM objects WHERE name='orphan'"); Check.That(reader.Read(), "count row"); Check.Equal(0L, reader.GetInt64(0), "unlinked interrupted rows reclaimed"); }
    }
    private static async Task RepeatedParent()
    {
        using var f = new Fixture(); using var s = new SqliteFileStore(f.Database);
        Check.Equal(NtStatus.ObjectPathNotFound, (await s.CreateAsync("same/same", FileAccessIntent.ReadWrite, CreateDispositionIntent.OpenIf, false, true)).Status, "repeated missing component still parent");
        Check.That(await s.ResolveIdentityAsync("same") is null, "missing traversal has no creation effect");
    }

    private sealed class CancelingMemory(byte[] data, CancellationTokenSource source) : MemoryManager<byte>
    {
        private bool _enabled;
        internal void EnableCancellation() => _enabled = true;
        public override Span<byte> GetSpan() { if (_enabled) source.Cancel(); return data; }
        public override MemoryHandle Pin(int elementIndex = 0) => throw new NotSupportedException();
        public override void Unpin() { }
        protected override void Dispose(bool disposing) { }
    }
    private static async Task CancelWrite()
    {
        using var f = new Fixture(); using var s = new SqliteFileStore(f.Database); using var h = await Open(s, "atomic");
        var original = Enumerable.Repeat((byte)3, 150000).ToArray(); await s.WriteAsync(h, 0, original); var before = h.GetInfo();
        using var cts = new CancellationTokenSource(); using var manager = new CancelingMemory(new byte[200000], cts); var memory = manager.Memory;
        manager.EnableCancellation();
        try { await s.WriteAsync(h, 0, memory, cts.Token); throw new InvalidOperationException("write did not cancel"); } catch (OperationCanceledException) { }
        Check.That((await Read(s, h, 0, 200000)).SequenceEqual(original), "mid-transaction cancellation restores every chunk");
        Check.Equal(before.EndOfFile, h.GetInfo().EndOfFile, "rollback EOF"); Check.Equal(before.LastWriteTime, h.GetInfo().LastWriteTime, "rollback metadata");
    }
    private static async Task Wildcards()
    {
        using var f = new Fixture(); using var s = new SqliteFileStore(f.Database); using var root = await Open(s, "", true);
        foreach (var name in new[] { "a.txt", "ab.txt", ".txt", "a", "report", "report.txt", "other.bin" }) { using var h = await Open(s, name); }
        var one = await s.QueryDirectoryAsync(root, "?.txt"); Check.That(one.Value!.Select(x => x.Name).SequenceEqual(new[] { "a.txt" }), "SMB ? consumes exactly one character");
        var dos = await s.QueryDirectoryAsync(root, "report<\"" ); Check.That(dos.Value!.Any(x => x.Name == "report"), "DOS_STAR/DOS_DOT supported");
    }
    private static async Task UnlimitedListing()
    {
        using var f = new Fixture(); using var s = new SqliteFileStore(f.Database); using var root = await Open(s, "", true);
        using var a = await Open(s, "a"); using var b = await Open(s, "b");
        var result = await ((IFileStore)s).QueryDirectoryAsync(root, "*", 0); Check.Equal(NtStatus.Success, result.Status, "zero max preserves IFileStore unlimited convention");
        Check.Equal(2, result.Value.Entries.Count, "unlimited entries"); Check.That(!result.Value.Truncated, "unlimited complete");
    }
    private static async Task Corruption()
    {
        using var f = new Fixture();
        using (var s = new SqliteFileStore(f.Database)) { using var h = await Open(s, "pending"); using var bad = await Open(s, "bad"); }
        using (var db = new SqliteConnection(new SqliteConnectionString(f.Database, true)))
        { db.ExecuteNonQuery("UPDATE objects SET pending=1 WHERE name='pending'; UPDATE objects SET parent='missing-id' WHERE name='bad';"); }
        var before = File.ReadAllBytes(f.Database); var rejected = false;
        try { using var s = new SqliteFileStore(f.Database); } catch (InvalidDataException) { rejected = true; }
        Check.That(rejected, "foreign key corruption rejected"); Check.That(before.SequenceEqual(File.ReadAllBytes(f.Database)), "corrupt startup does not partially recover");
    }
    private static async Task InvalidUnicode()
    {
        using var f = new Fixture(); using var s = new SqliteFileStore(f.Database);
        foreach (var name in new[] { "bad\ud800", "bad\udfff", "bad\ud800name" })
            Check.Equal(NtStatus.ObjectNameInvalid, (await s.CreateAsync(name, FileAccessIntent.ReadWrite, CreateDispositionIntent.Create, false, true)).Status, "invalid UTF16 rejected");
        using var h = await Open(s, "Ž-文件-😀"); Check.Equal(h.Identity!.Value, (await s.ResolveIdentityAsync("ž-文件-😀"))!.Value, "valid Unicode case");
    }
    private static async Task FailureSideEffects()
    {
        using var f = new Fixture(); using var s = new SqliteFileStore(f.Database); using var h = await Open(s, "sentinel"); await s.WriteAsync(h, 0, new byte[] { 1, 4, 9 });
        var before = h.GetInfo();
        foreach (var attributes in new uint[] { 0x400, 0x800, 0x4000, uint.MaxValue })
            Check.Equal(NtStatus.InvalidParameter, (await s.CreateWithMetadataAsync("sentinel", FileAccessIntent.ReadWrite, CreateDispositionIntent.Overwrite, false, true, attributes)).Status, "unsupported attributes before truncate");
        Check.Equal(NtStatus.NotADirectory, (await s.CreateAsync("sentinel", FileAccessIntent.ReadWrite, CreateDispositionIntent.Overwrite, true, false)).Status, "type check before truncate");
        Check.Equal(NtStatus.InvalidParameter, (await s.CreateAsync("sentinel", FileAccessIntent.ReadWrite, (CreateDispositionIntent)999, false, true)).Status, "undefined disposition");
        Check.Equal(NtStatus.InvalidParameter, await s.SetBasicInfoAsync(h, new() { CreationTime = 123, LastAccessTime = -2 }), "invalid time batch atomic");
        Check.Equal(before.CreationTime, h.GetInfo().CreationTime, "no partial metadata mutation");
        Check.That((await Read(s, h, 0, 4)).SequenceEqual(new byte[] { 1, 4, 9 }), "all failed opens preserve content");
        Check.Equal(NtStatus.Success, await s.SetBasicInfoAsync(h, new() { Attributes = 1 }), "DOS readonly");
        Check.Equal(NtStatus.AccessDenied, (await s.WriteAsync(h, 0, new byte[] { 2 })).Status, "readonly writes denied");
        Check.Equal((NtStatus)0xc0000121, await s.SetDeleteOnCloseAsync(h, true), "readonly delete denied");
        Check.Equal(NtStatus.Success, await s.SetBasicInfoAsync(h, new() { Attributes = 0x80 }), "clear readonly");
    }
    private static async Task Inheritance()
    {
        using var f = new Fixture(); using var s = new SqliteFileStore(f.Database); using var d = await Open(s, "dir", true);
        var descriptor = SecurityDescriptor.Create(WellKnownSids.LocalSystem, WellKnownSids.BuiltinUsers, new Acl { Aces = [new Ace { Type = AceType.AccessAllowed, Flags = AceFlags.ObjectInherit | AceFlags.ContainerInherit, Sid = WellKnownSids.Everyone, AccessMask = AccessMask.FileGenericRead }] });
        await s.SetSecurityAsync(d, descriptor); using var child = await Open(s, "dir/child"); var security = (await s.GetSecurityAsync(child)).Value!;
        Check.Equal(1, security.Dacl!.Aces.Count, "inherited ACL"); Check.That((security.Dacl.Aces[0].Flags & AceFlags.Inherited) != 0, "inherited marker");
        Check.Equal(AccessMask.FileGenericRead, security.Dacl.Aces[0].AccessMask, "inherited mask");
    }
    private static async Task ConcurrentWrites()
    {
        using var f = new Fixture(); using var s = new SqliteFileStore(f.Database); using var h = await Open(s, "concurrent");
        using var start = new ManualResetEventSlim();
        var tasks = Enumerable.Range(0, 8).Select(i => Task.Run(async () => { Check.That(start.Wait(Check.Timeout), "start writers"); return await s.WriteAsync(h, i * 100000L, Enumerable.Repeat((byte)(i + 1), 100000).ToArray()); })).ToArray();
        start.Set(); var results = await Task.WhenAll(tasks).WaitAsync(Check.Timeout); Check.That(results.All(r => r.IsSuccess && r.Value == 100000), "all concurrent writes");
        var bytes = await Read(s, h, 0, 800000); Check.Equal(800000, bytes.Length, "concurrent EOF");
        for (var i = 0; i < 8; i++) Check.That(bytes.AsSpan(i * 100000, 100000).ToArray().All(b => b == i + 1), "disjoint chunks preserve concurrent contents");
    }
    private static async Task IdentitySpace()
    {
        using var f = new Fixture(); var ids = new HashSet<FileIdentity>(); long maxIndex = 0;
        for (var run = 0; run < 2; run++)
        using (var s = new SqliteFileStore(f.Database))
            for (var i = 0; i < 8; i++)
            { using var h = await Open(s, "reused"); Check.That(ids.Add(h.Identity!.Value), "identity never reused"); Check.That(h.GetInfo().IndexNumber > maxIndex, "index monotonic across deletion and reopen"); maxIndex = h.GetInfo().IndexNumber; await s.SetDeleteOnCloseAsync(h, true); }
    }
    private static Task WrongApplication()
    {
        using var f = new Fixture(); using (var s = new SqliteFileStore(f.Database)) { }
        using (var db = new SqliteConnection(new SqliteConnectionString(f.Database, true)))
        { db.ExecuteNonQuery("PRAGMA application_id=12345"); }
        var before = File.ReadAllBytes(f.Database); var rejected = false; try { using var s = new SqliteFileStore(f.Database); } catch (NotSupportedException) { rejected = true; }
        Check.That(rejected, "different application rejected"); Check.That(before.SequenceEqual(File.ReadAllBytes(f.Database)), "application mismatch non-destructive"); return Task.CompletedTask;
    }
    private static async Task CursorMutation()
    {
        using var f = new Fixture(); using var s = new SqliteFileStore(f.Database); using var root = await Open(s, "", true);
        using var a = await Open(s, "a"); using var b = await Open(s, "b"); using var z = await Open(s, "z", true);
        using var cursor = (await s.OpenDirectoryCursorAsync(root, "*")).Value!; var first = await cursor.ReadAsync(1); Check.Equal("a", first.Value.Entries.Single().Name, "first page");
        await s.RenameAsync(b, "z/b", false); var rest = await cursor.ReadAsync(10);
        Check.That(rest.Value.Entries.All(e => e.Name != "b"), "moved lookahead does not escape directory scope");
    }

    private static async Task DetachedPath()
    {
        using var f = new Fixture(); using var s = new SqliteFileStore(f.Database); using var d = await Open(s, "dir", true);
        using var src = await Open(s, "src"); using var dst = await Open(s, "dir/dst");
        var id = dst.Identity; Check.Equal(NtStatus.Success, await s.RenameAsync(src, "dir/dst", true), "detach nested target");
        Check.Equal("dir\\dst", dst.Path, "unlinked acquired handle retains last full path");
        Check.That(dst.Identity == id && src.Identity != id, "detached identity stays separate");
        Check.Equal(NtStatus.Success, await s.RenameAsync(d, "moved", false), "move source parent");
        Check.Equal("moved\\dst", src.Path, "linked source follows parent"); Check.Equal("dir\\dst", dst.Path, "detached path remains last path");
    }
    private static async Task DispositionMatrix(CreateDispositionIntent disposition, bool exists, bool directory)
    {
        using var f = new Fixture(); using var s = new SqliteFileStore(f.Database); IFileHandle? original = null;
        if (exists) { original = await Open(s, "name", directory); if (!directory) await s.WriteAsync(original, 0, new byte[] { 1, 2 }); }
        using (original)
        {
            var destructive = disposition is CreateDispositionIntent.Supersede or CreateDispositionIntent.Overwrite or CreateDispositionIntent.OverwriteIf;
            var expected = directory && destructive ? NtStatus.InvalidParameter : exists && disposition == CreateDispositionIntent.Create ? NtStatus.ObjectNameCollision : !exists && disposition is CreateDispositionIntent.Open or CreateDispositionIntent.Overwrite ? NtStatus.ObjectNameNotFound : NtStatus.Success;
            var result = await s.CreateAsync("name", FileAccessIntent.ReadWrite, disposition, directory, !directory);
            Check.Equal(expected, result.Status, "disposition matrix status");
            if (!result.IsSuccess) { if (!exists) Check.That(await s.ResolveIdentityAsync("name") is null, "failed directory acquisition creates nothing"); return; }
            using var h = result.Value.Handle;
            var outcome = !exists ? CreateOutcome.Created : disposition == CreateDispositionIntent.Supersede ? CreateOutcome.Superseded : destructive ? CreateOutcome.Overwritten : CreateOutcome.Opened;
            Check.Equal(outcome, result.Value.Action, "matrix action");
            if (exists) Check.Equal(original!.Identity!.Value, h.Identity!.Value, "existing object identity");
            Check.Equal(exists && !destructive && !directory ? 2L : 0L, h.GetInfo().EndOfFile, "matrix EOF");
        }
    }

    private static async Task ImplicitGrant()
    {
        using var f = new Fixture(); using var s = new SqliteFileStore(f.Database); using var h = await Open(s, "implicit");
        foreach (var disposition in new[] { CreateDispositionIntent.Overwrite, CreateDispositionIntent.OverwriteIf, CreateDispositionIntent.Supersede })
        {
            await s.WriteAsync(h, 0, new byte[] { 2, 3 });
            var result = await s.CreateAuthorizedAsync("implicit", "", FileAccessIntent.Read, disposition, false, true, 0,
                (_, supported) => { Check.That((supported & (disposition == CreateDispositionIntent.Supersede ? AccessMask.Delete : AccessMask.FileWriteData)) != 0, "implicit disposition rights supported"); return FileAccessIntent.Read; }, (_, _) => true, _ => true);
            Check.Equal(NtStatus.Success, result.Status, "authorized implicit mutation independent of final data grant"); using var acquired = result.Value.Handle;
            Check.Equal(0L, acquired.GetInfo().EndOfFile, "authorized truncate");
            Check.Equal(NtStatus.AccessDenied, (await s.WriteAsync(acquired, 0, new byte[] { 9 })).Status, "final reduced grant does not permit writes");
        }
    }
}
