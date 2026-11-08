using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Testing;

static class PlatformTests
{
    public static IEnumerable<(string Name, Func<Task> Run)> Cases()
    {
        yield return ("platform.rename.same-name", SameName);
        yield return ("platform.identity.enumeration-index", EnumerationIndex);
        yield return ("platform.identity.unicode-hardlink-pins", Identity);
        yield return ("platform.rename.case-file", () => CaseRename(false));
        yield return ("platform.rename.case-directory", () => CaseRename(true));
        yield return ("platform.rename.directory-descendants-separators", Descendants);
        yield return ("platform.rename.destination-collision", Collision);
        yield return ("platform.disposition.hardlink-clear-final-close", DeleteAliases);
        yield return ("platform.disposition.directory-nonrecursive", DeleteDirectory);
        yield return ("platform.disposition.parent-rename-pending-child", PendingChildRename);
        yield return ("platform.metadata.renamed-handle", Metadata);
        yield return ("platform.metadata.replaced-name-pinned", MetadataReplacement);
        yield return ("platform.identity.named-stream-index-rename", StreamIndex);
        yield return ("platform.enumeration.bounded-case-resume", Enumeration);
        yield return ("platform.resources.failed-opens-close", Resources);
        yield return ("platform.volume.native-root", Volume);
        yield return ("platform.build-output.own-assemblies", BuildOutput);
    }
    static async Task<IFileHandle> Open(LocalFileStore s, string p, bool dir = false)
    {
        var r = await s.CreateAsync(p, FileAccessIntent.ReadWrite | FileAccessIntent.Delete, CreateDispositionIntent.OpenIf, dir, !dir);
        Check.Equal(NtStatus.Success, r.Status, "native host open " + p);
        return r.Value.Handle;
    }
    static async Task SameName()
    {
        using var r = new P2Tests.Root(); var s = new LocalFileStore(r.Path, false);
        using var a = await Open(s, "same");
        Check.Equal(NtStatus.Success, await s.RenameAsync(a, "same", false), "rename to own name succeeds");
        Check.Equal(a.Identity!.Value, (await s.ResolveIdentityAsync("same"))!.Value, "same object remains");
    }
    static async Task EnumerationIndex()
    {
        using var r = new P2Tests.Root(); var s = new LocalFileStore(r.Path, false);
        using var a = await Open(s, "a"); NativeHost.HardLink(Path.Combine(r.Path, "a"), Path.Combine(r.Path, "alias"));
        using var d = await Open(s, "", true);
        using var cursor = (await s.OpenDirectoryCursorAsync(d, "*")).Value!;
        var list = (await cursor.ReadAsync(10)).Value!.Entries;
        Check.Equal(a.GetInfo().IndexNumber, list.Single(x => x.Name == "a").IndexNumber, "directory entry and acquired handle share object index");
        Check.Equal(a.GetInfo().IndexNumber, list.Single(x => x.Name == "alias").IndexNumber, "hardlink entries share stable index");
    }
    static async Task Identity()
    {
        using var r = new P2Tests.Root(); var s = new LocalFileStore(r.Path, false);
        using var a = await Open(s, "ž-文件"); NativeHost.HardLink(a.PhysicalPath!, Path.Combine(r.Path, "alias"));
        using var b = await Open(s, "alias"); var id = a.Identity!.Value; var index = a.GetInfo().IndexNumber;
        Check.Equal(id, b.Identity!.Value, "hardlink full native identity");
        Check.Equal(NtStatus.Success, await s.RenameAsync(a, "renamed", false), "rename pinned file");
        Check.Equal(id, (await s.ResolveIdentityAsync("renamed"))!.Value, "identity survives rename");
        Check.Equal(index, a.GetInfo().IndexNumber, "index survives rename");
        Check.Equal(NtStatus.Success, (await s.WriteAsync(a, 0, new byte[] { 42 })).Status, "write pinned handle");
        var data = new byte[1]; Check.Equal(1, (await s.ReadAsync(b, 0, data)).Value, "alias remains readable"); Check.Equal((byte)42, data[0], "same object bytes");
    }
    static async Task CaseRename(bool dir)
    {
        using var r = new P2Tests.Root(); var s = new LocalFileStore(r.Path, false);
        using var a = await Open(s, "Mixed", dir); using var b = await Open(s, "Mixed", dir);
        var identity = a.Identity!.Value;
        Check.Equal(NtStatus.Success, await s.RenameAsync(a, "MIXED", false), "case-only rename while open");
        Check.Equal("MIXED", b.Path, "second open follows case rename");
        Check.That(Directory.EnumerateFileSystemEntries(r.Path).Any(p => Path.GetFileName(p) == "MIXED"), "host preserves requested spelling");
        Check.Equal(identity, (await s.ResolveIdentityAsync("MIXED"))!.Value, "case rename stable identity");
        if (OperatingSystem.IsLinux())
        {
            using var other = await Open(s, "mixed", dir);
            Check.That(other.Identity != identity, "Linux distinct case names remain distinct objects");
        }
        else
        {
            using var alias = await Open(s, "mixed", dir);
            Check.Equal(identity, alias.Identity!.Value, "Windows case alias shares full identity");
        }
    }
    static async Task Descendants()
    {
        using var r = new P2Tests.Root(); var s = new LocalFileStore(r.Path + Path.DirectorySeparatorChar, false);
        using var d = await Open(s, "Parent", true); using var c = await Open(s, "Parent\\child");
        using var alias = await Open(s, OperatingSystem.IsWindows() ? "parent/child" : "Parent/child");
        Check.Equal(NtStatus.Success, await s.RenameAsync(d, "New", false), "rename pinned directory");
        Check.Equal(c.Identity!.Value, alias.Identity!.Value, "separator aliases agree");
        Check.Equal(Path.Combine("New", "child"), alias.Path, "all descendant names relocate");
        Check.Equal(NtStatus.Success, await s.SetDeleteOnCloseAsync(alias, true), "descendant delete after move");
        Check.Equal(NtStatus.Success, await c.CloseAsync(), "first descendant close");
        Check.Equal(NtStatus.Success, await alias.CloseAsync(), "final descendant close");
        Check.That(!File.Exists(Path.Combine(r.Path, "New", "child")), "relocated child deleted");
    }
    static async Task Collision()
    {
        using var r = new P2Tests.Root(); var s = new LocalFileStore(r.Path, false);
        using var a = await Open(s, "a"); using var b = await Open(s, "b");
        Check.Equal(NtStatus.AccessDenied, await s.RenameAsync(a, "b", true), "open destination cannot be replaced");
        b.Dispose();
        Check.Equal(NtStatus.ObjectNameCollision, await s.RenameAsync(a, "b", false), "closed destination collision");
        Check.Equal(NtStatus.Success, await s.RenameAsync(a, "b", true), "closed destination replace");
        Check.Equal(a.Identity!.Value, (await s.ResolveIdentityAsync("b"))!.Value, "replacement is source object");
    }
    static async Task DeleteAliases()
    {
        using var r = new P2Tests.Root(); var s = new LocalFileStore(r.Path, false);
        using var a = await Open(s, "a"); NativeHost.HardLink(a.PhysicalPath!, Path.Combine(r.Path, "alias")); using var b = await Open(s, "alias");
        Check.Equal(NtStatus.Success, await s.SetDeleteOnCloseAsync(a, true), "mark shared pending");
        Check.That(b.DeletePending, "alias sees pending");
        var denied = await s.CreateAsync("alias", FileAccessIntent.Read, CreateDispositionIntent.Open, false, true);
        if (denied.IsSuccess) denied.Value.Handle.Dispose();
        Check.Equal((NtStatus)0xc0000056, denied.Status, "alias open rejected while pending");
        Check.Equal(NtStatus.Success, await s.SetDeleteOnCloseAsync(b, false), "alias clears shared pending");
        Check.That(!a.DeletePending, "clear visible on original");
        Check.Equal(NtStatus.Success, await s.SetDeleteOnCloseAsync(a, true), "mark original link");
        Check.Equal(NtStatus.Success, await a.CloseAsync(), "first close retains link"); Check.That(File.Exists(Path.Combine(r.Path, "a")), "link waits for final backend close");
        Check.Equal(NtStatus.Success, await b.CloseAsync(), "final alias close");
        Check.That(!File.Exists(Path.Combine(r.Path, "a")) && File.Exists(Path.Combine(r.Path, "alias")), "delete selected link preserves other hardlink");
    }
    static async Task DeleteDirectory()
    {
        using var r = new P2Tests.Root(); var s = new LocalFileStore(r.Path, false);
        using var d = await Open(s, "dir", true); using var other = await Open(s, "dir", true);
        Check.Equal(NtStatus.Success, await s.SetDeleteOnCloseAsync(d, true), "mark empty pinned directory");
        Check.Equal(NtStatus.Success, await d.CloseAsync(), "first directory close");
        Check.Equal(NtStatus.Success, await other.CloseAsync(), "final pinned directory deletes");
        Check.That(!Directory.Exists(Path.Combine(r.Path, "dir")), "directory deleted");
        using var late = await Open(s, "late", true);
        Check.Equal(NtStatus.Success, await s.SetDeleteOnCloseAsync(late, true), "mark before child arrives");
        File.WriteAllText(Path.Combine(r.Path, "late", "child"), "preserve");
        Check.Equal(NtStatus.DirectoryNotEmpty, await late.CloseAsync(), "late child makes final close fail nonrecursively");
        Check.That(File.Exists(Path.Combine(r.Path, "late", "child")), "late child preserved");
    }
    static async Task Metadata()
    {
        using var r = new P2Tests.Root(); var s = new LocalFileStore(r.Path, false);
        using var a = await Open(s, "meta");
        Check.Equal(NtStatus.Success, await s.RenameAsync(a, "meta-new", false), "metadata rename");
        var time = new DateTime(2020, 2, 3, 4, 5, 6, DateTimeKind.Utc).ToFileTimeUtc();
        Check.Equal(NtStatus.Success, await s.SetBasicInfoAsync(a, new FileBasicInfoUpdate { LastWriteTime = time }), "set handle metadata");
        Check.Equal(time, a.GetInfo().LastWriteTime, "handle metadata timestamp");
        using var directory = await Open(s, "dir-meta", true);
        Check.Equal(NtStatus.Success, await s.SetBasicInfoAsync(directory, new FileBasicInfoUpdate { LastWriteTime = time }), "set pinned directory metadata");
        Check.Equal(time, directory.GetInfo().LastWriteTime, "directory timestamp");
        using var stream = (await s.OpenNamedStreamAsync("meta-new", "alt", FileAccessIntent.ReadWrite, CreateDispositionIntent.OpenIf)).Value.Handle;
        Check.Equal(NtStatus.Success, await s.SetBasicInfoAsync(stream, new FileBasicInfoUpdate { LastWriteTime = time }), "set metadata through read-only base pin");
        Check.Equal(time, stream.GetInfo().LastWriteTime, "named stream uses acquired base metadata");
    }
    static async Task PendingChildRename()
    {
        using var r = new P2Tests.Root(); var s = new LocalFileStore(r.Path, false);
        using var directory = await Open(s, "parent", true); using var child = await Open(s, "parent/child");
        Check.Equal(NtStatus.Success, await s.SetDeleteOnCloseAsync(child, true), "child disposition before parent move");
        Check.Equal(NtStatus.Success, await s.RenameAsync(directory, "new-parent", false), "move parent of pending child");
        Check.Equal(NtStatus.Success, await child.CloseAsync(), "final child close follows relocated pending link");
        Check.That(!File.Exists(Path.Combine(r.Path, "new-parent", "child")), "pending child deleted at relocated name");
    }
    static async Task Enumeration()
    {
        using var r = new P2Tests.Root(); var s = new LocalFileStore(r.Path, false);
        for (var i = 0; i < 70; i++) File.WriteAllText(Path.Combine(r.Path, "Item-" + i), "");
        using var d = await Open(s, "", true); using var cursor = (await s.OpenDirectoryCursorAsync(d, OperatingSystem.IsWindows() ? "item-*" : "Item-*")).Value!;
        var names = new HashSet<string>();
        for (var i = 0; i < 100; i++)
        {
            var batch = (await cursor.ReadAsync(3)).Value!; Check.That(batch.Entries.Count <= 3, "bounded page");
            foreach (var entry in batch.Entries) Check.That(names.Add(entry.Name), "resume has no duplicate");
            if (!batch.Truncated) break;
        }
        Check.Equal(70, names.Count, "host case matching and complete resumable listing");
    }
    static async Task MetadataReplacement()
    {
        using var r = new P2Tests.Root(); var s = new LocalFileStore(r.Path, false);
        using var a = await Open(s, "meta");
        File.Move(Path.Combine(r.Path, "meta"), Path.Combine(r.Path, "original"));
        File.WriteAllText(Path.Combine(r.Path, "meta"), "replacement");
        var replacementTime = File.GetLastWriteTimeUtc(Path.Combine(r.Path, "meta"));
        var time = new DateTime(2020, 2, 3, 4, 5, 6, DateTimeKind.Utc).ToFileTimeUtc();
        Check.Equal(NtStatus.Success, await s.SetBasicInfoAsync(a, new FileBasicInfoUpdate { LastWriteTime = time }), "set pinned metadata after pathname replacement");
        Check.Equal(time, a.GetInfo().LastWriteTime, "metadata mutation stays on original acquired object");
        Check.Equal(replacementTime, File.GetLastWriteTimeUtc(Path.Combine(r.Path, "meta")), "replacement metadata untouched");
    }
    static async Task StreamIndex()
    {
        using var r = new P2Tests.Root(); var s = new LocalFileStore(r.Path, false);
        using var a = await Open(s, "base");
        using var stream = (await s.OpenNamedStreamAsync("base", "alt", FileAccessIntent.ReadWrite, CreateDispositionIntent.OpenIf)).Value.Handle;
        var index = stream.GetInfo().IndexNumber;
        Check.Equal(NtStatus.Success, await s.RenameAsync(a, "new-base", false), "stream base rename");
        Check.Equal(index, stream.GetInfo().IndexNumber, "stream index independent of renamed pathname");
    }
    static async Task Resources()
    {
        using var r = new P2Tests.Root(); var s = new LocalFileStore(r.Path, false);
        using (var warm = await Open(s, "warm")) { _ = warm.GetInfo(); }
        var before = NativeHost.HandleCount();
        for (var i = 0; i < 150; i++)
        {
            using var f = await Open(s, "file"); using var d = await Open(s, "dir", true); _ = f.GetInfo(); _ = d.GetInfo();
            var fail = await s.CreateAsync("missing/child", FileAccessIntent.Read, CreateDispositionIntent.Open, false, true);
            Check.That(!fail.IsSuccess, "failed open fixture");
        }
        Check.That(NativeHost.HandleCount() <= before + 4, "native handles released without finalizer dependency");
    }
    static Task Volume()
    {
        using var r = new P2Tests.Root(); var s = new LocalFileStore(r.Path, false);
        var info = s.GetVolumeInfo();
        Check.That(info.TotalBytes > 0 && info.AvailableBytes >= 0 && info.AvailableBytes <= info.TotalBytes, "actual host volume capacity at drive or UNC test root");
        return Task.CompletedTask;
    }
    static Task BuildOutput()
    {
        using var writer = new StringWriter(); BuildIdentity.Print(writer);
        var lines = writer.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Check.Equal(7, lines.Length, "runtime plus six maintained assembly identities");
        foreach (var line in lines.Skip(1))
        {
            Check.That(line.Contains(" | mvid=") && line.Contains(" | location=") && line.Contains(" | sha256="), "complete output identity fields");
            if (System.Runtime.CompilerServices.RuntimeFeature.IsDynamicCodeSupported)
                Check.Equal(64, line.Trim().Split(" | sha256=")[1].Length, "rebuilt JIT output SHA-256");
            else Check.That(line.Contains("<linked into native executable>"), "AOT linked identity");
        }
        return Task.CompletedTask;
    }
}
