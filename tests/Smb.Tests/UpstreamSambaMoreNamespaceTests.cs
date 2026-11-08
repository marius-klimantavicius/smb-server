using System.Text;
using Smb.Testing;

internal static partial class UpstreamSambaMoreTests
{
    static IEnumerable<(string Name, Func<Task> Run)> NamespaceCases()
    {
        foreach (var directory in new[] { false, true })
        {
            yield return ($"upstream.samba.more.create.concurrent-exclusive.{directory}", () => ConcurrentCreate(directory));
            yield return ($"upstream.samba.more.identity.enumeration-rename.{directory}", () => IdentityEnumeration(directory));
            yield return ($"upstream.samba.more.identity.distinct-objects.{directory}", () => DistinctIds(directory));
        }
        foreach (var recursive in new[] { false, true })
            foreach (var directory in new[] { false, true })
                yield return ($"upstream.samba.more.notify.native-subtree.{recursive}.{directory}", () => NotifySubtree(recursive, directory));
        yield return ("upstream.samba.more.notify.renamed-base", NotifyRenamedBase);
        yield return ("upstream.samba.more.directory.rename-1024", Rename1024);
        foreach (var size in new ulong[] { 1, 4096, 1048576 })
            yield return ($"upstream.samba.more.create.directory-allocation.{size}", () => DirectoryAllocation(size));
        yield return ("upstream.samba.more.create.readonly-delete-open", ReadonlyDeleteOpen);
        foreach (var directory in new[] { false, true }) yield return ($"upstream.samba.more.identity.mutation-stream-lifetime.{directory}", () => IdentityMutation(directory));
    }
    static async Task ConcurrentCreate(bool directory)
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); var clients = new List<WireClient>();
        try
        {
            for (var i = 0; i < 3; i++) clients.Add(await h.ConnectAsync());
            var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var requests = clients.Select(async c =>
            {
                var b = RawSmb.Create("same", directory, c.NextMessageId(), c.Session, c.Tree); RawSmb.Put32(b, 100, 2);
                await gate.Task; await c.SendAsync(b); return await c.ReceiveAsync();
            }).ToArray(); gate.SetResult(); var responses = await Task.WhenAll(requests);
            Check.Equal(1, responses.Count(b => RawSmb.U32(b, 8) == Ok), "exactly one FILE_CREATE winner");
            Check.Equal(2, responses.Count(b => RawSmb.U32(b, 8) == Collision), "two competing CREATE collisions");
            for (var i = 0; i < responses.Length; i++) if (RawSmb.U32(responses[i], 8) == Ok) await clients[i].CloseAsync(Id(responses[i]));
        }
        finally { foreach (var c in clients) await c.DisposeAsync(); }
    }
    static async Task IdentityEnumeration(bool directory)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var parent = await Open(d, "", directory: true);
        var first = await Open(d, "object", 3, directory: directory); var peer = await Open(d, "object", directory: directory);
        var index = RawSmb.U64(Output(await d.Send(Query(first, 6))), 0); Check.That(index != 0, "nonzero file index");
        Check.Equal(index, RawSmb.U64(Output(await d.Send(Query(peer, 6))), 0), "independent opens same object index");
        async Task CheckEntry(string name)
        {
            var bytes = Output(await d.Send(Enum(parent, name, 1, 37)));
            Check.Equal(0u, RawSmb.U32(bytes, 0), "one matching ID_BOTH_DIRECTORY_INFORMATION record");
            Check.Equal(name, Encoding.Unicode.GetString(bytes, 104, (int)RawSmb.U32(bytes, 60)), "exact enumeration name");
            Check.Equal(index, RawSmb.U64(bytes, 96), "enumeration ID equals FileInternalInformation");
        }
        await CheckEntry("object"); Status(await d.Send(Rename(first, "renamed")), Ok, "rename file/directory with peer");
        Check.Equal(index, RawSmb.U64(Output(await d.Send(Query(peer, 6))), 0), "peer retains object index through rename"); await CheckEntry("renamed");
        await Close(d, first); await Close(d, peer); var reopened = await Open(d, "renamed", directory: directory);
        Check.Equal(index, RawSmb.U64(Output(await d.Send(Query(reopened, 6))), 0), "identity persists across last-close/reopen");
    }
    static async Task DistinctIds(bool directory)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var ids = new HashSet<ulong>();
        // Bounded independent objects: uniqueness is an opaque identity property,
        // not a requirement that a private counter is contiguous or monotonic.
        for (var i = 0; i < 64; i++)
        {
            var id = await Open(d, $"object{i}", 2, directory: directory); var index = RawSmb.U64(Output(await d.Send(Query(id, 6))), 0);
            Check.That(index != 0 && ids.Add(index), "distinct simultaneously existing objects have distinct file indices"); await Close(d, id);
        }
    }
    static byte[] Route(byte[] request, WireClient c)
    { RawSmb.Put64(request, 24, c.NextMessageId()); RawSmb.Put64(request, 40, c.Session); RawSmb.Put32(request, 36, c.Tree); return request; }
    static async Task NotifySubtree(bool recursive, bool directory)
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); Directory.CreateDirectory(h.PathFor("scan/nested"));
        await using var watcher = await h.ConnectAsync(); await using var writer = await h.ConnectAsync(); var id = await watcher.CreateAsync("scan", true);
        await watcher.ExchangeAsync(Route(Notify(id, filter: directory ? 2u : 1u, recursive: recursive), watcher), 0x103);
        var b = RawSmb.Create("scan\\nested\\deep", directory, writer.NextMessageId(), writer.Session, writer.Tree); RawSmb.Put32(b, 100, 2); var nested = await writer.ExchangeAsync(b); await writer.CloseAsync(Id(nested));
        if (!recursive)
        {
            b = RawSmb.Create("scan\\immediate", directory, writer.NextMessageId(), writer.Session, writer.Tree); RawSmb.Put32(b, 100, 2); var immediate = await writer.ExchangeAsync(b); await writer.CloseAsync(Id(immediate));
        }
        var response = await watcher.ReceiveAsync(); Status(response, Ok, "native subtree notification"); var data = Output(response);
        Check.Equal(1u, RawSmb.U32(data, 4), "CREATE produces FILE_ACTION_ADDED");
        Check.Equal(recursive ? "nested\\deep" : "immediate", Encoding.Unicode.GetString(data, 12, (int)RawSmb.U32(data, 8)), "WATCH_TREE controls relative descendant names");
        await watcher.CloseAsync(id);
    }
    static async Task NotifyRenamedBase()
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); Directory.CreateDirectory(h.PathFor("old"));
        await using var watcher = await h.ConnectAsync(); await using var writer = await h.ConnectAsync(); var id = await watcher.CreateAsync("old", true);
        var open = RawSmb.Create("old", true, writer.NextMessageId(), writer.Session, writer.Tree); RawSmb.Put32(open, 88, All); var owner = Id(await writer.ExchangeAsync(open));
        await writer.ExchangeAsync(Route(Rename(owner, "new"), writer));
        await watcher.ExchangeAsync(Route(Notify(id), watcher), 0x103);
        var b = RawSmb.Create("new\\child", false, writer.NextMessageId(), writer.Session, writer.Tree); RawSmb.Put32(b, 100, 2); var child = Id(await writer.ExchangeAsync(b));
        var data = Output(await watcher.ReceiveAsync()); Check.Equal("child", Encoding.Unicode.GetString(data, 12, (int)RawSmb.U32(data, 8)), "watch by renamed live directory identity");
        await writer.CloseAsync(child); await writer.CloseAsync(owner); await watcher.CloseAsync(id);
    }
    static async Task Rename1024()
    {
        using var root = new P7cTests.Root(); Directory.CreateDirectory(Path.Combine(root.Path, "scan"));
        for (var i = 0; i < 1024; i++) File.WriteAllBytes(Path.Combine(root.Path, "scan", $"t{i:0000}.txt"), []);
        await using var d = new P2Tests.Direct(root.Store());
        for (var i = 0; i < 1024; i++)
        {
            var id = await Open(d, $"scan\\t{i:0000}.txt"); Status(await d.Send(Rename(id, $"scan\\r{i:0000}.txt")), Ok, "bounded full directory rename traversal"); await Close(d, id);
        }
        var dir = await Open(d, "scan", directory: true); var names = new HashSet<string>(StringComparer.Ordinal);
        for (var page = 0; page < 200; page++)
        {
            var response = await d.Send(Enum(dir, page == 0 ? "*" : "", page == 0 ? (byte)1 : (byte)0));
            if (RawSmb.U32(response, 8) == 0x80000006) break;
            var data = Output(response); var at = 0;
            while (true)
            {
                var name = Encoding.Unicode.GetString(data, at + 12, (int)RawSmb.U32(data, at + 8));
                if (name is not "." and not "..") Check.That(names.Add(name), "no duplicate renamed enumeration entry"); var next = RawSmb.U32(data, at); if (next == 0) break; at += (int)next;
            }
        }
        Check.That(names.SetEquals(Enumerable.Range(0, 1024).Select(i => $"r{i:0000}.txt")), "exact final 1024 renamed namespace");
    }
    static async Task DirectoryAllocation(ulong size)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var data = new byte[8]; RawSmb.Put64(data, 0, size);
        var response = await d.Send(P7cTests.Context(Create("dir", 3, directory: true), "AlSi", data)); var id = Id(response);
        Check.Equal(0ul, RawSmb.U64(response, 104), "directory ignores initial allocation size");
        Check.Equal(0ul, RawSmb.U64(Output(await d.Send(Query(id, 5))), 8), "directory has no file EOF");
    }
    static async Task ReadonlyDeleteOpen()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var id = await Open(d, disposition: 3); await Write(d, id, Payload);
        var data = new byte[40]; RawSmb.Put32(data, 32, 1); Status(await d.Send(Set(id, 4, data)), Ok, "set readonly before DELETE open"); await Close(d, id);
        try
        {
            var delete = await Open(d, access: 0x10000); Status(await d.Send(Set(delete, 13, [1])), 0xc0000121, "readonly permits DELETE access acquisition but rejects disposition"); await Close(d, delete);
        }
        finally { File.SetAttributes(Path.Combine(root.Path, "file"), FileAttributes.Normal); }
    }
    static async Task IdentityMutation(bool directory)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var parent = await Open(d, "", directory: true); var baseId = await Open(d, "base", 3, directory: directory);
        var expected = RawSmb.U64(Output(await d.Send(Query(baseId, 6))), 0);
        async Task Identity((ulong P, ulong V) id)
        { Check.Equal(expected, RawSmb.U64(Output(await d.Send(Query(id, 6))), 0), "FileInternalInformation identity invariant"); Check.Equal(expected, RawSmb.U64(Output(await d.Send(Query(id, 18))), 64), "ALL_INFORMATION agrees with internal ID"); }
        await Identity(baseId); await Close(d, baseId); baseId = await Open(d, "base", directory: directory); await Identity(baseId);
        if (!directory) { await Close(d, baseId); baseId = await Open(d, "base", 4); await Identity(baseId); await Write(d, baseId, Payload); await Identity(baseId); }
        var time = new byte[40]; RawSmb.Put64(time, 16, (ulong)new DateTime(2020, 1, 2, 3, 4, 5, DateTimeKind.Utc).ToFileTimeUtc()); Status(await d.Send(Set(baseId, 4, time)), Ok, "base timestamp mutation"); await Identity(baseId);
        if (directory) Status(await d.Send(Create("base:stream", 2)), 0xc00000ba, "local backend does not provide named data streams on a directory");
        else
        {
            var stream = await Open(d, "base:stream", 2); await Identity(stream); await Write(d, stream, Payload); await Identity(stream); Status(await d.Send(Set(stream, 4, time)), Ok, "stream timestamp mutation"); await Identity(stream); await Close(d, stream);
            stream = await Open(d, "base:stream", 4); await Identity(stream); await Close(d, stream);
        }
        await Identity(baseId); await Close(d, baseId);
        baseId = await Open(d, "base", directory: directory); await Identity(baseId);
        var data = Output(await d.Send(Enum(parent, "base", cls: 37))); Check.Equal(expected, RawSmb.U64(data, 96), "ID_BOTH_DIRECTORY final index agrees after base and stream mutations");
    }
}
