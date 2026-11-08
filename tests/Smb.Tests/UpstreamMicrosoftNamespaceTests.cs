using System.Text;
using Smb.Testing;

internal static partial class UpstreamMicrosoftTests
{
    static IEnumerable<(string Name, Func<Task> Run)> NamespaceCases()
    {
        foreach (var directory in new[] { false, true })
            foreach (var dot in new[] { false, true })
                yield return ($"upstream.microsoft.path.dot-{directory}-{dot}", () => DotPath(directory, dot));
        yield return ("upstream.microsoft.path.directory-trailing-backslash", TrailingDirectory);
        yield return ("upstream.microsoft.path.file-trailing-backslash", TrailingFile);
        yield return ("upstream.microsoft.path.missing-double-backslash-parent", DoubleBackslash);
        foreach (var directory in new[] { false, true })
            yield return ($"upstream.microsoft.path.trailing-colon-{directory}", () => Colon(directory));
        foreach (var shape in new[] { "zero", "odd", "greater" })
            yield return ("upstream.microsoft.rename.invalid-length-" + shape, () => RenameLength(shape));
        yield return ("upstream.microsoft.delete.readonly", DeleteReadonly);
        yield return ("upstream.microsoft.delete.readonly-after-open", DeleteReadonlyAfterOpen);
        yield return ("upstream.microsoft.create.invalid-share-mask", InvalidShare);
        yield return ("upstream.microsoft.query.directory-on-file", DirectoryOnFile);
        yield return ("upstream.microsoft.set.ea-query-only-class", SetEaQueryClass);
        foreach (var count in new[] { 0, 1, 2 })
            yield return ($"upstream.microsoft.directory.nested-{count}", () => NestedDirectories(count));
        foreach (var kind in new[] { "file-name", "directory-name", "attributes", "size", "last-write", "last-access" })
            yield return ("upstream.microsoft.notify.native-" + kind, () => NativeNotify(kind));
    }
    static async Task DotPath(bool directory, bool doubleDot)
    {
        using var root = new Root(); Directory.CreateDirectory(root.At("parent")); Directory.CreateDirectory(root.At("parent", "child"));
        if (directory) Directory.CreateDirectory(root.At("parent", "target")); else File.WriteAllBytes(root.At("parent", "target"), [42]);
        await using var d = root.Direct(); var path = doubleDot ? "parent\\child\\..\\target" : "parent\\.\\target";
        var id = await Open(d, path, directory); if (!directory) await ReadEquals(d, id, [42]);
        Check.Equal((byte)(directory ? 1 : 0), Output(await Query(d, id, 5, 24))[21], "dot-normalized file type");
    }
    static async Task TrailingDirectory()
    {
        using var root = new Root(); await using var d = root.Direct(); var b = RawSmb.Create("newdir\\", true, 0, 1, 42); RawSmb.Put32(b, 100, 2);
        Status(await d.Send(b), 0, "directory CREATE permits trailing separator"); Check.That(Directory.Exists(root.At("newdir")), "corresponding directory exists");
    }
    static async Task TrailingFile()
    {
        using var root = new Root(); await using var d = root.Direct();
        Status(await d.Send(RawSmb.Create("newfile\\", false, 0, 1, 42)), 0xc0000033, "NON_DIRECTORY_FILE with trailing separator is invalid");
        Check.That(!File.Exists(root.At("newfile")), "invalid trailing separator cannot create file");
    }
    static async Task DoubleBackslash()
    {
        using var root = new Root(); await using var d = root.Direct();
        Status(await d.Send(RawSmb.Create("missing\\\\file", false, 0, 1, 42)), 0xc000003a, "double separator cannot create missing parent");
    }
    static async Task Colon(bool directory)
    {
        using var root = new Root(); await using var d = root.Direct(); var b = RawSmb.Create("invalid:", directory, 0, 1, 42); RawSmb.Put32(b, 100, 2);
        Status(await d.Send(b), 0xc0000033, "trailing colon is invalid in ordinary pathname component");
    }
    static async Task RenameLength(string shape)
    {
        using var root = new Root(); File.WriteAllBytes(root.At("source"), [7, 8]); await using var d = root.Direct(); var id = await Open(d, "source");
        var data = new byte[24]; RawSmb.Put32(data, 16, shape == "zero" ? 0u : shape == "odd" ? 1u : 40u); data[20] = (byte)'b';
        Status(await d.Send(Set(id, 10, data)), Invalid, "rename FileNameLength zero/odd/outside input is invalid");
        await ReadEquals(d, id, [7, 8]); Check.That(File.Exists(root.At("source")), "failed rename leaves source name");
        var name = Encoding.Unicode.GetBytes("target"); data = new byte[20 + name.Length]; RawSmb.Put32(data, 16, (uint)name.Length); name.CopyTo(data, 20);
        Status(await d.Send(Set(id, 10, data)), 0, "valid rename retry"); await ReadEquals(d, id, [7, 8]);
        Check.That(File.Exists(root.At("target")) && !File.Exists(root.At("source")), "retry moves only intended name");
    }
    static async Task DeleteReadonly()
    {
        using var root = new Root(); File.WriteAllBytes(root.At("data"), [42]); File.SetAttributes(root.At("data"), FileAttributes.ReadOnly);
        try
        {
            await using var d = root.Direct(); var id = await Open(d, "data", access: 0x10081);
            Status(await d.Send(Set(id, 13, [1])), 0xc0000121, "read-only file disposition returns CANNOT_DELETE");
            Check.That(File.Exists(root.At("data")), "denied deletion preserves file");
        }
        finally { if (File.Exists(root.At("data"))) File.SetAttributes(root.At("data"), FileAttributes.Normal); }
    }
    static async Task DeleteReadonlyAfterOpen()
    {
        using var root = new Root(); await using var d = root.Direct(); var id = await Open(d, "data");
        var basic = new byte[40]; RawSmb.Put32(basic, 32, 1); Status(await d.Send(Set(id, 4, basic)), 0, "set READONLY on existing open");
        try { Status(await d.Send(Set(id, 13, [1])), 0xc0000121, "READONLY disposition after grant returns CANNOT_DELETE"); }
        finally { if (File.Exists(root.At("data"))) File.SetAttributes(root.At("data"), FileAttributes.Normal); }
    }
    static async Task InvalidShare()
    {
        using var root = new Root(); await using var d = root.Direct(); var create = RawSmb.Create("invalid", false, 0, 1, 42); RawSmb.Put32(create, 96, 8);
        Status(await d.Send(create), Invalid, "reserved ShareAccess bit from CreateFileTestCaseS4");
        Check.That(!File.Exists(root.At("invalid")), "invalid sharing mask rejected before creation");
    }
    static async Task DirectoryOnFile()
    {
        using var root = new Root(); await using var d = root.Direct(); var id = await Open(d, "data");
        Status(await d.Send(Enum(id, 12, "*", 16, 4096)), Invalid, "QUERY_DIRECTORY REOPEN on ordinary file");
    }
    static async Task SetEaQueryClass()
    {
        using var root = new Root(); await using var d = root.Direct(); var id = await Open(d, "data");
        Status(await d.Send(Set(id, 7, [0, 4, 0, 0])), 0xc0000003, "FileEaInformation is a query-only class");
    }
    static async Task NestedDirectories(int count)
    {
        using var root = new Root(); Directory.CreateDirectory(root.At("scan"));
        if (count >= 1) File.WriteAllBytes(root.At("scan", "file"), [42]);
        if (count == 2) { Directory.CreateDirectory(root.At("scan", "child")); File.WriteAllBytes(root.At("scan", "child", "nested"), [7]); }
        await using var d = root.Direct(); var id = await Open(d, "scan", true); var expected = new List<string> { ".", ".." };
        if (count >= 1) expected.Add("file"); if (count == 2) expected.Add("child");
        Names(expected, await Scan(d, id, 3, "*", 1), "ordinary directory listing includes only immediate children");
        if (count == 2) { var child = await Open(d, "scan\\child", true); Names([".", "..", "nested"], await Scan(d, child, 3, "*", 1), "independent child listing"); }
    }
    static async Task NativeNotify(string kind)
    {
        await using var host = await UpstreamLocalFixture.StartAsync(); Directory.CreateDirectory(host.PathFor("scan"));
        File.WriteAllBytes(host.PathFor("scan/data"), [42]);
        await using var watcher = await host.ConnectAsync(); await using var mutator = await host.ConnectAsync();
        var directory = await watcher.CreateAsync("scan", true);
        var open = RawSmb.Create("scan\\data", false, mutator.NextMessageId(), mutator.Session, mutator.Tree); RawSmb.Put32(open, 88, 0x10183);
        var opened = await mutator.ExchangeAsync(open); var file = (RawSmb.U64(opened, 128), RawSmb.U64(opened, 136));
        var filter = kind switch { "file-name" => 1u, "directory-name" => 2u, "attributes" => 4u, "size" => 8u, "last-write" => 16u, _ => 32u };
        var notify = P4Tests.Notify(directory, filter); RawSmb.Put64(notify, 24, watcher.NextMessageId()); RawSmb.Put64(notify, 40, watcher.Session); RawSmb.Put32(notify, 36, watcher.Tree);
        await watcher.ExchangeAsync(notify, 0x103);
        try
        {
            if (kind == "file-name")
            {
                var name = Encoding.Unicode.GetBytes("scan\\renamed"); var data = new byte[20 + name.Length]; RawSmb.Put32(data, 16, (uint)name.Length); name.CopyTo(data, 20);
                await mutator.ExchangeAsync(Route(Set(file, 10, data), mutator));
            }
            else if (kind == "directory-name")
            {
                var request = RawSmb.Create("scan\\child", true, mutator.NextMessageId(), mutator.Session, mutator.Tree); RawSmb.Put32(request, 100, 2);
                var created = await mutator.ExchangeAsync(request); await mutator.CloseAsync((RawSmb.U64(created, 128), RawSmb.U64(created, 136)));
            }
            else if (kind is "size" or "last-write") await mutator.WriteAsync(file, [7, 8, 9]);
            else
            {
                var data = new byte[40]; if (kind == "attributes") RawSmb.Put32(data, 32, 1);
                else RawSmb.Put64(data, 8, (ulong)new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc).ToFileTimeUtc());
                await mutator.ExchangeAsync(Route(Set(file, 4, data), mutator));
            }
            var final = await watcher.ReceiveAsync(); Status(final, 0, "native watcher completes matching public mutation");
            Check.Equal((ushort)15, RawSmb.U16(final, 12), "CHANGE_NOTIFY final command"); var dataOut = Output(final);
            Check.That(dataOut.Length >= 12 && RawSmb.U32(dataOut, 4) is >= 1 and <= 5, "native event has valid FILE_NOTIFY_INFORMATION action");
            var nameLength = RawSmb.U32(dataOut, 8); Check.That((nameLength & 1) == 0 && 12ul + nameLength <= (ulong)dataOut.Length, "native event UTF16 bounded");
            var nameOut = Encoding.Unicode.GetString(dataOut, 12, (int)nameLength);
            Check.That(kind == "directory-name" ? nameOut == "child" : nameOut is "data" or "renamed", "native event names actual mutated child");
        }
        finally
        {
            if (File.Exists(host.PathFor("scan/data"))) File.SetAttributes(host.PathFor("scan/data"), FileAttributes.Normal);
        }
        await watcher.CloseAsync(directory); await mutator.CloseAsync(file);
    }
    static byte[] Route(byte[] request, WireClient client)
    {
        RawSmb.Put64(request, 24, client.NextMessageId()); RawSmb.Put64(request, 40, client.Session); RawSmb.Put32(request, 36, client.Tree); return request;
    }
}
