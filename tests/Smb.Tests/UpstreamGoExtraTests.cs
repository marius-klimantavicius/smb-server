using System.Text;
using Smb.Testing;

internal static partial class UpstreamGoTests
{
    static IEnumerable<(string Name, Func<Task> Run)> ExtraCases()
    {
        yield return ("upstream.go.io.sequential-model", SequentialModel);
        yield return ("upstream.go.io.append-truncate-and-copy", Append);
        yield return ("upstream.go.io.buffered-copy-model", BufferedCopy);
        yield return ("upstream.go.names.mixed-separators-spaces", MixedPath);
        yield return ("upstream.go.concurrent.publish-rename-delete-visibility", Publish);
        yield return ("upstream.go.io.readonly-handle-denies-write", ReadOnlyHandle);
        yield return ("upstream.go.protocol.unknown-set-info", UnknownSet);
        yield return ("upstream.go.ioctl.response-buffer-offset-relation", IoctlOffsets);
        yield return ("upstream.go.names.open-if-existing-readonly", OpenIfReadonly);
        yield return ("upstream.go.metadata.create-directory-readonly", CreateReadonlyDirectory);
        yield return ("upstream.go.protocol.enumerate-regular-file", EnumerateRegularFile);
        foreach (var mode in new[] { "write-open", "new-file", "mkdir", "delete-on-close", "write", "rename", "delete", "truncate" })
        { var value = mode; yield return ($"upstream.go.readonly.{value}", () => ReadOnlyShare(value)); }
    }
    static async Task SequentialModel()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); await using var c = await f.ConnectAsync(); var id = await Open(c, "model");
        // The upstream's literal prefix, followed by a deterministic bounded model.
        // Seek itself is client-only; it selects offsets for subsequent SMB READ/WRITE.
        (string Op, int Offset, int Size)[] initial = [ ("seek",17,0),("write",0,7),("at",3,5),("read",20,8),("truncate",12,0),("truncate",48,0),("read",45,5),("seek",40,0),("write",0,9),("at",65536,0),("read",65536,0),("truncate",65536,0),("truncate",4,0),("at",65528,8),("read",65532,8),("truncate",0,0),("read",0,1),("write",0,3) ];
        var model = Array.Empty<byte>(); var position = 0;
        for (var step = 0; step < 50; step++)
        {
            var op = step < initial.Length ? initial[step] : (new[] { "write", "at", "read", "seek", "truncate" }[step % 5], (step * 7919) % 65537, (step * 113) % 1025);
            var (kind, offset, size) = op; if (kind == "write") offset = position;
            if (kind is "write" or "at")
            {
                size = Math.Min(size, 65536 - offset); var data = Pattern(size, step);
                // Zero-length API writes are client-only no-ops, not extra SMB WRITE claims.
                if (size != 0) { await Write(c, id, data, (ulong)offset); if (offset + size > model.Length) Array.Resize(ref model, offset + size); data.CopyTo(model, offset); }
                if (kind == "write") position += size;
            }
            else if (kind == "seek") position = offset;
            else if (kind == "truncate") { await Resize(c, id, (ulong)offset); Array.Resize(ref model, offset); }
            else if (size != 0)
            {
                if (offset >= model.Length) await c.ExchangeAsync(RawSmb.Read(id, (uint)size, (ulong)offset, c.NextMessageId(), c.Session, c.Tree), Eof, 9);
                else Bytes(model.AsSpan(offset, Math.Min(size, model.Length - offset)).ToArray(), await Read(c, id, size, (ulong)offset), "model ReadAt step " + step);
            }
            await AssertFile(c, id, model);
        }
        await c.CloseAsync(id);
    }
    static async Task Append()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); await using var c = await f.ConnectAsync();
        foreach (var truncate in new[] { false, true })
        {
            var id = await Open(c, "append"); await Write(c, id, "old"u8.ToArray()); await c.CloseAsync(id); id = await Open(c, "append", disposition: truncate ? 4u : 1u);
            foreach (var letter in new[] { "A", "B", "C" }) { var end = RawSmb.U64(await Query(c, id, 5), 8); await Write(c, id, Encoding.UTF8.GetBytes(letter), end); }
            await AssertFile(c, id, Encoding.UTF8.GetBytes(truncate ? "ABC" : "oldABC")); await c.CloseAsync(id); await Remove(c, "append");
        }
        var source = await Open(c, "source"); var payload = Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("copy", 1024))); await Write(c, source, payload);
        var destination = await Open(c, "destination"); await Write(c, destination, "prefix"u8.ToArray()); var content = await Read(c, source, payload.Length); var eof = RawSmb.U64(await Query(c, destination, 5), 8); await Write(c, destination, content, eof);
        await AssertFile(c, destination, "prefix"u8.ToArray().Concat(payload).ToArray()); await c.CloseAsync(destination); await c.CloseAsync(source);
    }
    static async Task BufferedCopy()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); await using var c = await f.ConnectAsync();
        foreach (var row in new[] { ("long-tail", 4097, 65536, new[] { (17, 101) }), ("source-eof", 4097, 8192, new[] { (4097, 37) }), ("reuse-after-seek", 65536, 65536, new[] { (65527, 17), (1027, 3) }) })
        {
            var source = Pattern(row.Item2, 7); var model = Pattern(row.Item3, 97); var src = await Open(c, row.Item1 + "-src"); var dst = await Open(c, row.Item1 + "-dst"); await Write(c, src, source); await Write(c, dst, model);
            foreach (var (from, to) in row.Item4)
            {
                if (from == source.Length) await c.ExchangeAsync(RawSmb.Read(src, 1, (ulong)from, c.NextMessageId(), c.Session, c.Tree), Eof, 9);
                else { var data = await Read(c, src, source.Length - from, (ulong)from); await Write(c, dst, data, (ulong)to); source.AsSpan(from).CopyTo(model.AsSpan(to)); }
                await AssertFile(c, dst, model);
            }
            await c.CloseAsync(src); await c.CloseAsync(dst);
        }
    }
    static async Task MixedPath()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); await using var c = await f.ConnectAsync();
        foreach (var dir in new[] { "dir with spaces", "dir with spaces/slashSub", "dir with spaces/slashSub\\日本語フォルダ" }) await c.CloseAsync(await Open(c, dir, true));
        var name = "dir with spaces/slashSub\\日本語フォルダ/テスト ファイル #1.txt"; var id = await Open(c, name); var data = Encoding.UTF8.GetBytes("ユニコードテスト"); await Write(c, id, data); await AssertFile(c, id, data); await c.CloseAsync(id);
        Check.That((await List(c, "dir with spaces\\slashSub/日本語フォルダ")).SequenceEqual(new[] { "テスト ファイル #1.txt" }), "mixed separator directory resolution");
    }
    static async Task Publish()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); await using var writer = await f.ConnectAsync(); await using var peer = await f.ConnectAsync();
        var id = await Open(writer, "temporary"); await Write(writer, id, "published"u8.ToArray()); await Rename(writer, id, "published"); await writer.CloseAsync(id);
        await peer.ExchangeAsync(Create(peer, "temporary", disposition: 1), 0xc0000034, 9); var reader = await Open(peer, "published", disposition: 1); await AssertFile(peer, reader, "published"u8.ToArray()); await peer.CloseAsync(reader);
        await Remove(writer, "published"); await peer.ExchangeAsync(Create(peer, "published", disposition: 1), 0xc0000034, 9);
    }
    static async Task ReadOnlyHandle()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); File.WriteAllBytes(f.PathFor("readonly"), "keep"u8.ToArray()); await using var c = await f.ConnectAsync(); var id = await Open(c, "readonly", disposition: 1, access: 0x81);
        await c.ExchangeAsync(RawSmb.Write(id, "fail"u8.ToArray(), 0, c.NextMessageId(), c.Session, c.Tree), 0xc0000022, 9); await AssertFile(c, id, "keep"u8.ToArray()); await c.CloseAsync(id);
    }
    static async Task UnknownSet()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); await using var c = await f.ConnectAsync(); var id = await Open(c, "unknown"); await Write(c, id, "keep"u8.ToArray());
        await c.ExchangeAsync(Set(c, id, 0xee, []), 0xc0000003, 9); await AssertFile(c, id, "keep"u8.ToArray()); await c.CloseAsync(id);
    }
    static async Task OpenIfReadonly()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); await using var c = await f.ConnectAsync(); var id = await Open(c, "existing-readonly"); await Write(c, id, "existing content"u8.ToArray());
        var data = new byte[40]; RawSmb.Put32(data, 32, 1); await c.ExchangeAsync(Set(c, id, 4, data), size: 2); await c.CloseAsync(id);
        try
        {
            var opened = await c.ExchangeAsync(Create(c, "existing-readonly", disposition: 3, access: 0x81), size: 89); var read = Id(opened);
            Check.Equal(1u, RawSmb.U32(opened, 68), "read-only OPEN_IF opens existing object"); await AssertFile(c, read, "existing content"u8.ToArray());
            Check.That((RawSmb.U32(await Query(c, read, 4), 32) & 1) != 0, "read-only OPEN_IF preserves existing attributes"); await c.CloseAsync(read);
        }
        finally { File.SetAttributes(f.PathFor("existing-readonly"), FileAttributes.Normal); }
    }
    static async Task EnumerateRegularFile()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); await using var c = await f.ConnectAsync(); var id = await Open(c, "regular"); await Write(c, id, "keep"u8.ToArray());
        await c.ExchangeAsync(RawSmb.Enumerate(id, c.NextMessageId(), c.Session, c.Tree), 0xc000000d, 9);
        await AssertFile(c, id, "keep"u8.ToArray()); await c.CloseAsync(id);
    }
    static async Task CreateReadonlyDirectory()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); await using var c = await f.ConnectAsync();
        var request = Create(c, "readonly-dir", true, 2); RawSmb.Put32(request, 92, 0x11);
        try
        {
            var opened = await c.ExchangeAsync(request, size: 89); var id = Id(opened); var created = RawSmb.U32(opened, 120); var basic = await Query(c, id, 4); var queried = RawSmb.U32(basic, 32);
            Check.That((created & 0x11) == 0x11 && (queried & 0x11) == 0x11, $"READONLY directory CREATE/query flags must retain DIRECTORY|READONLY; create=0x{created:x8}, query=0x{queried:x8}"); await c.CloseAsync(id);
        }
        finally { if (Directory.Exists(f.PathFor("readonly-dir"))) File.SetAttributes(f.PathFor("readonly-dir"), FileAttributes.Normal); }
    }
    static async Task IoctlOffsets()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); f.Server.State.Options.FeaturePolicy = Smb.Server.SmbFeaturePolicy.CopyOnly;
        await using var c = await f.ConnectAsync(); var id = await Open(c, "ioctl-layout");
        var b = RawSmb.Header(11, 57, c.NextMessageId(), c.Session, c.Tree); RawSmb.Put16(b, 64, 57); RawSmb.Put32(b, 68, 0x140078); RawSmb.Put64(b, 72, id.P); RawSmb.Put64(b, 80, id.V); RawSmb.Put32(b, 108, 32); RawSmb.Put32(b, 112, 1);
        var response = await c.ExchangeAsync(b, size: 49); var input = RawSmb.U32(response, 88); var count = RawSmb.U32(response, 92); var output = RawSmb.U32(response, 96);
        Check.Equal(32u, RawSmb.U32(response, 100), "resume key output size");
        Check.Equal(((ulong)input + count + 7) & ~7ul, (ulong)output, "MS-SMB2 2.2.32 output starts at aligned InputOffset+InputCount even when InputCount is zero");
        Check.Equal(0u, RawSmb.U32(response, 104), "IOCTL response flags reserved zero"); Check.Equal(id.P, RawSmb.U64(response, 72), "IOCTL persistent FileId"); Check.Equal(id.V, RawSmb.U64(response, 80), "IOCTL volatile FileId"); await c.CloseAsync(id);
    }
    static async Task ReadOnlyShare(string mode)
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); var root = f.PathFor("ro-root"); Directory.CreateDirectory(root); File.WriteAllBytes(Path.Combine(root, "f.txt"), "hello"u8.ToArray());
        f.Server.State.Options.Shares.Add(new Smb.FileSystem.Share { Name = "readonly", FileStore = new Smb.FileSystem.Local.LocalFileStore(root, true) }); await using var c = await f.ConnectAsync();
        var tree = await c.ExchangeAsync(RawSmb.TreeConnect("\\\\localhost\\readonly", c.NextMessageId(), c.Session), size: 16); var tid = RawSmb.U32(tree, 36);
        byte[] OnTree(byte[] b) { RawSmb.Put32(b, 36, tid); return b; }
        if (mode is "write-open" or "new-file" or "mkdir" or "delete-on-close")
        {
            var b = Create(c, mode == "new-file" ? "new.txt" : mode == "mkdir" ? "newdir" : "f.txt", mode == "mkdir", mode == "write-open" || mode == "delete-on-close" ? 1u : 3u, mode == "write-open" ? 3u : 0x81u);
            if (mode == "delete-on-close") { RawSmb.Put32(b, 88, 0x10081); RawSmb.Put32(b, 104, 0x1040); }
            await c.ExchangeAsync(OnTree(b), 0xc0000022, 9);
        }
        else
        {
            var opened = await c.ExchangeAsync(OnTree(Create(c, "f.txt", disposition: 1, access: 0x81)), size: 89); var id = Id(opened);
            var read = await c.ExchangeAsync(RawSmb.Read(id, 5, 0, c.NextMessageId(), c.Session, tid), size: 17); Bytes("hello"u8.ToArray(), RawSmb.Buffer(read, read[66], RawSmb.U32(read, 68)), "read-only share remains readable");
            byte[] mutation;
            if (mode == "write") mutation = RawSmb.Write(id, [120], 0, c.NextMessageId(), c.Session, tid);
            else if (mode == "truncate") mutation = Set(c, id, 20, new byte[8]);
            else if (mode == "delete") mutation = Set(c, id, 13, [1]);
            else { var text = Encoding.Unicode.GetBytes("moved.txt"); var data = new byte[20 + text.Length]; RawSmb.Put32(data, 16, (uint)text.Length); text.CopyTo(data, 20); mutation = Set(c, id, 10, data); }
            await c.ExchangeAsync(OnTree(mutation), 0xc0000022, 9); await c.ExchangeAsync(RawSmb.Close(id, c.NextMessageId(), c.Session, tid), size: 60);
        }
        Bytes("hello"u8.ToArray(), NativeHost.ReadAllBytes(Path.Combine(root, "f.txt")), "read-only rejection preserves data"); Check.Equal(1, Directory.GetFileSystemEntries(root).Length, "no mutation leaked");
    }
}
