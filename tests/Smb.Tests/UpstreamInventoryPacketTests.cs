using Smb.Testing;

internal static partial class UpstreamInventoryTests
{
    static IEnumerable<(string Name, Func<Task> Run)> PacketCases()
    {
        foreach (var kind in new[] { "tree", "create", "read", "write", "ioctl", "query", "set", "directory" })
            yield return ("upstream.inventory.bounds.truncated-fixed-" + kind, () => TruncatedFixed(kind));
        foreach (var flags in new uint[] { 0, 5, 16 })
            yield return ($"upstream.inventory.lock.invalid-flags-{flags}", () => InvalidLockFlags(flags));
        foreach (var form in new[] { 0, 1, 2 })
            yield return ($"upstream.inventory.names.escape-{form}", () => PathEscape(form));
        yield return ("upstream.inventory.query.volume-two-bytes-short", VolumeShort);
    }
    static async Task InvalidLockFlags(uint flags)
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); await using var c = await h.ConnectAsync(); var a = await c.CreateAsync("data"); var peer = await c.CreateAsync("data");
        await c.ExchangeAsync(Lock(c, a, (100, 20, 18)), size: 4);
        await c.ExchangeAsync(Lock(c, a, (100, 20, flags)), Invalid);
        await c.ExchangeAsync(Lock(c, peer, (100, 20, 18)), NotGranted);
        await c.ExchangeAsync(Lock(c, a, (100, 20, 4)), size: 4); await c.ExchangeAsync(Lock(c, peer, (100, 20, 18)), size: 4);
        await c.CloseAsync(peer); await c.CloseAsync(a);
    }
    static async Task TruncatedFixed(string kind)
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); await using var c = await h.ConnectAsync(); var id = await MetadataOpen(c, false); await c.WriteAsync(id, [42]); var dir = await MetadataOpen(c, true, "scan");
        for (var size = 0; size < (kind switch { "tree" => 8, "create" => 56, "read" or "write" => 48, "ioctl" => 56, "query" => 40, _ => 32 }); size++)
        {
            var b = kind switch
            {
                "tree" => RawSmb.TreeConnect("\\\\localhost\\P0", c.NextMessageId(), c.Session),
                "create" => RawSmb.Create("bad", false, c.NextMessageId(), c.Session, c.Tree),
                "read" => RawSmb.Read(id, 1, 0, c.NextMessageId(), c.Session, c.Tree),
                "write" => RawSmb.Write(id, [1], 0, c.NextMessageId(), c.Session, c.Tree),
                "ioctl" => P5Tests.Ioctl(id, 0x00140078, [], 24),
                "query" => Query(c, id, 4),
                "set" => Set(c, id, 20, new byte[8]),
                _ => RawSmb.Enumerate(dir, c.NextMessageId(), c.Session, c.Tree)
            };
            if (kind == "ioctl") { RawSmb.Put64(b, 24, c.NextMessageId()); RawSmb.Put64(b, 40, c.Session); RawSmb.Put32(b, 36, c.Tree); }
            Array.Resize(ref b, 64 + size); await c.ExchangeAsync(b, Invalid);
        }
        Check.That((await c.ReadAsync(id, 1)).SequenceEqual(new byte[] { 42 }), "every truncated fixed request leaves data/session usable");
        Check.That(!File.Exists(h.PathFor("bad")), "truncated CREATE cannot materialize a file"); await c.CloseAsync(dir); await c.CloseAsync(id);
    }
    static async Task PathEscape(int form)
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); var name = "smb-inventory-outside-" + Guid.NewGuid().ToString("N");
        var outside = Path.Combine(Path.GetDirectoryName(h.RootPath)!, name); File.WriteAllBytes(outside, [42]);
        try
        {
            await using var c = await h.ConnectAsync(); var path = form switch { 0 => "..\\" + name, 1 => "foo\\..\\..\\" + name, _ => "\\..\\" + name };
            await c.SendAsync(RawSmb.Create(path, false, c.NextMessageId(), c.Session, c.Tree)); var response = await c.ReceiveAsync();
            Check.That((RawSmb.U32(response, 8) & 0xc0000000) == 0xc0000000, "source requires error for traversal outside the share");
            Check.That(File.ReadAllBytes(outside).SequenceEqual(new byte[] { 42 }), "outside bytes preserved"); Check.Equal(0, Directory.GetFileSystemEntries(h.RootPath).Length, "no escape-name artifact in share");
        }
        finally { File.Delete(outside); }
    }
    static async Task VolumeShort()
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); await using var c = await h.ConnectAsync(); var id = await c.CreateAsync("data");
        byte[] Request(uint length) { var b = Query(c, id, 1, length); b[66] = 2; return b; }
        var full = await c.ExchangeAsync(Request(4096)); var data = Output(full); Check.That(data.Length >= 20, "volume fixed fields and label");
        var tight = (uint)data.Length - 2; var shortResponse = await c.ExchangeAsync(Request(tight), 0x80000005);
        Check.Equal(tight, RawSmb.U32(shortResponse, 68), "exact volume response two bytes short clamps count");
        Check.That(Output(shortResponse).AsSpan().SequenceEqual(data.AsSpan(0, (int)tight)), "overflow retains exact available prefix"); await c.CloseAsync(id);
    }
}
