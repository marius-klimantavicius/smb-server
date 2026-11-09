using System.Security.Cryptography;
using System.Text;
using Smb.Testing;

// Protocol adaptations only. Pinned sources, per-symbol dispositions and host
// qualifications live in docs/correctness/upstream-go-tests.md.
internal static partial class UpstreamGoTests
{
    const uint Eof = 0xc0000011, NoMore = 0x80000006;
    public static IEnumerable<(string Name, Func<Task> Run)> Cases()
    {
        yield return ("upstream.go.io.sequential-truncate", Sequential);
        yield return ("upstream.go.io.mutate-append-shrink-grow-hole", Mutate);
        yield return ("upstream.go.io.random-access-64mib", RandomAccess);
        yield return ("upstream.go.io.large-stream-256mib", LargeStream);
        yield return ("upstream.go.io.sparse-4-5gib", Sparse);
        yield return ("upstream.go.io.positioned-concurrent", Positioned);
        yield return ("upstream.go.io.truncate-peer-live-eof", PeerResize);
        yield return ("upstream.go.io.truncate-invalid-preserves", InvalidResize);
        yield return ("upstream.go.names.unicode-punctuation-long", SpecialNames);
        yield return ("upstream.go.names.deep-tree-22", DeepTree);
        yield return ("upstream.go.names.case-only-rename", CaseRename);
        yield return ("upstream.go.names.directory-rename-live-child", DirectoryRename);
        yield return ("upstream.go.names.cross-directory-move", CrossDirectory);
        yield return ("upstream.go.names.remove-tree-postorder", RemoveTree);
        yield return ("upstream.go.enum.create-list-delete-1000", ManySmall);
        yield return ("upstream.go.enum.5000-and-300-lookups", BigFolder);
        yield return ("upstream.go.enum.parallel-50", ParallelListings);
        yield return ("upstream.go.enum.churn-300", Churn);
        foreach (var cls in new byte[] { 1, 2, 3, 37, 38 })
        { var value = cls; yield return ($"upstream.go.enum.layout-{value}", () => DirectoryLayout(value)); }
        yield return ("upstream.go.metadata.network-open-live", NetworkOpen);
        yield return ("upstream.go.metadata.chtimes", Times);
        yield return ("upstream.go.metadata.chmod-readonly", Attributes);
        yield return ("upstream.go.metadata.file-id-survives-rename", FileIdentity);
        yield return ("upstream.go.concurrent.readers-8", ConcurrentReaders);
        yield return ("upstream.go.concurrent.writers-8", ConcurrentWriters);
        yield return ("upstream.go.concurrent.sessions-50", Sessions);
        yield return ("upstream.go.disconnect.partial-transfer-recovery", Disconnect);
        yield return ("upstream.go.routing.share-isolation", Shares);
        foreach (var flag in new ushort[] { 0, 1 })
        { var value = flag; yield return ($"upstream.go.close.postquery-{value}", () => CloseAttributes(value)); }
        yield return ("upstream.go.io.copy-offsets-and-tail", CopyOffsets);
        foreach (var item in ExtraCases()) yield return item;
        foreach (var item in UpstreamGoAuthTests.Cases()) yield return item;
    }

    static byte[] Pattern(int count, int salt = 0) => Enumerable.Range(0, count).Select(i => (byte)(i * 7 + (i >> 12) + salt)).ToArray();
    static byte[] Create(WireClient c, string name, bool directory = false, uint disposition = 3, uint access = 0x10183)
    {
        var b = RawSmb.Create(name, directory, c.NextMessageId(), c.Session, c.Tree);
        RawSmb.Put32(b, 88, access); RawSmb.Put32(b, 100, disposition); return b;
    }
    static (ulong P, ulong V) Id(byte[] b) => (RawSmb.U64(b, 128), RawSmb.U64(b, 136));
    static async Task<(ulong P, ulong V)> Open(WireClient c, string name, bool directory = false, uint disposition = 3, uint access = 0x10183)
        => Id(await c.ExchangeAsync(Create(c, name, directory, disposition, access), size: 89));
    static async Task Write(WireClient c, (ulong P, ulong V) id, byte[] data, ulong offset = 0)
    {
        // <=64KiB requests also exercise SMB2.0.2 without fabricated credit state.
        for (var at = 0; at < data.Length; at += 61440)
        {
            var chunk = data.AsSpan(at, Math.Min(61440, data.Length - at)).ToArray();
            var b = await c.ExchangeAsync(RawSmb.Write(id, chunk, offset + (ulong)at, c.NextMessageId(), c.Session, c.Tree), size: 17);
            Check.Equal((uint)chunk.Length, RawSmb.U32(b, 68), "exact WRITE count");
        }
    }
    static async Task<byte[]> Read(WireClient c, (ulong P, ulong V) id, int count, ulong offset = 0)
    {
        using var result = new MemoryStream();
        while (result.Length < count)
        {
            var n = Math.Min(61440, count - (int)result.Length);
            var b = await c.ExchangeAsync(RawSmb.Read(id, (uint)n, offset + (ulong)result.Length, c.NextMessageId(), c.Session, c.Tree), size: 17);
            var data = RawSmb.Buffer(b, b[66], RawSmb.U32(b, 68));
            Check.That(data.Length > 0 && data.Length <= n, "READ progresses within requested bounds");
            result.Write(data); if (data.Length < n) break;
        }
        return result.ToArray();
    }
    static void Bytes(byte[] expected, byte[] actual, string why) => Check.That(expected.AsSpan().SequenceEqual(actual), why);
    static byte[] Set(WireClient c, (ulong P, ulong V) id, byte cls, byte[] data)
    {
        var b = RawSmb.Header(17, 32 + data.Length, c.NextMessageId(), c.Session, c.Tree);
        RawSmb.Put16(b, 64, 33); b[66] = 1; b[67] = cls; RawSmb.Put32(b, 68, (uint)data.Length); RawSmb.Put16(b, 72, 96);
        RawSmb.Put64(b, 80, id.P); RawSmb.Put64(b, 88, id.V); data.CopyTo(b, 96); return b;
    }
    static async Task Resize(WireClient c, (ulong P, ulong V) id, ulong length)
    { var data = new byte[8]; RawSmb.Put64(data, 0, length); await c.ExchangeAsync(Set(c, id, 20, data), size: 2); }
    static async Task<byte[]> Query(WireClient c, (ulong P, ulong V) id, byte cls, byte type = 1, uint size = 4096)
    {
        var b = RawSmb.Header(16, 40, c.NextMessageId(), c.Session, c.Tree); RawSmb.Put16(b, 64, 41);
        b[66] = type; b[67] = cls; RawSmb.Put32(b, 68, size); RawSmb.Put64(b, 88, id.P); RawSmb.Put64(b, 96, id.V);
        b = await c.ExchangeAsync(b, size: 9); return RawSmb.Buffer(b, RawSmb.U16(b, 66), RawSmb.U32(b, 68));
    }
    static async Task Rename(WireClient c, (ulong P, ulong V) id, string name, bool replace = false)
    {
        var text = Encoding.Unicode.GetBytes(name); var data = new byte[Math.Max(24, 20 + text.Length)];
        data[0] = (byte)(replace ? 1 : 0); RawSmb.Put32(data, 16, (uint)text.Length); text.CopyTo(data, 20);
        await c.ExchangeAsync(Set(c, id, 10, data), size: 2);
    }
    static async Task Remove(WireClient c, string name, bool directory = false)
    {
        var id = await Open(c, name, directory, 1);
        await c.ExchangeAsync(Set(c, id, 13, [1]), size: 2); await c.CloseAsync(id);
    }
    static async Task<List<string>> List(WireClient c, string path = "", string pattern = "*", byte cls = 12)
    {
        var id = await Open(c, path, true, 1); var names = new List<string>();
        try
        {
            for (var page = 0; page < 10000; page++)
            {
                var q = RawSmb.Enumerate(id, c.NextMessageId(), c.Session, c.Tree, pattern, (byte)(page == 0 ? 1 : 0)); q[66] = cls;
                await c.SendAsync(q); var response = await c.ReceiveAsync(); var status = RawSmb.U32(response, 8);
                if (status == NoMore || (page == 0 && status == 0xc000000f))
                { RawSmb.Response(response, 14, RawSmb.U64(q, 24), status, 9); break; }
                RawSmb.Response(response, 14, RawSmb.U64(q, 24), 0, 9);
                names.AddRange(RawSmb.Names(RawSmb.Buffer(response, RawSmb.U16(response, 66), RawSmb.U32(response, 68))).Where(n => n is not "." and not ".."));
                if (page == 9999) throw new InvalidOperationException("directory enumeration did not terminate");
            }
        }
        finally { await c.CloseAsync(id); }
        Check.Equal(names.Count, names.Distinct(StringComparer.Ordinal).Count(), "no repeated directory entries"); return names;
    }
    static async Task AssertFile(WireClient c, (ulong P, ulong V) id, byte[] expected)
    {
        var standard = await Query(c, id, 5); Check.Equal((ulong)expected.Length, RawSmb.U64(standard, 8), "live FileStandardInformation EOF");
        if (expected.Length > 0) Bytes(expected, await Read(c, id, expected.Length + 1), "wire content equals independent bytes with no tail");
        await c.ExchangeAsync(RawSmb.Read(id, 1, (ulong)expected.Length, c.NextMessageId(), c.Session, c.Tree), Eof, 9);
    }
    static async Task Sequential()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); await using var c = await f.ConnectAsync(); var id = await Open(c, "testFile");
        await Write(c, id, "test"u8.ToArray()); await Write(c, id, "Content"u8.ToArray(), 4);
        Bytes("testConten"u8.ToArray(), await Read(c, id, 10), "Go TestFile sequential read");
        await AssertFile(c, id, "testContent"u8.ToArray()); await Resize(c, id, 4);
        Bytes("est"u8.ToArray(), await Read(c, id, 10, 1), "truncate followed by seek-from-end read"); await c.CloseAsync(id);
    }
    static async Task Mutate()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); await using var c = await f.ConnectAsync(); var id = await Open(c, "mutate");
        var expected = Pattern(3 << 20); await Write(c, id, expected);
        var a = Pattern(1 << 20, 19); var b = Pattern(300 << 10, 71);
        await Write(c, id, a, (ulong)expected.Length); expected = expected.Concat(a).ToArray(); await AssertFile(c, id, expected);
        await Write(c, id, b, 1 << 20); b.CopyTo(expected, 1 << 20); await AssertFile(c, id, expected);
        await Resize(c, id, 2621440); Array.Resize(ref expected, 2621440); await AssertFile(c, id, expected);
        await Resize(c, id, 6 << 20); Array.Resize(ref expected, 6 << 20); await AssertFile(c, id, expected);
        await Write(c, id, b, (ulong)expected.Length); expected = expected.Concat(b).ToArray(); await AssertFile(c, id, expected);
        await Write(c, id, a, 8 << 20); Array.Resize(ref expected, 9 << 20); a.CopyTo(expected, 8 << 20); await AssertFile(c, id, expected);
        Bytes(expected, NativeHost.ReadAllBytes(f.PathFor("mutate")), "physical mutation oracle"); await c.CloseAsync(id);
    }
    static async Task RandomAccess()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); var bytes = Pattern(64 << 20); File.WriteAllBytes(f.PathFor("random"), bytes);
        await using var c = await f.ConnectAsync(); var id = await Open(c, "random", disposition: 1);
        foreach (var (offset, count) in new[] { (0, 1), (13, 2), (31, 1), (63, 1), (40, 8), (5, 3) })
            Bytes(bytes.AsSpan(offset << 20, count << 20).ToArray(), await Read(c, id, count << 20, (ulong)offset << 20), "independent MiB range " + offset);
        await c.CloseAsync(id);
    }
    static async Task LargeStream()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); await using var c = await f.ConnectAsync(); var id = await Open(c, "large");
        var chunk = Pattern(1 << 20); using var want = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        for (var i = 0; i < 256; i++) { chunk[0] = (byte)i; want.AppendData(chunk); await Write(c, id, chunk, (ulong)i << 20); }
        using var got = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        for (var i = 0; i < 256; i++) got.AppendData(await Read(c, id, 1 << 20, (ulong)i << 20));
        Bytes(want.GetHashAndReset(), got.GetHashAndReset(), "256MiB multi-PDU roundtrip SHA256");
        Check.Equal(256ul << 20, RawSmb.U64(await Query(c, id, 5), 8), "large EOF"); await c.CloseAsync(id);
    }
    static async Task Sparse()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); await using var c = await f.ConnectAsync(); var id = await Open(c, "sparse");
        const ulong size = 4608ul << 20; await Resize(c, id, size); var tail = Pattern(1 << 20, 33); await Write(c, id, tail, size - (1 << 20));
        Check.Equal(size, RawSmb.U64(await Query(c, id, 5), 8), "64-bit EOF above 4GiB");
        Bytes(new byte[1 << 20], await Read(c, id, 1 << 20, 2048ul << 20), "hole reads zero");
        Bytes(tail, await Read(c, id, tail.Length, size - (1 << 20)), "64-bit offset tail"); await c.CloseAsync(id);
    }
    static async Task Positioned()
    {
        await using var f = await UpstreamLocalFixture.StartAsync();
        await Task.WhenAll(Enumerable.Range(0, 8).Select(async i => { await using var c = await f.ConnectAsync(); var id = await Open(c, "positioned");
            var data = Pattern(32768, i * 23); await Write(c, id, data, (ulong)i * 32768); Bytes(data, await Read(c, id, data.Length, (ulong)i * 32768), "concurrent positioned range " + i); await c.CloseAsync(id); }));
        var expected = Enumerable.Range(0, 8).SelectMany(i => Pattern(32768, i * 23)).ToArray();
        Bytes(expected, NativeHost.ReadAllBytes(f.PathFor("positioned")), "disjoint writes preserve all lanes");
    }
    static async Task PeerResize()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); await using var c = await f.ConnectAsync(); await using var peer = await f.ConnectAsync();
        var a = await Open(c, "resize"); var b = await Open(peer, "resize"); await Write(c, a, "discarded-tail"u8.ToArray());
        await Resize(c, a, 3); await AssertFile(peer, b, "dis"u8.ToArray()); await Resize(c, a, 16);
        var expected = new byte[16]; "dis"u8.CopyTo(expected); await AssertFile(peer, b, expected);
        await Resize(peer, b, 0); await AssertFile(c, a, []); await c.CloseAsync(a); await peer.CloseAsync(b);
    }
    static async Task InvalidResize()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); await using var c = await f.ConnectAsync(); var id = await Open(c, "resize"); await Write(c, id, "keep"u8.ToArray());
        var data = new byte[8]; RawSmb.Put64(data, 0, ulong.MaxValue); await c.ExchangeAsync(Set(c, id, 20, data), 0xc000000d, 9);
        await AssertFile(c, id, "keep"u8.ToArray()); await Resize(c, id, 2); await AssertFile(c, id, "ke"u8.ToArray()); await c.CloseAsync(id);
    }
    static async Task SpecialNames()
    {
        string[] names = ["hello world.dat", "paren(1).dat", "plus+dash-_.dat", "dotted.name.v2.dat", "it's here.txt", "#hash %percent &amp ,comma ;semi =eq @at.txt", "café_münchen.dat", "日本語ファイル.txt", "emoji-😀.txt", ".hidden", "UPPER.TXT", new string('a', 200) + ".txt", string.Concat(Enumerable.Repeat("日", 60)) + ".txt", "ünïcödé.txt"];
        await using var f = await UpstreamLocalFixture.StartAsync(); await using var c = await f.ConnectAsync();
        foreach (var name in names) { var id = await Open(c, name); var data = Encoding.UTF8.GetBytes("name:" + name); await Write(c, id, data); await AssertFile(c, id, data); await c.CloseAsync(id); }
        Check.That(names.Order(StringComparer.Ordinal).SequenceEqual((await List(c)).Order(StringComparer.Ordinal)), "exact Unicode and long names survive enumeration");
        foreach (var name in names) await Remove(c, name);
    }
    static async Task DeepTree()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); await using var c = await f.ConnectAsync(); var parts = new List<string>();
        for (var i = 1; i <= 22; i++) { parts.Add($"level-{i:00}"); await c.CloseAsync(await Open(c, string.Join('\\', parts), true)); }
        var path = string.Join('\\', parts); var id = await Open(c, path + "\\bottom.txt"); await Write(c, id, "bottom"u8.ToArray()); await AssertFile(c, id, "bottom"u8.ToArray()); await c.CloseAsync(id);
        foreach (var depth in new[] { 1, 11, 22 }) Check.That((await List(c, string.Join('\\', parts.Take(depth)))).SequenceEqual(new[] { depth == 22 ? "bottom.txt" : parts[depth] }), "deep directory listing " + depth);
        await Remove(c, path + "\\bottom.txt"); for (var i = 22; i >= 1; i--) await Remove(c, string.Join('\\', parts.Take(i)), true);
    }
    static async Task CaseRename()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); await using var c = await f.ConnectAsync(); var id = await Open(c, "Foo.txt"); await Write(c, id, "foo"u8.ToArray());
        await Rename(c, id, "foo.txt"); await AssertFile(c, id, "foo"u8.ToArray()); await c.CloseAsync(id);
        Check.That((await List(c)).SequenceEqual(new[] { "foo.txt" }), "wire rename applies stored case with one surviving name");
    }
    static async Task DirectoryRename()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); await using var c = await f.ConnectAsync(); await c.CloseAsync(await Open(c, "d1", true));
        var child = await Open(c, "d1\\inner.txt"); await Write(c, child, "inner"u8.ToArray()); var dir = await Open(c, "d1", true, 1);
        // MS-FSA 2.1.5.15.12 rejects open descendants. Retain the original
        // successful rename/list/read workflow after an explicit close and retry.
        var target = Encoding.Unicode.GetBytes("d2"); var rejected = new byte[24]; RawSmb.Put32(rejected, 16, (uint)target.Length); target.CopyTo(rejected, 20);
        await c.ExchangeAsync(Set(c, dir, 10, rejected), 0xc0000022);
        await AssertFile(c, child, "inner"u8.ToArray()); await c.CloseAsync(child);
        await Rename(c, dir, "d2"); await c.CloseAsync(dir);
        Check.That((await List(c, "d2")).SequenceEqual(new[] { "inner.txt" }), "renamed subtree enumeration");
        var renamed = await Open(c, "d2\\inner.txt", disposition: 1); await AssertFile(c, renamed, "inner"u8.ToArray()); await c.CloseAsync(renamed);
    }
    static async Task CrossDirectory()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); await using var c = await f.ConnectAsync(); await c.CloseAsync(await Open(c, "sub", true));
        var id = await Open(c, "source"); await Write(c, id, "alpha"u8.ToArray()); await Rename(c, id, "sub\\moved.txt"); await c.CloseAsync(id);
        Check.That((await List(c)).SequenceEqual(new[] { "sub" }), "source removed after cross-directory move");
        id = await Open(c, "sub\\moved.txt", disposition: 1); await AssertFile(c, id, "alpha"u8.ToArray()); await c.CloseAsync(id);
    }
    static async Task RemoveTree()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); await using var c = await f.ConnectAsync();
        foreach (var dir in new[] { "tree", "tree\\a", "tree\\a\\b", "tree\\a\\b\\c" }) await c.CloseAsync(await Open(c, dir, true));
        foreach (var name in new[] { "tree\\1.txt", "tree\\a\\2.txt", "tree\\a\\b\\c\\3.txt" }) { var id = await Open(c, name); await Write(c, id, [120]); await c.CloseAsync(id); }
        foreach (var name in new[] { "tree\\1.txt", "tree\\a\\2.txt", "tree\\a\\b\\c\\3.txt" }) await Remove(c, name);
        foreach (var dir in new[] { "tree\\a\\b\\c", "tree\\a\\b", "tree\\a", "tree" }) await Remove(c, dir, true);
        Check.That(!Directory.Exists(f.PathFor("tree")), "recursive client algorithm removed all wire objects");
    }
    static async Task ManySmall()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); await using var c = await f.ConnectAsync();
        for (var i = 1; i <= 1000; i++) { var id = await Open(c, $"f_{i}.dat"); await Write(c, id, Encoding.UTF8.GetBytes($"content-{i}")); await c.CloseAsync(id); }
        var names = await List(c); Check.Equal(1000, names.Count, "1000 created names");
        foreach (var i in new[] { 1, 500, 1000 }) { var id = await Open(c, $"f_{i}.dat", disposition: 1); await AssertFile(c, id, Encoding.UTF8.GetBytes($"content-{i}")); await c.CloseAsync(id); }
        foreach (var name in names) await Remove(c, name);
        Check.Equal(0, Directory.GetFileSystemEntries(f.RootPath).Length, "all 1000 removed");
    }
    static async Task BigFolder()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); for (var i = 0; i < 5000; i++) File.WriteAllBytes(f.PathFor($"file-{i:00000}.txt"), [120]);
        await using var c = await f.ConnectAsync(); var names = await List(c); Check.Equal(5000, names.Count, "5000 paged names");
        Check.That(names.Order(StringComparer.Ordinal).SequenceEqual(Enumerable.Range(0, 5000).Select(i => $"file-{i:00000}.txt")), "exact high-count name set");
        for (var i = 0; i < 300; i++) { var id = await Open(c, $"file-{i * 17 % 5000:00000}.txt", disposition: 1); Check.Equal(1ul, RawSmb.U64(await Query(c, id, 34), 40), "network-open stat in large folder"); await c.CloseAsync(id); }
    }
    static async Task ParallelListings()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); var expected = Enumerable.Range(0, 200).Select(i => $"f-{i:000}").ToArray(); foreach (var name in expected) File.WriteAllBytes(f.PathFor(name), []);
        await Task.WhenAll(Enumerable.Range(0, 50).Select(async _ => { await using var c = await f.ConnectAsync(); Check.That((await List(c)).Order(StringComparer.Ordinal).SequenceEqual(expected), "independent concurrent directory cursor"); }));
    }
    static async Task Churn()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); await using var writer = await f.ConnectAsync(); await using var reader = await f.ConnectAsync();
        // Bounded rounds; active-directory membership is intentionally unspecified.
        var churn = Task.Run(async () => { for (var i = 0; i < 300; i++) { var id = await Open(writer, $"f_{i}"); await Write(writer, id, [120]); await Rename(writer, id, $"g_{i}"); await writer.CloseAsync(id); await Remove(writer, $"g_{i}"); } });
        for (var round = 0; round < 20; round++)
        {
            var id = await Open(reader, "", true, 1, access: 0x81); var q = RawSmb.Enumerate(id, reader.NextMessageId(), reader.Session, reader.Tree); await reader.SendAsync(q); var b = await reader.ReceiveAsync();
            Check.That(RawSmb.U32(b, 8) is 0 or 0xc000000f, $"churning directory returns data or initial no-match; actual NTSTATUS=0x{RawSmb.U32(b, 8):x8}"); await reader.CloseAsync(id);
        }
        await churn; Check.Equal(0, Directory.GetFileSystemEntries(f.RootPath).Length, "churn leaves no objects");
    }
    static async Task DirectoryLayout(byte cls)
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); File.WriteAllBytes(f.PathFor("日本😀.txt"), [1, 2, 3]); Directory.CreateDirectory(f.PathFor("sub"));
        await using var c = await f.ConnectAsync(); var id = await Open(c, "", true, 1); var request = RawSmb.Enumerate(id, c.NextMessageId(), c.Session, c.Tree); request[66] = cls;
        var response = await c.ExchangeAsync(request, size: 9); var data = RawSmb.Buffer(response, RawSmb.U16(response, 66), RawSmb.U32(response, 68));
        var nameOffset = cls switch { 1 => 64, 2 => 68, 3 => 94, 37 => 104, 38 => 80, _ => throw new InvalidOperationException() };
        var seen = new HashSet<string>();
        for (var at = 0; ;)
        {
            Check.That(at + nameOffset <= data.Length, "directory fixed structure"); var length = RawSmb.U32(data, at + 60); Check.That(length % 2 == 0 && at + nameOffset + length <= data.Length, "UTF16 bounds");
            var name = Encoding.Unicode.GetString(data, at + nameOffset, (int)length);
            if (name is not "." and not "..")
            {
            Check.That(seen.Add(name), "unique layout name");
            Check.Equal(name == "sub" ? 0ul : 3ul, RawSmb.U64(data, at + 40), "directory entry EOF");
            Check.Equal(name == "sub", (RawSmb.U32(data, at + 56) & 0x10) != 0, "directory bit");
            if (cls is 37 or 38) Check.That(RawSmb.U64(data, at + (cls == 37 ? 96 : 72)) != 0, "nonzero opaque file identity");
            }
            var next = RawSmb.U32(data, at); if (next == 0) break;
            Check.That(next % 8 == 0 && next >= nameOffset + length && at + next < data.Length, "bounded aligned next entry"); at += (int)next;
        }
        Check.That(seen.SetEquals(new[] { "日本😀.txt", "sub" }), "all layout names decoded independently"); await c.CloseAsync(id);
    }
    static async Task NetworkOpen()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); await using var c = await f.ConnectAsync(); var id = await Open(c, "stat"); await Write(c, id, "hello world"u8.ToArray());
        var data = await Query(c, id, 34); Check.Equal(56, data.Length, "FileNetworkOpenInformation fixed length"); Check.Equal(11ul, RawSmb.U64(data, 40), "network open EOF");
        Check.That(RawSmb.U64(data, 16) > 0 && (RawSmb.U32(data, 48) & 0x10) == 0, "write time and regular file attributes");
        await Resize(c, id, 2); Check.Equal(2ul, RawSmb.U64(await Query(c, id, 34), 40), "stat not stale after truncation"); await c.CloseAsync(id);
    }
    static async Task Times()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); await using var c = await f.ConnectAsync(); var id = await Open(c, "times");
        var data = new byte[40]; var access = (ulong)new DateTime(2006, 1, 2, 15, 4, 5, DateTimeKind.Utc).ToFileTimeUtc(); var write = (ulong)new DateTime(2006, 3, 8, 19, 32, 5, DateTimeKind.Utc).ToFileTimeUtc();
        RawSmb.Put64(data, 8, access); RawSmb.Put64(data, 16, write); await c.ExchangeAsync(Set(c, id, 4, data), size: 2);
        var info = await Query(c, id, 4); Check.Equal(access, RawSmb.U64(info, 8), "explicit access time"); Check.Equal(write, RawSmb.U64(info, 16), "explicit write time"); await c.CloseAsync(id);
        Check.Equal(write, (ulong)File.GetLastWriteTimeUtc(f.PathFor("times")).ToFileTimeUtc(), "mtime physically persisted");
    }
    static async Task Attributes()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); await using var c = await f.ConnectAsync(); var id = await Open(c, "attrs");
        var data = new byte[40]; RawSmb.Put32(data, 32, 1); await c.ExchangeAsync(Set(c, id, 4, data), size: 2);
        try { Check.That((RawSmb.U32(await Query(c, id, 4), 32) & 1) != 0, "chmod 0444 maps to READONLY bit"); }
        finally { RawSmb.Put32(data, 32, 0x80); await c.ExchangeAsync(Set(c, id, 4, data), size: 2); }
        Check.That((RawSmb.U32(await Query(c, id, 4), 32) & 1) == 0, "chmod 0666 clears READONLY"); await c.CloseAsync(id);
    }
    static async Task FileIdentity()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); await using var c = await f.ConnectAsync(); var id = await Open(c, "identity");
        var before = await Query(c, id, 6); await Rename(c, id, "renamed"); var reopened = await Open(c, "renamed", disposition: 1);
        Bytes(before, await Query(c, reopened, 6), "FileInternalInformation stable across rename/reopen"); var other = await Open(c, "identity");
        var otherInfo = await Query(c, other, 6); Check.That(!before.SequenceEqual(otherInfo), "recreated old name has distinct identity"); await c.CloseAsync(other); await c.CloseAsync(reopened); await c.CloseAsync(id);
    }
    static async Task ConcurrentReaders()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); var data = Pattern(8 << 20); File.WriteAllBytes(f.PathFor("readers"), data); var expected = SHA256.HashData(data);
        await Task.WhenAll(Enumerable.Range(0, 8).Select(async _ => { await using var c = await f.ConnectAsync(); var id = await Open(c, "readers", disposition: 1); Bytes(expected, SHA256.HashData(await Read(c, id, data.Length)), "eight reader SHA256"); await c.CloseAsync(id); }));
    }
    static async Task ConcurrentWriters()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); var data = Pattern(8 << 20); var expected = SHA256.HashData(data);
        await Task.WhenAll(Enumerable.Range(0, 8).Select(async i => { await using var c = await f.ConnectAsync(); var id = await Open(c, $"writer-{i}"); await Write(c, id, data); await c.CloseAsync(id); }));
        await using var reader = await f.ConnectAsync(); for (var i = 0; i < 8; i++) { var id = await Open(reader, $"writer-{i}", disposition: 1); Bytes(expected, SHA256.HashData(await Read(reader, id, data.Length)), "independent writer file SHA256"); await reader.CloseAsync(id); }
    }
    static async Task Sessions()
    {
        await using var f = await UpstreamLocalFixture.StartAsync();
        await Task.WhenAll(Enumerable.Range(0, 50).Select(async i => { await using var c = await f.ConnectAsync(); var id = await Open(c, $"session-{i}"); await Write(c, id, BitConverter.GetBytes(i)); await AssertFile(c, id, BitConverter.GetBytes(i)); await c.CloseAsync(id); }));
        Check.Equal(50, Directory.GetFiles(f.RootPath).Length, "50 isolated session files");
    }
    static async Task Disconnect()
    {
        await using var f = await UpstreamLocalFixture.StartAsync();
        await using (var c = await f.ConnectAsync()) { var id = await Open(c, "partial"); await Write(c, id, Pattern(1 << 20)); /* no CLOSE: transport loss retires handle */ }
        // Server processing is ordered by receipt of the next connection, but cleanup can
        // run concurrently. Observe cleanup itself with a bound, never retry the operation.
        var until = DateTime.UtcNow + Check.Timeout;
        while (f.Server.State.Options.Metrics.OpenHandles != 0 && DateTime.UtcNow < until) await Task.Yield();
        Check.Equal(0L, f.Server.State.Options.Metrics.OpenHandles, "disconnect retires partial-transfer open");
        await using var next = await f.ConnectAsync(); await Remove(next, "partial"); var fresh = await Open(next, "fresh"); await Write(next, fresh, "survived"u8.ToArray()); await AssertFile(next, fresh, "survived"u8.ToArray()); await next.CloseAsync(fresh);
    }
    static async Task Shares()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); var second = Path.Combine(f.RootPath, "second-root"); Directory.CreateDirectory(second);
        // A second tree is configured before opening its connection. Distinct backend
        // roots corroborate public TREE_CONNECT/CREATE routing; no private map assertions.
        f.Server.State.Options.Shares.Add(new Smb.FileSystem.Share { Name = "second", FileStore = new Smb.FileSystem.Local.LocalFileStore(second, false) });
        await using var c = await f.ConnectAsync(); var one = await Open(c, "only-first"); await Write(c, one, [1]); await c.CloseAsync(one);
        var connected = await c.ExchangeAsync(RawSmb.TreeConnect("\\\\localhost\\second", c.NextMessageId(), c.Session), size: 16); var tree = RawSmb.U32(connected, 36);
        var request = Create(c, "only-first", disposition: 1); RawSmb.Put32(request, 36, tree); await c.ExchangeAsync(request, 0xc0000034, 9);
        request = Create(c, "only-second"); RawSmb.Put32(request, 36, tree); var id = Id(await c.ExchangeAsync(request, size: 89));
        var close = RawSmb.Close(id, c.NextMessageId(), c.Session, tree); await c.ExchangeAsync(close, size: 60);
        await c.ExchangeAsync(Create(c, "only-second", disposition: 1), 0xc0000034, 9);
        await c.ExchangeAsync(RawSmb.TreeConnect("\\\\localhost\\nosuchshare", c.NextMessageId(), c.Session), 0xc00000cc, 9);
    }
    static async Task CloseAttributes(ushort flag)
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); await using var c = await f.ConnectAsync(); var id = await Open(c, "close"); await Write(c, id, "hello world"u8.ToArray());
        var request = RawSmb.Close(id, c.NextMessageId(), c.Session, c.Tree); RawSmb.Put16(request, 66, flag); var response = await c.ExchangeAsync(request, size: 60);
        Check.Equal(flag, RawSmb.U16(response, 66), "POSTQUERY_ATTRIB response flag");
        if (flag == 1) { Check.Equal(11ul, RawSmb.U64(response, 112), "close final EOF"); Check.That(RawSmb.U64(response, 88) != 0, "close final mtime"); }
        else Check.That(response.AsSpan(72, 52).ToArray().All(b => b == 0), "plain CLOSE omits optional attributes");
    }
    static async Task CopyOffsets()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); f.Server.State.Options.FeaturePolicy = Smb.Server.SmbFeaturePolicy.CopyOnly;
        await using var c = await f.ConnectAsync(); var src = await Open(c, "src"); var dst = await Open(c, "dst");
        var source = "AAAABBBBCCCCDDDDEEEEFFFF"u8.ToArray(); await Write(c, src, source);
        byte[] Ioctl((ulong P, ulong V) id, uint code, byte[] input, uint output)
        { var b = RawSmb.Header(11, 56 + Math.Max(1, input.Length), c.NextMessageId(), c.Session, c.Tree); RawSmb.Put16(b, 64, 57); RawSmb.Put32(b, 68, code); RawSmb.Put64(b, 72, id.P); RawSmb.Put64(b, 80, id.V); if (input.Length != 0) { RawSmb.Put32(b, 88, 120); RawSmb.Put32(b, 92, (uint)input.Length); input.CopyTo(b, 120); } RawSmb.Put32(b, 108, output); RawSmb.Put32(b, 112, 1); return b; }
        var keyResponse = await c.ExchangeAsync(Ioctl(src, 0x140078, [], 32), size: 49); var key = RawSmb.Buffer(keyResponse, (int)RawSmb.U32(keyResponse, 96), RawSmb.U32(keyResponse, 100)).AsSpan(0, 24).ToArray();
        foreach (var (from, to) in new[] { (0, 0), (4, 4), (4, 0), (0, 6), (4, 6), (3, 5), (8, 16) })
        {
            await Resize(c, dst, 0); var expected = "0123456789abcdef"u8.ToArray(); await Write(c, dst, expected);
            var count = source.Length - from; var data = new byte[56]; key.CopyTo(data, 0); RawSmb.Put32(data, 24, 1); RawSmb.Put64(data, 32, (ulong)from); RawSmb.Put64(data, 40, (ulong)to); RawSmb.Put32(data, 48, (uint)count);
            var response = await c.ExchangeAsync(Ioctl(dst, 0x1440f2, data, 12), size: 49); var result = RawSmb.Buffer(response, (int)RawSmb.U32(response, 96), RawSmb.U32(response, 100));
            Check.Equal(1u, RawSmb.U32(result, 0), "one copy chunk"); Check.Equal((uint)count, RawSmb.U32(result, 8), "all source suffix bytes copied");
            if (to + count > expected.Length) Array.Resize(ref expected, to + count); source.AsSpan(from).CopyTo(expected.AsSpan(to));
            await AssertFile(c, dst, expected); await AssertFile(c, src, source);
        }
        await c.CloseAsync(dst); await c.CloseAsync(src);
    }
}
