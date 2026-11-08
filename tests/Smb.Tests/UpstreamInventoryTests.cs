using System.Text;
using Smb.Testing;

// Public packet facets recovered by the independent inventory audit. Sources and
// precise limits are recorded in docs/correctness/upstream-inventory-audit.md.
internal static partial class UpstreamInventoryTests
{
    const uint Invalid = 0xc000000d, NotGranted = 0xc0000055;
    public static IEnumerable<(string Name, Func<Task> Run)> Cases()
    {
        foreach (var (count, length) in new (ushort, int)[] { (1, 0), (1, 23), (1, 24), (1, 47), (2, 48), (2, 71), (65535, 48) })
            yield return ($"upstream.inventory.lock.truncated-{count}-{length}", () => TruncatedLock(count, length));
        yield return ("upstream.inventory.lock.two-wire-elements", TwoLocks);
        yield return ("upstream.inventory.create.no-response-contexts", NoContexts);
        yield return ("upstream.inventory.create.padded-unknown-before-security-context", PaddedContext);
        yield return ("upstream.inventory.create.context-length-outside-frame", ContextLength);
        foreach (var directory in new[] { false, true })
        {
            yield return ($"upstream.inventory.metadata.archive-on-modification-{directory}", () => ArchiveOnModification(directory));
            yield return ($"upstream.inventory.metadata.creation-stable-on-modification-{directory}", () => CreationStable(directory));
        }
        foreach (var c in SecurityCases()) yield return c;
        foreach (var c in PacketCases()) yield return c;
        foreach (var c in RecoveryCases()) yield return c;
        foreach (var c in BoundaryCases()) yield return c;
        foreach (var c in UnsupportedQueries)
            yield return ($"upstream.inventory.query.unsupported-{c}", () => UnsupportedQuery(c));
    }
    static byte[] Lock(WireClient c, (ulong P, ulong V) id, params (ulong Offset, ulong Length, uint Flags)[] ranges)
    {
        var b = RawSmb.Header(10, 24 + 24 * ranges.Length, c.NextMessageId(), c.Session, c.Tree);
        RawSmb.Put16(b, 64, 48); RawSmb.Put16(b, 66, (ushort)ranges.Length);
        RawSmb.Put64(b, 72, id.P); RawSmb.Put64(b, 80, id.V);
        for (var i = 0; i < ranges.Length; i++)
        {
            var at = 88 + i * 24; RawSmb.Put64(b, at, ranges[i].Offset); RawSmb.Put64(b, at + 8, ranges[i].Length); RawSmb.Put32(b, at + 16, ranges[i].Flags);
        }
        return b;
    }
    static async Task TruncatedLock(ushort count, int length)
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); await using var c = await h.ConnectAsync();
        var a = await c.CreateAsync("locks"); var peer = await c.CreateAsync("locks");
        await c.ExchangeAsync(Lock(c, a, (100, 20, 18)), size: 4);
        var b = Lock(c, a, (200, 30, 18), (300, 40, 18)); RawSmb.Put16(b, 66, count); Array.Resize(ref b, 64 + length);
        await c.ExchangeAsync(b, Invalid);
        // Complete first elements in an incomplete array must not be committed.
        await c.ExchangeAsync(Lock(c, peer, (200, 30, 18)), size: 4);
        await c.ExchangeAsync(Lock(c, peer, (200, 30, 4)), size: 4);
        await c.ExchangeAsync(Lock(c, peer, (100, 20, 18)), NotGranted);
        await c.ExchangeAsync(Lock(c, a, (100, 20, 4)), size: 4);
        await c.ExchangeAsync(Lock(c, a, (200, 30, 18)), size: 4);
        await c.CloseAsync(peer); await c.CloseAsync(a);
    }
    static async Task TwoLocks()
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); await using var c = await h.ConnectAsync();
        var a = await c.CreateAsync("locks"); var peer = await c.CreateAsync("locks");
        await c.ExchangeAsync(Lock(c, a, (100, 20, 18), (200, 30, 18)), size: 4);
        foreach (var range in new (ulong Offset, ulong Length)[] { (100, 20), (200, 30) })
            await c.ExchangeAsync(Lock(c, peer, (range.Offset, range.Length, 18)), NotGranted);
        await c.ExchangeAsync(Lock(c, peer, (120, 80, 18)), size: 4);
        await c.ExchangeAsync(Lock(c, peer, (120, 80, 4)), size: 4);
        await c.ExchangeAsync(Lock(c, a, (100, 20, 4), (200, 30, 4)), size: 4);
        await c.ExchangeAsync(Lock(c, peer, (100, 20, 18), (200, 30, 18)), size: 4);
        await c.CloseAsync(peer); await c.CloseAsync(a);
    }
    static async Task NoContexts()
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); await using var c = await h.ConnectAsync();
        var b = await c.ExchangeAsync(RawSmb.Create("plain", false, c.NextMessageId(), c.Session, c.Tree), size: 89);
        Check.Equal(0u, RawSmb.U32(b, 144), "CREATE without returned contexts has zero context offset");
        Check.Equal(0u, RawSmb.U32(b, 148), "CREATE without returned contexts has zero context length");
        await c.CloseAsync((RawSmb.U64(b, 128), RawSmb.U64(b, 136)));
    }
    static byte[] Context(string name, byte[] data)
    {
        var n = Encoding.ASCII.GetBytes(name); var at = (16 + n.Length + 7) & ~7;
        var b = new byte[(at + data.Length + 7) & ~7]; RawSmb.Put16(b, 4, 16); RawSmb.Put16(b, 6, (ushort)n.Length);
        RawSmb.Put16(b, 10, (ushort)at); RawSmb.Put32(b, 12, (uint)data.Length); n.CopyTo(b, 16); data.CopyTo(b, at); return b;
    }
    static byte[] CreateWithContexts(WireClient c, params byte[][] contexts)
    {
        var b = RawSmb.Create("contexts", false, c.NextMessageId(), c.Session, c.Tree); var offset = (b.Length + 7) & ~7;
        Array.Resize(ref b, offset + contexts.Sum(x => x.Length)); RawSmb.Put32(b, 112, (uint)offset); RawSmb.Put32(b, 116, (uint)(b.Length - offset));
        for (var i = 0; i < contexts.Length; i++) { var ctx = contexts[i]; RawSmb.Put32(ctx, 0, i + 1 < contexts.Length ? (uint)ctx.Length : 0); ctx.CopyTo(b, offset); offset += ctx.Length; }
        return b;
    }
    static async Task PaddedContext()
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); await using var c = await h.ConnectAsync();
        // Upstream's first logical record is 84 bytes, padded to Next=88.
        var first = Context("0123456789abcdef", Enumerable.Range(0, 52).Select(x => (byte)x).ToArray()); Check.Equal(88, first.Length, "source padding scenario");
        await c.ExchangeAsync(CreateWithContexts(c, first, Context("SecD", new byte[20])), 0xc00000bb);
        Check.That(!File.Exists(h.PathFor("contexts")), "second recognized context rejects unsupported atomic security CREATE before mutation");
        var id = await c.CreateAsync("contexts"); await c.WriteAsync(id, [42]); await c.CloseAsync(id);
    }
    static async Task ContextLength()
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); await using var c = await h.ConnectAsync();
        var b = CreateWithContexts(c, Context("MxAc", new byte[8])); RawSmb.Put32(b, 116, RawSmb.U32(b, 116) + 1000);
        await c.ExchangeAsync(b, Invalid); Check.That(!File.Exists(h.PathFor("contexts")), "malformed context array cannot create the object");
        var id = await c.CreateAsync("contexts"); await c.CloseAsync(id);
    }
    static byte[] Query(WireClient c, (ulong P, ulong V) id, byte cls, uint length = 40)
    {
        var b = RawSmb.Header(16, 40, c.NextMessageId(), c.Session, c.Tree); RawSmb.Put16(b, 64, 41); b[66] = 1; b[67] = cls;
        RawSmb.Put32(b, 68, length); RawSmb.Put64(b, 88, id.P); RawSmb.Put64(b, 96, id.V); return b;
    }
    static byte[] Set(WireClient c, (ulong P, ulong V) id, byte cls, byte[] data)
    {
        var b = RawSmb.Header(17, 32 + data.Length, c.NextMessageId(), c.Session, c.Tree); RawSmb.Put16(b, 64, 33); b[66] = 1; b[67] = cls;
        RawSmb.Put32(b, 68, (uint)data.Length); RawSmb.Put16(b, 72, 96); RawSmb.Put64(b, 80, id.P); RawSmb.Put64(b, 88, id.V); data.CopyTo(b, 96); return b;
    }
    static byte[] Output(byte[] b) => RawSmb.Buffer(b, RawSmb.U16(b, 66), RawSmb.U32(b, 68));
    static async Task<(ulong P, ulong V)> MetadataOpen(WireClient c, bool directory, string name = "data")
    {
        var b = RawSmb.Create(name, directory, c.NextMessageId(), c.Session, c.Tree); RawSmb.Put32(b, 88, 0x1f01ff); RawSmb.Put32(b, 100, 3);
        var r = await c.ExchangeAsync(b, size: 89); return (RawSmb.U64(r, 128), RawSmb.U64(r, 136));
    }
    static async Task<(ulong P, ulong V)> MetadataReopen(WireClient c, bool directory)
    {
        var b = RawSmb.Create("data", directory, c.NextMessageId(), c.Session, c.Tree); RawSmb.Put32(b, 88, 0x1f01ff); RawSmb.Put32(b, 100, 1);
        var response = await c.ExchangeAsync(b, size: 89); return (RawSmb.U64(response, 128), RawSmb.U64(response, 136));
    }
    static async Task Modify(WireClient c, (ulong P, ulong V) id, bool directory)
    {
        if (directory) { var child = await c.CreateAsync("data\\child"); await c.CloseAsync(child); }
        else await c.WriteAsync(id, [1, 2, 3]);
    }
    static async Task ArchiveOnModification(bool directory)
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); await using var c = await h.ConnectAsync(); var id = await MetadataOpen(c, directory);
        var basic = new byte[40]; RawSmb.Put32(basic, 32, 0x80); await c.ExchangeAsync(Set(c, id, 4, basic));
        Check.Equal(0u, RawSmb.U32(Output(await c.ExchangeAsync(Query(c, id, 4))), 32) & 0x20u, "clear archive through public SET_INFO");
        await Modify(c, id, directory); await c.CloseAsync(id); id = await MetadataReopen(c, directory);
        Check.That((RawSmb.U32(Output(await c.ExchangeAsync(Query(c, id, 4))), 32) & 0x20) != 0, "MS-FSA source policy sets ARCHIVE on modification (SHOULD)");
        await c.CloseAsync(id);
    }
    static async Task CreationStable(bool directory)
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); await using var c = await h.ConnectAsync(); var id = await MetadataOpen(c, directory);
        var before = RawSmb.U64(Output(await c.ExchangeAsync(Query(c, id, 4))), 0); await Modify(c, id, directory); await c.CloseAsync(id); id = await MetadataReopen(c, directory);
        Check.Equal(before, RawSmb.U64(Output(await c.ExchangeAsync(Query(c, id, 4))), 0), "creation time unchanged by file write/directory child creation");
        await c.CloseAsync(id);
    }
    // Recognized optional classes excluded by the original inventory: test their
    // actual public rejection rather than pretending to test their success shape.
    static readonly byte[] UnsupportedQueries = [8, 16, 17, 21, 28, 29, 30, 39, 46, 54];
    static async Task UnsupportedQuery(byte cls)
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); await using var c = await h.ConnectAsync(); var id = await c.CreateAsync("data"); await c.WriteAsync(id, [42]);
        await c.ExchangeAsync(Query(c, id, cls, 4096), 0xc00000bb);
        Check.That((await c.ReadAsync(id, 1)).SequenceEqual(new byte[] { 42 }), "unsupported query preserves live open and data"); await c.CloseAsync(id);
    }
}
