using Smb.Testing;

internal static partial class UpstreamInventoryTests
{
    static IEnumerable<(string Name, Func<Task> Run)> SecurityCases()
    {
        foreach (var flags in new uint[] { 3, 4, 7 })
            yield return ($"upstream.inventory.security.query-{flags}", () => SecurityQuery(flags));
        yield return ("upstream.inventory.security.query-set-dacl-roundtrip", SecurityRoundtrip);
    }
    static byte[] QuerySecurity(WireClient c, (ulong P, ulong V) id, uint flags)
    { var b = Query(c, id, 0, 4096); b[66] = 3; RawSmb.Put32(b, 80, flags); return b; }
    static void Descriptor(byte[] data, uint flags)
    {
        Check.That(data.Length >= 20 && data[0] == 1 && (RawSmb.U16(data, 2) & 0x8000) != 0, "non-null revision1 self-relative security descriptor");
        if ((flags & 3) != 0)
            foreach (var field in new[] { 4, 8 })
            {
                var at = RawSmb.U32(data, field); Check.That(at >= 20 && at <= data.Length - 8, "requested owner/group SID is present and bounded");
                Check.Equal((byte)1, data[at], "SID revision"); Check.That((ulong)at + 8 + 4ul * data[at + 1] <= (ulong)data.Length, "SID subauthority array bounded");
            }
    }
    static async Task SecurityQuery(uint flags)
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); await using var c = await h.ConnectAsync(); var id = await MetadataOpen(c, false);
        Descriptor(Output(await c.ExchangeAsync(QuerySecurity(c, id, flags))), flags); await c.CloseAsync(id);
    }
    static async Task SecurityRoundtrip()
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); await using var c = await h.ConnectAsync(); var id = await MetadataOpen(c, false);
        var original = Output(await c.ExchangeAsync(QuerySecurity(c, id, 4))); Descriptor(original, 4);
        var request = Set(c, id, 0, original); request[66] = 3; RawSmb.Put32(request, 76, 4); await c.ExchangeAsync(request);
        var after = Output(await c.ExchangeAsync(QuerySecurity(c, id, 4))); Descriptor(after, 4);
        Check.That(after.SequenceEqual(original), "same DACL roundtrips through public SET/QUERY security info");
        await c.CloseAsync(id);
    }
}
