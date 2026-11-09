using Smb.Testing;

internal static partial class CacheSequenceRecoveryTests
{
    static IEnumerable<(string Name, Func<Task> Run)> StatRepairCases()
    {
        foreach (var dialect in new ushort[] { 0x202, 0x300, 0x311 })
        foreach (var leased in dialect == 0x202 ? new[] { false } : new[] { false, true })
        {
            yield return ($"cache.repair.stat-ea.{dialect:x}.{leased}", () => StatEa(dialect, leased));
            foreach (var operation in new[] { "data", "ea-write", "overwrite", "share-denial" })
                yield return ($"cache.repair.stat-control.{dialect:x}.{leased}.{operation}", () => StatControl(dialect, leased, operation));
        }
    }
    static async Task StatEa(ushort dialect, bool leased)
    {
        await using var f = new Fixture(); await f.Server.StartAsync();
        await using var owner = await f.Connect(dialect, Guid.NewGuid());
        await using var peer = await f.Connect(dialect, Guid.NewGuid());
        var initial = await owner.Exchange(leased ? FullLease(dialect, 7, disposition: 3) : Classic(9, 3));
        if (leased) Grant(initial, 7); else Check.Equal((byte)9, initial[66], "Batch established");
        var id = Id(initial); var bytes = "metadata-only CREATE preserves dirty-cache promises"u8.ToArray();
        await owner.Exchange(RawSmb.Write(id, bytes, 0, 0, 0, 0));
        var before = File.GetLastWriteTimeUtc(f.Root.Path + "/file");
        // MS-SMB2 2.2.13.1.1: READ_EA reads metadata, never stream data.
        // Exercise both the exact original compound access and READ_EA alone.
        foreach (var access in new uint[] { 0x100088, 8 })
        {
            var create = Classic(0); RawSmb.Put32(create, 88, access);
            var stat = Id(await peer.Exchange(create));
            var ea = await peer.Exchange(QueryPacket(stat, 7));
            Check.Equal(0u, RawSmb.U32(ea, RawSmb.U16(ea, 66)), "empty EA size");
            if (access != 8)
            {
                var info = await peer.Exchange(QueryPacket(stat, 22));
                // MS-FSCC FileStreamInformation: size follows Next/NameLength.
                var at = RawSmb.U16(info, 66); Check.Equal(0u, RawSmb.U32(info, at), "one default stream");
                Check.Equal((ulong)bytes.Length, RawSmb.U64(info, at + 8), "stat stream EOF");
                Check.Equal("::$DATA", System.Text.Encoding.Unicode.GetString(info, at + 24, (int)RawSmb.U32(info, at + 4)), "default stream name");
                await peer.Exchange(RawSmb.Read(stat, 1, 0, 0, 0, 0), 0xc0000022);
                await peer.Exchange(RawSmb.Write(stat, [0], 0, 0, 0, 0), 0xc0000022);
            }
            await peer.Exchange(RawSmb.Close(stat, 0, 0, 0));
            Check.Equal(0, f.Options.CacheCoordinator.BreakingCount, "no break pending after stat workflow");
            Check.That(bytes.SequenceEqual(File.ReadAllBytes(f.Root.Path + "/file")), "metadata workflow preserves physical bytes");
            Check.Equal(before, File.GetLastWriteTimeUtc(f.Root.Path + "/file"), "no physical write or truncation");
        }
        // A real data CREATE must still pend. Its exact first owner notification
        // proves no earlier stat notification was buffered or discarded.
        var pending = await Begin(peer, Classic(0)); await Reply(peer, pending, 0x103);
        if (leased) { var notice = await Notice(owner, 7, 3); await owner.Exchange(Ack(notice, 3)); }
        else { await ClassicNotice(owner, id, 1); await owner.Exchange(ClassicAck(id, 1)); }
        var data = Id(await Reply(peer, pending));
        var read = await peer.Exchange(RawSmb.Read(data, (uint)bytes.Length, 0, 0, 0, 0));
        Check.That(bytes.SequenceEqual(RawSmb.Buffer(read, read[66], RawSmb.U32(read, 68))), "data opener reads intact bytes");
        await peer.Exchange(RawSmb.Close(data, 0, 0, 0)); await owner.Exchange(RawSmb.Close(id, 0, 0, 0));
        Check.Equal(0, f.Options.CacheCoordinator.GrantCount, "all grants retired");
    }
    static async Task StatControl(ushort dialect, bool leased, string operation)
    {
        await using var f = new Fixture(); await f.Server.StartAsync();
        await using var owner = await f.Connect(dialect, Guid.NewGuid());
        await using var peer = await f.Connect(dialect, Guid.NewGuid());
        var initial = await owner.Exchange(leased ? FullLease(dialect, 7, disposition: 3) : Classic(9, 3)); var id = Id(initial);
        if (leased) Grant(initial, 7); else Check.Equal((byte)9, initial[66], "control Batch established");
        var bytes = "held bytes before cache ACK"u8.ToArray(); await owner.Exchange(RawSmb.Write(id, bytes, 0, 0, 0, 0));
        var request = Classic(0, operation == "overwrite" ? 4u : 1u, operation == "share-denial" ? 0u : 7u);
        RawSmb.Put32(request, 88, operation switch { "data" or "share-denial" => 0x100089u, "ea-write" => 0x100098u, _ => 0x100088u });
        var pending = await Begin(peer, request); await Reply(peer, pending, 0x103);
        Check.That(bytes.SequenceEqual(File.ReadAllBytes(f.Root.Path + "/file")), "no mutation before break ACK");
        var target = operation == "overwrite" ? 0u : operation == "share-denial" ? 5u : 3u;
        if (leased) { var notice = await Notice(owner, 7, target); await owner.Exchange(Ack(notice, target)); }
        else { var level = operation == "overwrite" ? (byte)0 : (byte)1; await ClassicNotice(owner, id, level); await owner.Exchange(ClassicAck(id, level)); }
        var response = await Reply(peer, pending, operation == "share-denial" ? 0xc0000043u : 0u);
        if (operation == "overwrite") Check.Equal(0L, new FileInfo(f.Root.Path + "/file").Length, "destructive stat CREATE truncates only after ACK");
        else Check.That(bytes.SequenceEqual(File.ReadAllBytes(f.Root.Path + "/file")), "nondestructive admission retains physical bytes");
        if (operation == "ea-write")
        {
            // FILE_FULL_EA_INFORMATION: next=0, flags=0, name='A', value=42.
            byte[] ea = [0, 0, 0, 0, 0, 1, 1, 0, 65, 0, 42];
            var mutation = await Begin(peer, SetPacket(Id(response), 15, ea));
            if (leased) { await Reply(peer, mutation, 0x103); var notice = await Notice(owner, 3, 0); await owner.Exchange(Ack(notice, 0)); }
            else await ClassicNotice(owner, id, 0);
            await Reply(peer, mutation);
            var queried = await peer.Exchange(QueryPacket(Id(response), 15));
            Check.That(ea.SequenceEqual(RawSmb.Buffer(queried, RawSmb.U16(queried, 66), RawSmb.U32(queried, 68))), "EA mutation reaches backend after invalidation");
            Check.That(bytes.SequenceEqual(File.ReadAllBytes(f.Root.Path + "/file")), "EA mutation preserves stream data");
        }
        if (operation != "share-denial") await peer.Exchange(RawSmb.Close(Id(response), 0, 0, 0));
        await owner.Exchange(RawSmb.Close(id, 0, 0, 0));
        Check.Equal(0, f.Options.CacheCoordinator.GrantCount, "control grants retired");
    }
}
