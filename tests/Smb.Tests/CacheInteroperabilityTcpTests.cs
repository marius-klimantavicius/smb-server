using Smb.Testing;

internal static partial class CacheSequenceRecoveryTests
{
    // Independent literal targets from MS-FSA 2.1.5.18.2. All participants
    // negotiate and authenticate their own TCP transport; signatures use Peer.
    static IEnumerable<(string Name, Func<Task> Run)> RepairCases()
    {
        foreach (var test in StatRepairCases()) yield return test;
        foreach (var test in ProtectedCases()) yield return test;
        foreach (var durable in new[] { false, true })
        foreach (var dialect in new ushort[] { 0x210, 0x311 })
        {
            foreach (var leaseFirst in new[] { false, true })
            foreach (var state in new uint[] { 1, 3, 5, 7 })
            foreach (var level in new byte[] { 1, 8, 9 })
                yield return ($"cache.repair.tcp.mixed.{durable}.{dialect:x}.{leaseFirst}.{state}.{level}", () => Mixed(durable, dialect, leaseFirst, state, level));
            foreach (var leased in new[] { false, true })
                yield return ($"cache.repair.tcp.share-denial.{durable}.{dialect:x}.{leased}", () => Sharing(durable, dialect, leased));
            yield return ($"cache.repair.tcp.contended-rh.{durable}.{dialect:x}", () => Contended(durable, dialect));
            yield return ($"cache.repair.tcp.locked-grants.{durable}.{dialect:x}", () => Locked(durable, dialect));
            yield return ($"cache.repair.tcp.rename-read.{durable}.{dialect:x}", () => RenameRead(durable, dialect));
            if (dialect >= 0x300) yield return ($"cache.repair.tcp.version-epoch.{durable}.{dialect:x}", () => VersionEpoch(durable, dialect));
            foreach (var operation in new[] { "query", "attributes", "delete-pending" })
                yield return ($"cache.repair.tcp.metadata.{durable}.{dialect:x}.{operation}", () => Metadata(durable, dialect, operation));
            yield return ($"cache.repair.tcp.rearm.{durable}.{dialect:x}", () => Rearm(durable, dialect));
        }
    }
    static byte[] Classic(byte level, uint disposition = 1, uint share = 7)
    { var b = RawSmb.Create("file", false, 0, 0, 0); b[67] = level; RawSmb.Put32(b, 100, disposition); RawSmb.Put32(b, 96, share); RawSmb.Put32(b, 88, 0x1f01ff); return b; }
    static async Task<byte[]> ClassicNotice(Peer peer, (ulong P, ulong V) id, byte target)
    {
        var b = await peer.Notification(); Check.Equal((ushort)18, RawSmb.U16(b, 12), "classic notification command");
        Check.Equal(ulong.MaxValue, RawSmb.U64(b, 24), "unsolicited classic MessageId");
        Check.Equal((ushort)24, RawSmb.U16(b, 64), "classic structure"); Check.Equal(target, b[66], "classic target");
        Check.Equal(id, (RawSmb.U64(b, 72), RawSmb.U64(b, 80)), "classic owner FileId"); return b;
    }
    static byte[] ClassicAck((ulong P, ulong V) id, byte target)
    { var b = RawSmb.Header(18, 24, 0); RawSmb.Put16(b, 64, 24); b[66] = target; RawSmb.Put64(b, 72, id.P); RawSmb.Put64(b, 80, id.V); return b; }
    static async Task Mixed(bool durable, ushort dialect, bool leaseFirst, uint state, byte level)
    {
        await using var f = new Fixture(durable); await f.Server.StartAsync();
        await using var a = await f.Connect(dialect, Guid.NewGuid()); await using var b = await f.Connect(dialect, Guid.NewGuid());
        var first = await a.Exchange(leaseFirst ? Lease(dialect, state, disposition: 3) : Classic(level, 3)); var owner = Id(first);
        if (leaseFirst) Grant(first, state); else Check.Equal(level, first[66], "first classic grant");
        var request = await Begin(b, leaseFirst ? Classic(level) : Lease(dialect, state, 2));
        if (leaseFirst && (state & 4) != 0 || !leaseFirst && level != 1)
        {
            await Reply(b, request, 0x103);
            if (leaseFirst) { var notice = await Notice(a, state, state & 3); await a.Exchange(Ack(notice, state & 3)); }
            else { await ClassicNotice(a, owner, 1); await a.Exchange(ClassicAck(owner, 1)); }
        }
        var second = await Reply(b, request); var peer = Id(second);
        if (leaseFirst) Check.Equal((byte)((state & 2) == 0 ? 1 : 0), second[66], "mixed classic grant"); else Grant(second, 1);
        // Each physical WRITE must invalidate every foreign read promise.
        var bytes = new byte[] { 4, 8, 15, 16, 23, 42 }; var write = await Begin(b, RawSmb.Write(peer, bytes, 0, 0, 0, 0));
        if (leaseFirst)
        {
            if ((state & 2) != 0)
            { await Reply(b, write, 0x103); var n = await Notice(a, state & 3, 0); await a.Exchange(Ack(n, 0)); }
            else await Notice(a, 1, 0);
        }
        else await ClassicNotice(a, owner, 0);
        // A writing level-II handle also invalidates its own promise.
        if (leaseFirst && second[66] == 1) await ClassicNotice(b, peer, 0);
        await Reply(b, write);
        var read = await a.Exchange(RawSmb.Read(owner, (uint)bytes.Length, 0, 0, 0, 0));
        Check.That(bytes.SequenceEqual(RawSmb.Buffer(read, read[66], RawSmb.U32(read, 68))), "mixed grants preserve coherent data");
        await a.Exchange(RawSmb.Close(owner, 0, 0, 0)); await b.Exchange(RawSmb.Close(peer, 0, 0, 0));
        Check.Equal(0, f.Options.CacheCoordinator.GrantCount, "all mixed grant memberships retired");
    }
    static byte[] QueryPacket((ulong P, ulong V) id, byte cls)
    { var b = RawSmb.Header(16, 40, 0); RawSmb.Put16(b, 64, 41); b[66] = 1; b[67] = cls; RawSmb.Put32(b, 68, 4096); RawSmb.Put64(b, 88, id.P); RawSmb.Put64(b, 96, id.V); return b; }
    static byte[] SetPacket((ulong P, ulong V) id, byte cls, byte[] data)
    { var b = RawSmb.Header(17, 32 + data.Length, 0); RawSmb.Put16(b, 64, 33); b[66] = 1; b[67] = cls; RawSmb.Put32(b, 68, (uint)data.Length); RawSmb.Put16(b, 72, 96); RawSmb.Put64(b, 80, id.P); RawSmb.Put64(b, 88, id.V); data.CopyTo(b, 96); return b; }
    static async Task Metadata(bool durable, ushort dialect, string operation)
    {
        await using var f = new Fixture(durable); await f.Server.StartAsync();
        await using var a = await f.Connect(dialect, Guid.NewGuid()); await using var b = await f.Connect(dialect, Guid.NewGuid());
        var owner = Id(await a.Exchange(Classic(9, 3))); await a.Exchange(RawSmb.Write(owner, [42], 0, 0, 0, 0));
        if (operation == "delete-pending")
        {
            await a.Exchange(SetPacket(owner, 13, [1])); await b.Exchange(Classic(0), 0xc0000056);
            await a.Exchange(SetPacket(owner, 13, [0]));
        }
        else
        {
            var statRequest = Classic(0); RawSmb.Put32(statRequest, 88, 0x180); var stat = Id(await b.Exchange(statRequest));
            if (operation == "query")
            { var response = await b.Exchange(QueryPacket(stat, 18)); Check.Equal(1ul, RawSmb.U64(response, RawSmb.U16(response, 66) + 40 + 8), "stat ALL_INFORMATION includes EOF"); }
            else
            { var basic = new byte[40]; RawSmb.Put32(basic, 32, 2); await b.Exchange(SetPacket(stat, 4, basic)); var response = await b.Exchange(QueryPacket(stat, 4)); Check.That((RawSmb.U32(response, RawSmb.U16(response, 66) + 32) & 2) != 0, "attribute update visible"); }
            await b.Exchange(RawSmb.Close(stat, 0, 0, 0));
        }
        Check.Equal(0, f.Options.CacheCoordinator.BreakingCount, "metadata leaves no pending break");
        // A later ordinary data opener proves that no notification was hidden
        // in the owner's TCP stream by the metadata operation.
        var request = await Begin(b, Classic(0)); await Reply(b, request, 0x103); await ClassicNotice(a, owner, 1);
        await a.Exchange(ClassicAck(owner, 1)); var peer = Id(await Reply(b, request));
        var read = await b.Exchange(RawSmb.Read(peer, 1, 0, 0, 0, 0)); Check.Equal((byte)42, read[read[66]], "metadata never modifies file bytes");
        await a.Exchange(RawSmb.Close(owner, 0, 0, 0)); await b.Exchange(RawSmb.Close(peer, 0, 0, 0));
    }
    static byte[] FullLease(ushort dialect, uint state, ulong key = 1, uint disposition = 1)
    { var b = Lease(dialect, state, key, disposition); RawSmb.Put32(b, 88, 0x1f01ff); return b; }
    static async Task Sharing(bool durable, ushort dialect, bool leased)
    {
        await using var f = new Fixture(durable); await f.Server.StartAsync();
        await using var a = await f.Connect(dialect, Guid.NewGuid()); await using var b = await f.Connect(dialect, Guid.NewGuid());
        var first = await a.Exchange(leased ? FullLease(dialect, 7, disposition: 3) : Classic(9, 3, 0)); var owner = Id(first);
        await a.Exchange(RawSmb.Write(owner, [42], 0, 0, 0, 0));
        var denied = leased ? FullLease(dialect, 7, 2) : Classic(0); if (leased) RawSmb.Put32(denied, 96, 1);
        var req = await Begin(b, denied); await Reply(b, req, 0x103);
        if (leased)
        { var notice = await Notice(a, 7, 5); await a.Exchange(Ack(notice, 7), 0xc00000d0); Check.Equal((byte)42, File.ReadAllBytes(f.Root.Path + "/file")[0], "invalid ACK cannot mutate data"); await a.Exchange(Ack(notice, 5)); }
        else { await ClassicNotice(a, owner, 1); await a.Exchange(ClassicAck(owner, 1)); }
        await Reply(b, req, 0xc0000043);
        Check.Equal(1, f.Options.CacheCoordinator.GrantCount, "denied CREATE publishes no cache member");
        if (leased)
        {
            var accepted = await Begin(b, FullLease(dialect, 7, 2)); await Reply(b, accepted, 0x103); var notice = await Notice(a, 5, 1);
            await a.Exchange(Ack(notice, 1)); var peer = Id(await Reply(b, accepted));
            var write = await Begin(a, RawSmb.Write(owner, [43], 0, 0, 0, 0)); await Reply(a, write, 0x103); var n = await Notice(b, 3, 0, 2); await b.Exchange(Ack(n, 0)); await Reply(a, write);
            var read = await b.Exchange(RawSmb.Read(peer, 1, 0, 0, 0, 0)); Check.Equal((byte)43, read[read[66]], "post-denial data remains coherent"); await b.Exchange(RawSmb.Close(peer, 0, 0, 0));
        }
        else
        { var write = await Begin(a, RawSmb.Write(owner, [43], 0, 0, 0, 0)); await ClassicNotice(a, owner, 0); await Reply(a, write); }
        await a.Exchange(RawSmb.Close(owner, 0, 0, 0)); Check.Equal(0, f.Options.CacheCoordinator.GrantCount, "share denial leaves no leaked grant");
    }
    static async Task Contended(bool durable, ushort dialect)
    {
        await using var f = new Fixture(durable); await f.Server.StartAsync(); var client = Guid.NewGuid();
        await using var a = await f.Connect(dialect, client); await using var b = await f.Connect(dialect, Guid.NewGuid());
        var owner = Id(await a.Exchange(FullLease(dialect, 1, disposition: 3))); var peer = Id(await b.Exchange(FullLease(dialect, 1, 2)));
        var promoted = await a.Exchange(FullLease(dialect, 3)); Grant(promoted, 3); var member = Id(promoted);
        var rejected = await a.Exchange(FullLease(dialect, 7)); Grant(rejected, 3); await a.Exchange(RawSmb.Close(Id(rejected), 0, 0, 0));
        var write = await Begin(b, RawSmb.Write(peer, [8], 0, 0, 0, 0)); await Reply(b, write, 0x103); var notice = await Notice(a, 3, 0);
        await a.Exchange(Ack(notice, 1), 0xc00000d0); Check.Equal(0L, new FileInfo(f.Root.Path + "/file").Length, "invalid ACK withholds physical WRITE");
        await a.Exchange(Ack(notice, 0)); await Reply(b, write); await a.Exchange(Ack(notice, 0), 0xc0000001);
        var read = await a.Exchange(RawSmb.Read(owner, 1, 0, 0, 0, 0)); Check.Equal((byte)8, read[read[66]], "write after valid ACK visible");
        await a.Exchange(RawSmb.Close(member, 0, 0, 0)); await a.Exchange(RawSmb.Close(owner, 0, 0, 0)); await b.Exchange(RawSmb.Close(peer, 0, 0, 0));
    }
    static byte[] LockPacket((ulong P, ulong V) id, uint flags)
    { var b = RawSmb.Header(10, 48, 0); RawSmb.Put16(b, 64, 48); RawSmb.Put16(b, 66, 1); RawSmb.Put64(b, 72, id.P); RawSmb.Put64(b, 80, id.V); RawSmb.Put64(b, 96, 1); RawSmb.Put32(b, 104, flags); return b; }
    static async Task Locked(bool durable, ushort dialect)
    {
        await using var f = new Fixture(durable); await f.Server.StartAsync();
        await using var a = await f.Connect(dialect, Guid.NewGuid()); await using var b = await f.Connect(dialect, Guid.NewGuid());
        var owner = Id(await a.Exchange(FullLease(dialect, 7, disposition: 3))); await a.Exchange(RawSmb.Write(owner, [9], 0, 0, 0, 0)); await a.Exchange(LockPacket(owner, 0x12));
        var req = await Begin(b, FullLease(dialect, 7, 2)); await Reply(b, req, 0x103); var notice = await Notice(a, 7, 3); await a.Exchange(Ack(notice, 3)); var result = await Reply(b, req); Grant(result, 3); var peer = Id(result);
        await b.Exchange(LockPacket(peer, 0x12), 0xc0000055); await b.Exchange(RawSmb.Read(peer, 1, 0, 0, 0, 0), 0xc0000054);
        await a.Exchange(LockPacket(owner, 4)); var pending = await Begin(b, LockPacket(peer, 0x12)); await Reply(b, pending, 0x103); notice = await Notice(a, 3, 0);
        await a.Exchange(Ack(notice, 0)); await Reply(b, pending); await b.Exchange(LockPacket(peer, 4));
        var read = await b.Exchange(RawSmb.Read(peer, 1, 0, 0, 0, 0)); Check.Equal((byte)9, read[read[66]], "BRL checks remain enforced with read grants");
        await a.Exchange(RawSmb.Close(owner, 0, 0, 0)); await b.Exchange(RawSmb.Close(peer, 0, 0, 0));
    }
    static async Task RenameRead(bool durable, ushort dialect)
    {
        await using var f = new Fixture(durable); await f.Server.StartAsync();
        await using var a = await f.Connect(dialect, Guid.NewGuid()); await using var b = await f.Connect(dialect, Guid.NewGuid());
        var owner = Id(await a.Exchange(FullLease(dialect, 3, disposition: 3))); var peer = Id(await b.Exchange(FullLease(dialect, 3, 2)));
        var name = System.Text.Encoding.Unicode.GetBytes("renamed"); var data = new byte[20 + name.Length]; RawSmb.Put32(data, 16, (uint)name.Length); name.CopyTo(data, 20);
        var req = await Begin(a, SetPacket(owner, 10, data)); await Reply(a, req, 0x103); var notice = await Notice(b, 3, 1, 2);
        await b.Exchange(Ack(notice, 1)); await Reply(a, req); // The name changed; identity and FileIds survive.
        var renamed = RawSmb.Create("renamed", false, 0, 0, 0); RawSmb.Put32(renamed, 100, 1); renamed = P7cTests.Context(renamed, "RqLs", ContextData(dialect, 0, 2)); renamed[67] = 255;
        var grant = await b.Exchange(renamed); Grant(grant, 1); await b.Exchange(RawSmb.Close(Id(grant), 0, 0, 0));
        await a.Exchange(RawSmb.Close(owner, 0, 0, 0)); await b.Exchange(RawSmb.Close(peer, 0, 0, 0));
    }
    static byte[] ContextData(ushort dialect, uint state, ulong key, ushort epoch = 0)
    { var data = new byte[dialect < 0x300 ? 32 : 52]; RawSmb.Put64(data, 0, key); RawSmb.Put64(data, 8, ~key); RawSmb.Put32(data, 16, state); if (data.Length == 52) RawSmb.Put16(data, 48, epoch); return data; }
    static async Task VersionEpoch(bool durable, ushort dialect)
    {
        await using var f = new Fixture(durable); await f.Server.StartAsync(); var client = Guid.NewGuid();
        await using var a = await f.Connect(dialect, client); await using var b = await f.Connect(dialect, client);
        byte[] Request(ushort version, uint state, ushort epoch = 0)
        { var q = Classic(255, 3); return P7cTests.Context(q, "RqLs", ContextData(version, state, 1, epoch)); }
        var original = await a.Exchange(Request(0x210, 1)); var owner = Id(original); Check.Equal(32, Context(original).Length, "v1 established");
        var member = await b.Exchange(Request(dialect, 5, 100)); Grant(member, 5); Check.Equal(52, Context(member).Length, "MS-SMB2 3.3.5.9.11 returns v2 response to v2 CREATE");
        Check.Equal((ushort)0, RawSmb.U16(Context(member), 48), "common v1 lease does not adopt incoming v2 epoch");
        var contender = await Begin(b, FullLease(dialect, 3, 2)); await Reply(b, contender, 0x103);
        var notification = await Notice(a, 5, 1); Check.Equal((ushort)0, RawSmb.U16(notification, 66), "underlying common lease remains v1");
        await a.Exchange(Ack(notification, 1)); var other = Id(await Reply(b, contender)); await b.Exchange(RawSmb.Close(other, 0, 0, 0));
        await a.Exchange(RawSmb.Close(owner, 0, 0, 0)); await b.Exchange(RawSmb.Close(Id(member), 0, 0, 0));
        var fresh = await a.Exchange(Request(dialect, 1, 100)); owner = Id(fresh); Check.Equal((ushort)101, RawSmb.U16(Context(fresh), 48), "new v2 starts after final v1 member retires");
        await a.Exchange(RawSmb.Close(owner, 0, 0, 0));
        owner = Id(await a.Exchange(Classic(0))); await a.Exchange(RawSmb.Write(owner, [42], 0, 0, 0, 0)); await a.Exchange(LockPacket(owner, 0x12));
        var declined = await b.Exchange(Request(dialect, 1, 100)); Grant(declined, 0); Check.Equal((ushort)100, RawSmb.U16(Context(declined), 48), "declined promotion retains supplied epoch");
        await b.Exchange(RawSmb.Close(Id(declined), 0, 0, 0)); await a.Exchange(LockPacket(owner, 4)); await a.Exchange(RawSmb.Close(owner, 0, 0, 0));
    }
    static async Task Rearm(bool durable, ushort dialect)
    {
        await using var f = new Fixture(durable); await f.Server.StartAsync();
        await using var a = await f.Connect(dialect, Guid.NewGuid()); await using var b = await f.Connect(dialect, Guid.NewGuid());
        var owner = Id(await a.Exchange(Lease(dialect, 1, disposition: 3))); var peer = Id(await b.Exchange(Lease(dialect, 1, 2)));
        var write = await Begin(a, RawSmb.Write(owner, [1], 0, 0, 0, 0)); await Notice(b, 1, 0, 2); await Reply(a, write);
        var rearmed = await b.Exchange(Lease(dialect, 1, 2)); Grant(rearmed, 1); var extra = Id(rearmed);
        write = await Begin(b, RawSmb.Write(peer, [2], 0, 0, 0, 0)); await Notice(a, 1, 0); await Reply(b, write);
        write = await Begin(a, RawSmb.Write(owner, [3], 0, 0, 0, 0)); await Notice(b, 1, 0, 2); await Reply(a, write);
        foreach (var p in new[] { a, b })
        { var id = p == a ? owner : peer; var read = await p.Exchange(RawSmb.Read(id, 1, 0, 0, 0, 0)); Check.Equal((byte)3, read[read[66]], "alternating writes retain final byte"); }
        await b.Exchange(RawSmb.Close(extra, 0, 0, 0)); await a.Exchange(RawSmb.Close(owner, 0, 0, 0)); await b.Exchange(RawSmb.Close(peer, 0, 0, 0));
    }
}
