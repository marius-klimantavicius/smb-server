using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server;
using Smb.Server.Locking;
using Smb.Testing;

static class P6AdvancedTests
{
    public static IEnumerable<(string Name, Func<Task> Run)> Cases()
    {
        yield return ("p6.physical.prevent-grant-during-io", PhysicalGrant);
        yield return ("p6.prepared.reuses-ordinary-owner", Prepared);
        yield return ("p6.config.nonpositive-timeout", InvalidTimeout);
        yield return ("p6.capabilities.leasing", Capabilities);
        yield return ("p6.read-cache.benign-create", BenignCreate);
        yield return ("p6.lease.promote-same-key", Promote);
        yield return ("p6.lease.lock-conflict", LockConflict);
        yield return ("p6.lease.query-size-flush", QuerySize);
        yield return ("p6.grant.existing-foreign-lock", LockedGrant);
        yield return ("p6.lease.key-other-object-before-overwrite", KeyOtherObject);
        foreach (var level in new[] { OplockLevel.LevelII, OplockLevel.Exclusive, OplockLevel.Batch })
        { var l = level; yield return ($"p6.tcp.classic-{level}", () => Tcp(l, LeaseState.None, false)); }
        foreach (var state in new[] { LeaseState.Read, LeaseState.ReadWrite, LeaseState.ReadHandle, LeaseState.ReadWriteHandle })
        foreach (var v2 in new[] { false, true })
        { var st = state; var v = v2; yield return ($"p6.tcp.lease-{state}-v{(v2 ? 2 : 1)}", () => Tcp(OplockLevel.Lease, st, v)); }
        foreach (var mode in new[] { "timeout", "cancel", "owner-close", "waiter-close", "duplicate", "invalid" })
        { var m = mode; yield return ($"p6.lifecycle.{mode}", () => Lifecycle(m)); }
        yield return ("p6.backend.shared-access-no-grant", SharedBackend);
    }
    static async Task Prepared()
    {
        using var r = new P6Tests.Root(); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(); var id = await d.Open();
        var b = RawSmb.Write(id, [42], 0, 30, 1, 42); RawSmb.Sign(b, d.Session.SigningKey);
        Check.That(d.Dispatcher.TryBeginConcurrentFrame(d.Connection, b, false, out var frame), "prepared admission"); frame = d.Dispatcher.ReserveScope(frame);
        try { var response = await d.Dispatcher.ExecutePreparedFrameAsync(d.Connection, frame); Check.Equal(0u, RawSmb.U32(response, 8), "prepared operation reuses its already-admitted physical owner"); }
        finally { foreach (var request in d.Connection.OrdinaryRequests.Values) request.Dispose(); d.Connection.OrdinaryRequests.Clear(); }
    }
    static async Task BenignCreate()
    { using var r = new P6Tests.Root(); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(); var a = await d.Open(); var open = d.Session.Opens[a]; d.Options.OplockManager.RequestOplock(open, OplockLevel.LevelII); var req = d.Create(); RawSmb.Put32(req, 88, 1); await d.Send(req); Check.Equal(OplockLevel.LevelII, open.OplockLevel, "benign open preserves compatible cached reads"); }
    static async Task Promote()
    { using var r = new P6Tests.Root(); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(); var a = await d.Open(); var b = await d.Open(); var key = new LeaseKey(123, 456); d.Options.CacheCoordinator.RequestLease(d.Session.Opens[a], new LeaseRequest { Key = key, RequestedState = LeaseState.Read }); var grant = d.Options.CacheCoordinator.RequestLease(d.Session.Opens[b], new LeaseRequest { Key = key, RequestedState = LeaseState.ReadWrite }); Check.Equal(LeaseState.ReadWrite, grant.GrantedState, "superset same-key request promotes coherent lease"); }
    static async Task LockConflict()
    {
        using var r = new P6Tests.Root(); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(); var a = await d.Open(); var b = await d.Open(); var key = new LeaseKey(91, 92); d.Options.CacheCoordinator.RequestLease(d.Session.Opens[a], new LeaseRequest { Key = key, RequestedState = LeaseState.ReadWrite });
        var t = new RecordingTransport(); t.Attach(d.Connection); var req = RawSmb.Header(10, 48, 0, 1, 42); RawSmb.Put16(req, 64, 48); RawSmb.Put16(req, 66, 1); RawSmb.Put64(req, 72, b.P); RawSmb.Put64(req, 80, b.V); RawSmb.Put64(req, 96, 1); RawSmb.Put32(req, 104, 0x12);
        var response = await d.Send(req); Check.That(t.Sends.Any(x => RawSmb.U16(x.Message, 64) == 44), "cached WRITE and byte-range-lock rights revoked before foreign LOCK"); Check.Equal(0x103u, RawSmb.U32(response, 8), "LOCK waits for cache flush"); var pending = d.Connection.PendingRequests.Values.Single(); await d.Send(P6Tests.LeaseAck(key)); await pending.Finished.WaitAsync(Check.Timeout); Check.Equal(NtStatus.Success, pending.FinalStatus, "LOCK after ACK");
    }
    static async Task QuerySize()
    {
        using var r = new P6Tests.Root(); File.WriteAllText(r.Path + "/a", "original"); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(); var a = await d.Open(); var b = await d.Open(); var key = new LeaseKey(43, 44); d.Options.CacheCoordinator.RequestLease(d.Session.Opens[a], new LeaseRequest { Key = key, RequestedState = LeaseState.ReadWrite }); var t = new RecordingTransport(); t.Attach(d.Connection);
        var req = RawSmb.Header(16, 40, 0, 1, 42); RawSmb.Put16(req, 64, 41); req[66] = 1; req[67] = 5; RawSmb.Put32(req, 68, 100); RawSmb.Put64(req, 88, b.P); RawSmb.Put64(req, 96, b.V);
        var response = await d.Send(req); Check.That(t.Sends.Any(x => RawSmb.U16(x.Message, 64) == 44), "QUERY_INFO size waits for cached writes"); Check.Equal(0x103u, RawSmb.U32(response, 8), "size query parks"); var pending = d.Connection.PendingRequests.Values.Single(); await d.Send(P6Tests.LeaseAck(key)); await pending.Finished.WaitAsync(Check.Timeout); Check.Equal(NtStatus.Success, pending.FinalStatus, "size query after ACK");
    }
    static async Task LockedGrant()
    {
        using var r = new P6Tests.Root(); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(); var a = await d.Open(); var b = await d.Open();
        await d.Options.LockManager.ApplyAsync(d.Session.Opens[a], [new LockElement(0, 1, true, false)], true, default);
        var grant = d.Options.CacheCoordinator.RequestOplock(d.Session.Opens[b], OplockLevel.Batch); Check.Equal(OplockLevel.None, grant.GrantedLevel, "foreign byte locks prevent exclusive cached lock/data rights");
    }
    static async Task InvalidTimeout()
    { using var r = new P6Tests.Root(); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(); d.Options.OplockBreakTimeout = TimeSpan.Zero; var rejected = false; try { d.Options.Validate(); } catch (InvalidOperationException) { rejected = true; } Check.That(rejected, "cache profile rejects nonpositive break timeout"); }
    static async Task PhysicalGrant()
    { using var r = new P6Tests.Root(); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(); var a = await d.Open(); var b = await d.Open(); using var scope = await d.Options.CacheCoordinator.AcquireAsync([new FileIoRange(d.Session.Opens[a], 0, 1, true)]); var grant = d.Options.CacheCoordinator.RequestOplock(d.Session.Opens[b], OplockLevel.Batch); Check.Equal(OplockLevel.None, grant.GrantedLevel, "no cached grant while another open can still physically mutate"); }
    static async Task SharedBackend()
    { using var r = new P6Tests.Root(); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path, false)); d.Options.FeaturePolicy = P6Tests.Caching(); var req = d.Create(); req[67] = 9; var response = await d.Send(req); Check.Equal((byte)0, response[66], "profile cannot override missing backend coherence contract"); }
    internal static byte[] LeaseCreate(byte[] create, LeaseKey key, LeaseState state, bool v2 = false, ushort epoch = 7)
    {
        var offset = (create.Length + 7) & ~7; var b = new byte[offset + 24 + (v2 ? 52 : 32)]; create.CopyTo(b, 0); b[67] = 0xff;
        RawSmb.Put32(b, 112, (uint)offset); RawSmb.Put32(b, 116, (uint)(b.Length - offset)); RawSmb.Put16(b, offset + 4, 16); RawSmb.Put16(b, offset + 6, 4); RawSmb.Put16(b, offset + 10, 24); RawSmb.Put32(b, offset + 12, v2 ? 52u : 32u); "RqLs"u8.CopyTo(b.AsSpan(offset + 16)); key.ToBytes().CopyTo(b, offset + 24); RawSmb.Put32(b, offset + 40, (uint)state); if (v2) RawSmb.Put16(b, offset + 72, epoch); return b;
    }
    static async Task KeyOtherObject()
    {
        using var r = new P6Tests.Root(); File.WriteAllText(r.Path + "/b", "preserve"); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(); d.Connection.Dialect = SmbDialect.Smb210; d.Connection.ServerCapabilities |= Smb2Capabilities.Leasing;
        var key = new LeaseKey(5, 6); var a = await d.Send(LeaseCreate(d.Create(), key, LeaseState.ReadWrite)); Check.Equal((byte)255, a[66], "lease granted control");
        var req = LeaseCreate(d.Create("b"), key, LeaseState.ReadWrite); RawSmb.Put32(req, 100, 4); var b = await d.Send(req); Check.Equal(0xc000000du, RawSmb.U32(b, 8), "lease key cannot identify another object"); Check.Equal("preserve", NativeHost.ReadAllText(r.Path + "/b"), "invalid key rejected before truncation");
    }
    static async Task Capabilities()
    { using var r = new P6Tests.Root(); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(); var c = new Smb.Server.State.SmbConnection(); var req = RawSmb.Negotiate(); RawSmb.Put16(req, 100, 0x210); var b = await d.Dispatcher.ProcessMessageAsync(c, req); Check.That((RawSmb.U32(b, 88) & 2) != 0, "negotiated leasing agrees with coherent backend profile"); Check.That((RawSmb.U32(b, 88) & (8u | 16u | 32u)) == 0, "recovery and directory leases remain unavailable"); }
    static async Task Lifecycle(string mode)
    {
        using var r = new P6Tests.Root(); File.WriteAllText(r.Path + "/a", "original"); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(); var clock = new ManualClock(); d.Options.TimeProvider = clock; d.Options.OplockBreakTimeout = TimeSpan.FromSeconds(4);
        var a = await d.Open(); var b = await d.Open(); var owner = d.Session.Opens[a]; d.Options.OplockManager.RequestOplock(owner, OplockLevel.Batch); var t = new RecordingTransport(); t.Attach(d.Connection);
        var response = await d.Send(RawSmb.Write(b, [42], 0, 0, 1, 42)); Check.Equal(0x103u, RawSmb.U32(response, 8), "lifecycle starts with actual break wait"); var pending = d.Connection.PendingRequests.Values.Single();
        if (mode == "timeout") { Check.Equal(1, clock.ActiveTimers, "one break timer"); clock.Advance(TimeSpan.FromSeconds(3)); Check.Equal("original", NativeHost.ReadAllText(r.Path + "/a"), "no premature timeout"); clock.Advance(TimeSpan.FromSeconds(2)); }
        else if (mode == "cancel") pending.Cancel();
        else if (mode == "owner-close") await d.Send(RawSmb.Close(a, 0, 1, 42));
        else if (mode == "waiter-close") await d.Send(RawSmb.Close(b, 0, 1, 42));
        else if (mode == "invalid") { var ack = await d.Send(P6Tests.Ack(a, OplockLevel.Batch)); Check.Equal(0xc00000e3u, RawSmb.U32(ack, 8), "invalid ACK level revokes without upgrade"); }
        else { Check.Equal(0u, RawSmb.U32(await d.Send(P6Tests.Ack(a, OplockLevel.None)), 8), "first ACK"); Check.Equal(0xc0000184u, RawSmb.U32(await d.Send(P6Tests.Ack(a, OplockLevel.None)), 8), "duplicate ACK"); }
        await pending.Finished.WaitAsync(Check.Timeout);
        if (mode is "cancel" or "waiter-close") { Check.Equal(NtStatus.Cancelled, pending.FinalStatus, "cancel wins before backend admission"); Check.Equal("original", NativeHost.ReadAllText(r.Path + "/a"), "cancelled wait leaves original bytes"); await d.Send(P6Tests.Ack(a, OplockLevel.None)); }
        else Check.Equal(NtStatus.Success, pending.FinalStatus, "revoked wait proceeds");
        foreach (var physical in d.Connection.OrdinaryRequests.Values) await physical.PhysicalFinished.WaitAsync(Check.Timeout);
        Check.Equal(0, clock.ActiveTimers, "break timer retired"); Check.Equal(0, d.Options.CacheCoordinator.BreakingCount, "no stuck break"); Check.Equal(0, d.Options.CacheCoordinator.PhysicalScopeCount, "physical scopes retired");
    }
    static async Task Tcp(OplockLevel level, LeaseState state, bool v2)
    {
        using var r = new P6Tests.Root(); File.WriteAllText(r.Path + "/a", "original"); var store = new GatedStore(P6Tests.Local(r.Path));
        await using var host = Smb.Host.SmbServerBuilder.Create().WithEndpoint(System.Net.IPAddress.Loopback, 0)
            .UseAuthentication(new Smb.Auth.Ntlm.NtlmSpnegoNegotiator(new Smb.Auth.InMemoryIdentityBackend().AddUser(HostFixture.Domain, HostFixture.User, HostFixture.Password)))
            .AddShare(new Share { Name = "P0", FileStore = store }).Configure(o => o.FeaturePolicy = P6Tests.Caching()).Build();
        await host.StartAsync(); await using var a = new WireClient(); await using var b = new WireClient(); var dialect = v2 ? (ushort)0x300 : level == OplockLevel.Lease ? (ushort)0x210 : (ushort)0x202;
        await a.ConnectAsync(host.Endpoint, HostFixture.Domain, HostFixture.User, HostFixture.Password, dialect); await b.ConnectAsync(host.Endpoint, HostFixture.Domain, HostFixture.User, HostFixture.Password, dialect);
        var req = RawSmb.Create("a", false, a.NextMessageId(), a.Session, a.Tree); req[67] = (byte)level; var key = new LeaseKey(33, 44); if (level == OplockLevel.Lease) req = LeaseCreate(req, key, state, v2);
        var created = await a.ExchangeAsync(req, size: 89); Check.Equal((byte)level, created[66], "raw selected caching grant"); var aid = (RawSmb.U64(created, 128), RawSmb.U64(created, 136));
        if (level == OplockLevel.Lease) { var ctx = (int)RawSmb.U32(created, 144); var data = ctx + RawSmb.U16(created, ctx + 10); Check.Equal((uint)state, RawSmb.U32(created, data + 16), "exact lease rights"); if (v2) Check.Equal((ushort)8, RawSmb.U16(created, data + 48), "v2 acquisition epoch increment"); }
        var ackOnCreate = level is OplockLevel.Exclusive or OplockLevel.Batch || level == OplockLevel.Lease && state != LeaseState.Read;
        (ulong P, ulong V) bid;
        if (ackOnCreate)
        {
            var conflicting = RawSmb.Create("a", false, b.NextMessageId(), b.Session, b.Tree); RawSmb.Put32(conflicting, 100, 4); await b.SendAsync(conflicting);
            var createBreak = await a.ReceiveAsync(); Check.Equal((ushort)18, RawSmb.U16(createBreak, 12), "CREATE revokes exclusive cache before backend acquisition"); Check.Equal(0u, RawSmb.U32(createBreak, 36), "CREATE break TreeId zero");
            if (level == OplockLevel.Lease) { Check.Equal(0ul, RawSmb.U64(createBreak, 40), "lease CREATE break SessionId zero"); Check.Equal(1u, RawSmb.U32(createBreak, 68), "CREATE lease ACK flag"); Check.Equal(v2 ? (ushort)9 : (ushort)0, RawSmb.U16(createBreak, 66), "CREATE break epoch"); }
            var interim = await b.ReceiveAsync(); Check.Equal(0x103u, RawSmb.U32(interim, 8), "destructive CREATE pending before ACK"); Check.Equal("original", NativeHost.ReadAllText(r.Path + "/a"), "raw overwrite preserves bytes until ACK");
            var packet = level == OplockLevel.Lease ? P6Tests.LeaseAck(key) : P6Tests.Ack(aid, OplockLevel.None); RawSmb.Put64(packet, 24, a.NextMessageId()); RawSmb.Put64(packet, 40, a.Session); RawSmb.Put32(packet, 36, a.Tree); await a.ExchangeAsync(packet);
            var complete = await b.ReceiveAsync(); Check.Equal(0u, RawSmb.U32(complete, 8), "CREATE after ACK"); bid = (RawSmb.U64(complete, 128), RawSmb.U64(complete, 136));
        }
        else bid = await b.CreateAsync("a");
        var gate = new AsyncBarrier(); store.WriteBarrier = gate;
        await b.SendAsync(RawSmb.Write(bid, "changed!"u8.ToArray(), 0, b.NextMessageId(), b.Session, b.Tree));
        if (!ackOnCreate)
        {
        var notification = await a.ReceiveAsync(); Check.Equal((ushort)18, RawSmb.U16(notification, 12), "unsolicited break command"); Check.Equal(ulong.MaxValue, RawSmb.U64(notification, 24), "unsolicited MessageId"); Check.Equal(0u, RawSmb.U32(notification, 36), "break TreeId is zero");
        var ack = level is OplockLevel.Exclusive or OplockLevel.Batch || level == OplockLevel.Lease && state != LeaseState.Read;
        if (level == OplockLevel.Lease) { Check.Equal(0ul, RawSmb.U64(notification, 40), "lease notification SessionId zero"); Check.Equal(ack ? 1u : 0u, RawSmb.U32(notification, 68), "exact lease ACK flag"); Check.Equal(v2 ? (ushort)9 : (ushort)0, RawSmb.U16(notification, 66), "break epoch"); }
        }
        try
        {
            await gate.Entered.WaitAsync(Check.Timeout); Check.Equal(ackOnCreate ? "" : "original", NativeHost.ReadAllText(r.Path + "/a"), "backend barrier before physical mutation");
        }
        finally { gate.Release(); }
        var final = await b.ReceiveAsync(); Check.Equal(0u, RawSmb.U32(final, 8), "second client write succeeds");
        Check.That((await b.ReadAsync(bid, 8)).SequenceEqual("changed!"u8.ToArray()), "second client sees coherent content"); await b.CloseAsync(bid); await a.CloseAsync(aid); await host.StopAsync(TimeSpan.FromSeconds(1));
        Check.Equal(0, host.State.Options.CacheCoordinator.GrantCount, "TCP grant resources quiescent");
    }
    internal sealed class GatedStore(IFileStore inner) : IFileStore, ICacheCoherentFileStore, ISharedDeleteFileStore, INamedStreamStore
    {
        public ValueTask<FileStoreResult<IReadOnlyList<StreamInfo>>> QueryStreamsAsync(IFileHandle handle, CancellationToken ct = default) => ((INamedStreamStore)inner).QueryStreamsAsync(handle, ct);
        public ValueTask<FileStoreResult<FileCreateResult>> OpenNamedStreamAsync(string path, string stream, FileAccessIntent access, CreateDispositionIntent disposition, CancellationToken ct = default) => ((INamedStreamStore)inner).OpenNamedStreamAsync(path, stream, access, disposition, ct);
        public AsyncBarrier? WriteBarrier;
        public int RenameCalls;
        public AsyncBarrier? RenameBarrier;
        public bool HasExclusiveServerAccess => true;
        public ValueTask<FileIdentity?> ResolveIdentityAsync(string p, string s = "", CancellationToken ct = default) => ((IFileIdentityStore)inner).ResolveIdentityAsync(p, s, ct);
        public ValueTask<FileStoreResult<FileCreateResult>> CreateAsync(string p, FileAccessIntent a, CreateDispositionIntent d, bool dir, bool non, CancellationToken ct = default) => inner.CreateAsync(p, a, d, dir, non, ct);
        public ValueTask<FileStoreResult<int>> ReadAsync(IFileHandle h, long o, Memory<byte> b, CancellationToken ct = default) => inner.ReadAsync(h, o, b, ct);
        public async ValueTask<FileStoreResult<int>> WriteAsync(IFileHandle h, long o, ReadOnlyMemory<byte> b, CancellationToken ct = default) { if (WriteBarrier is { } gate) { WriteBarrier = null; await gate.WaitAsync(CancellationToken.None); } return await inner.WriteAsync(h, o, b, ct); }
        public ValueTask<FileStoreResult<IReadOnlyList<FileEntryInfo>>> QueryDirectoryAsync(IFileHandle h, string p, CancellationToken ct = default) => inner.QueryDirectoryAsync(h, p, ct);
        public ValueTask<NtStatus> SetEndOfFileAsync(IFileHandle h, long n, CancellationToken ct = default) => inner.SetEndOfFileAsync(h, n, ct);
        public async ValueTask<NtStatus> RenameAsync(IFileHandle h, string p, bool r, CancellationToken ct = default) { Interlocked.Increment(ref RenameCalls); if (RenameBarrier is { } gate) { RenameBarrier = null; await gate.WaitAsync(CancellationToken.None); } return await inner.RenameAsync(h, p, r, ct); }
        public ValueTask<NtStatus> SetDeleteOnCloseAsync(IFileHandle h, bool b, CancellationToken ct = default) => inner.SetDeleteOnCloseAsync(h, b, ct);
        public ValueTask<NtStatus> FlushAsync(IFileHandle h, CancellationToken ct = default) => inner.FlushAsync(h, ct);
    }
}
