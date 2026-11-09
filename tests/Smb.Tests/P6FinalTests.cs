using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server;
using Smb.Server.Leases;
using Smb.Server.State;
using Smb.Testing;

static class P6FinalTests
{
    public static IEnumerable<(string Name, Func<Task> Run)> Cases()
    {
        yield return ("p6.v2.parent-key-context", Parent);
        yield return ("p6.capability.unadvertised-context", Unadvertised);
        yield return ("p6.policy.disable-preserves-existing-breaks", PolicyTransition);
        yield return ("p6.policy.enable-during-physical-write", EnableDuringWrite);
        yield return ("p6.manager.custom-directory-cannot-bypass", LegacyManager);
        foreach (var owner in new[] { false, true }) { var o = owner; yield return ($"p6.tcp.disconnect-owner-{o}", () => Disconnect(o)); }
        yield return ("p6.tcp.mixed-content-rename-copy-delete", MixedWorkflow);
        yield return ("p6.stress.resources", Stress);
        yield return ("p6.stress.ack-one-winner", ConcurrentAck);
        yield return ("p6.read.seeded-write-cache", Read);
        yield return ("p6.directory.no-cache-grants", Directory);
    }
    static async Task Unadvertised()
    { using var r = new P6Tests.Root(); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(); d.Connection.Dialect = SmbDialect.Smb210; d.Connection.ServerCapabilities |= Smb2Capabilities.Leasing; d.Connection.ServerCapabilities &= ~Smb2Capabilities.Leasing; var response = await d.Send(P6AdvancedTests.LeaseCreate(d.Create(), new LeaseKey(5, 6), LeaseState.ReadWrite)); Check.Equal((byte)0, response[66], "lease context cannot bypass negotiated server capability"); Check.Equal(0u, RawSmb.U32(response, 148), "unadvertised leasing context ignored"); }
    static async Task PolicyTransition()
    { using var r = new P6Tests.Root(); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(); var a = await d.Open(); var b = await d.Open(); d.Options.CacheCoordinator.RequestOplock(d.Session.Opens[a], OplockLevel.LevelII); var t = new RecordingTransport(); t.Attach(d.Connection); d.Options.FeaturePolicy = SmbFeaturePolicy.Restricted; await d.Send(RawSmb.Write(b, [42], 0, 0, 1, 42)); Check.That(t.Sends.Any(), "disabling new grants cannot bypass already-granted cache coherence"); Check.Equal(OplockLevel.None, d.Session.Opens[a].OplockLevel, "existing cache right revoked before mutation after profile switch"); }
    static async Task EnableDuringWrite()
    {
        using var r = new P6Tests.Root(); var store = new P6AdvancedTests.GatedStore(P6Tests.Local(r.Path)); await using var d = new P2Tests.Direct(store); var a = await d.Open(); var b = await d.Open(); var gate = new AsyncBarrier(); store.WriteBarrier = gate; var write = d.Send(RawSmb.Write(a, [42], 0, 0, 1, 42)); await gate.Entered.WaitAsync(Check.Timeout);
        try { d.Options.FeaturePolicy = P6Tests.Caching(); var grant = d.Options.CacheCoordinator.RequestOplock(d.Session.Opens[b], OplockLevel.Batch); Check.Equal(OplockLevel.None, grant.GrantedLevel, "enabling profile cannot grant caching over an already-admitted physical mutation"); }
        finally { gate.Release(); await write.WaitAsync(Check.Timeout); }
    }
    static async Task Parent()
    {
        using var r = new P6Tests.Root(); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(); d.Connection.Dialect = SmbDialect.Smb300; d.Connection.ServerCapabilities |= Smb2Capabilities.Leasing;
        var req = P6AdvancedTests.LeaseCreate(d.Create(), new LeaseKey(7, 8), LeaseState.ReadWriteHandle, true); var offset = (int)RawSmb.U32(req, 112) + 24; RawSmb.Put32(req, offset + 20, 4); new LeaseKey(9, 10).ToBytes().CopyTo(req, offset + 32);
        var b = await d.Send(req); Check.Equal(0u, RawSmb.U32(b, 8), "v2 parent context"); var ctx = (int)RawSmb.U32(b, 144); var data = ctx + RawSmb.U16(b, ctx + 10); Check.Equal(4u, RawSmb.U32(b, data + 20), "v2 response retains flagged parent key"); Check.That(b.AsSpan(data + 32, 16).SequenceEqual(new LeaseKey(9, 10).ToBytes()), "parent key bytes retained without granting directory lease");
    }
    sealed class Legacy : ILeaseManager
    {
        public LeaseGrant RequestLease(SmbOpen open, LeaseRequest request) => throw new InvalidOperationException("legacy grant bypass");
        public LeaseState Acknowledge(LeaseKey key, LeaseState state) => throw new InvalidOperationException("legacy ACK bypass");
        public void ReleaseOwner(SmbOpen open) { }
        public IReadOnlyList<LeaseBreak> BreakDirectoryLease(string key) => throw new InvalidOperationException("legacy directory bypass");
    }
    static async Task LegacyManager()
    { using var r = new P6Tests.Root(); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(); d.Options.LeaseManager = new Legacy(); var response = await d.Send(d.Create()); Check.Equal(0u, RawSmb.U32(response, 8), "supplied legacy manager cannot participate outside common cache gate"); }
    static Smb.Host.SmbServer Host(IFileStore store) => Smb.Host.SmbServerBuilder.Create().WithEndpoint(System.Net.IPAddress.Loopback, 0)
        .UseAuthentication(new Smb.Auth.Ntlm.NtlmSpnegoNegotiator(new Smb.Auth.InMemoryIdentityBackend().AddUser(HostFixture.Domain, HostFixture.User, HostFixture.Password)))
        .AddShare(new Share { Name = "P0", FileStore = store }).Configure(o => o.FeaturePolicy = P6Tests.Caching(true)).Build();
    static Task Connect(WireClient c, Smb.Host.SmbServer host) => c.ConnectAsync(host.Endpoint, HostFixture.Domain, HostFixture.User, HostFixture.Password, 0x300);
    static byte[] Bind(byte[] packet, WireClient c) { RawSmb.Put64(packet, 24, c.NextMessageId()); RawSmb.Put32(packet, 36, c.Tree); RawSmb.Put64(packet, 40, c.Session); return packet; }
    static async Task Disconnect(bool owner)
    {
        using var r = new P6Tests.Root(); File.WriteAllText(r.Path + "/a", "original"); await using var host = Host(P6Tests.Local(r.Path)); await host.StartAsync(); await using var a = new WireClient(); await using var b = new WireClient(); await Connect(a, host); await Connect(b, host);
        var req = RawSmb.Create("a", false, a.NextMessageId(), a.Session, a.Tree); req[67] = 9; var created = await a.ExchangeAsync(req, size: 89); Check.Equal((byte)9, created[66], "disconnect cache control"); var aid = (RawSmb.U64(created, 128), RawSmb.U64(created, 136));
        var conflict = RawSmb.Create("a", false, b.NextMessageId(), b.Session, b.Tree); RawSmb.Put32(conflict, 100, 4); await b.SendAsync(conflict); await a.ReceiveAsync(); var interim = await b.ReceiveAsync(); Check.Equal(0x103u, RawSmb.U32(interim, 8), "disconnect occurs during actual break wait"); Check.Equal("original", NativeHost.ReadAllText(r.Path + "/a"), "disconnect pre-ACK bytes");
        if (owner) { await a.DisposeAsync(); var final = await b.ReceiveAsync(); Check.Equal(0u, RawSmb.U32(final, 8), "owner disconnect revokes and permits waiter"); Check.Equal(0L, new FileInfo(r.Path + "/a").Length, "overwrite after owner disconnect"); }
        else { await b.DisposeAsync(); var pending = host.State.Connections.Values.SelectMany(c => c.PendingRequests.Values).SingleOrDefault(); if (pending != null) await pending.Finished.WaitAsync(Check.Timeout); Check.Equal("original", NativeHost.ReadAllText(r.Path + "/a"), "waiter disconnect leaves bytes unchanged"); await a.ExchangeAsync(Bind(P6Tests.Ack(aid, OplockLevel.None), a)); }
        await host.StopAsync(TimeSpan.FromSeconds(1)); Check.Equal(0, host.State.Options.CacheCoordinator.GrantCount, "disconnect grants retired"); Check.Equal(0, host.State.Options.CacheCoordinator.BreakingCount, "disconnect breaks retired");
    }
    static async Task MixedWorkflow()
    {
        using var r = new P6Tests.Root(); File.WriteAllText(r.Path + "/a", "original"); await using var host = Host(P6Tests.Local(r.Path)); await host.StartAsync(); await using var a = new WireClient(); await using var b = new WireClient(); await Connect(a, host); await Connect(b, host); var key = new LeaseKey(101, 102);
        var created = await a.ExchangeAsync(P6AdvancedTests.LeaseCreate(RawSmb.Create("a", false, a.NextMessageId(), a.Session, a.Tree), key, LeaseState.ReadWriteHandle, true), size: 89); Check.Equal((byte)255, created[66], "mixed lease grant");
        var req = RawSmb.Create("a", false, b.NextMessageId(), b.Session, b.Tree); req[67] = 9; RawSmb.Put32(req, 88, 0x10003); RawSmb.Put32(req, 100, 4); await b.SendAsync(req); var notification = await a.ReceiveAsync(); Check.Equal((ushort)44, RawSmb.U16(notification, 64), "classic open conflicts with lease in common domain"); Check.Equal(0x103u, RawSmb.U32(await b.ReceiveAsync(), 8), "mixed CREATE parks"); Check.Equal("original", NativeHost.ReadAllText(r.Path + "/a"), "mixed original preserved before ACK"); await a.ExchangeAsync(Bind(P6Tests.LeaseAck(key), a)); var final = await b.ReceiveAsync(); Check.Equal(0u, RawSmb.U32(final, 8), "mixed CREATE after ACK"); var bid = (RawSmb.U64(final, 128), RawSmb.U64(final, 136)); Check.Equal((byte)1, final[66], "MS-SMB2 3.3.5.9 falls back to compatible level II after destructive CREATE");
        await b.SendAsync(RawSmb.Write(bid, "changed!"u8.ToArray(), 0, b.NextMessageId(), b.Session, b.Tree));
        var invalidation = await b.ReceiveAsync(); Check.Equal((ushort)18, RawSmb.U16(invalidation, 12), "writing level-II handle receives its own invalidation");
        Check.Equal((ushort)24, RawSmb.U16(invalidation, 64), "classic read-cache notification"); Check.Equal((byte)0, invalidation[66], "read cache retired before physical WRITE");
        Check.Equal(bid, (RawSmb.U64(invalidation, 72), RawSmb.U64(invalidation, 80)), "self invalidation targets writing FileId");
        Check.Equal(0u, RawSmb.U32(await b.ReceiveAsync(), 8), "WRITE succeeds after no-ACK invalidation"); Check.That((await b.ReadAsync(bid, 8)).SequenceEqual("changed!"u8.ToArray()), "mixed second client reads latest bytes");
        var renamed = await b.ExchangeAsync(Bind(P6Tests.Rename(bid, "renamed"), b)); Check.Equal(0u, RawSmb.U32(renamed, 8), "mixed rename");
        var src = await b.CreateAsync("source"); await b.WriteAsync(src, "copied!!"u8.ToArray()); var resume = await b.ExchangeAsync(Bind(P5Tests.Ioctl(src, 0x140078, [], 32), b)); var copy = await b.ExchangeAsync(Bind(P6WorkflowTests.CopyPacket(bid, resume.AsSpan(112, 24).ToArray()), b)); Check.Equal(0u, RawSmb.U32(copy, 8), "mixed coordinated copy"); Check.Equal("copied!!", NativeHost.ReadAllText(r.Path + "/renamed"), "mixed copied content");
        await b.ExchangeAsync(Bind(P6Tests.Set(bid, 13, [1]), b)); await b.CloseAsync(bid); Check.That(File.Exists(r.Path + "/renamed"), "delete waits for other client open"); await a.CloseAsync((RawSmb.U64(created, 128), RawSmb.U64(created, 136))); Check.That(!File.Exists(r.Path + "/renamed"), "last close deletes coherent renamed object"); await b.CloseAsync(src);
    }
    static async Task Read()
    { using var r = new P6Tests.Root(); File.WriteAllText(r.Path + "/a", "original"); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(); var a = await d.Open(); var b = await d.Open(); var key = new LeaseKey(65, 66); d.Options.CacheCoordinator.RequestLease(d.Session.Opens[a], new LeaseRequest { Key = key, RequestedState = LeaseState.ReadWrite }); var t = new RecordingTransport(); t.Attach(d.Connection); var response = await d.Send(RawSmb.Read(b, 8, 0, 0, 1, 42)); Check.Equal(0x103u, RawSmb.U32(response, 8), "READ flushes foreign cached WRITE state"); var pending = d.Connection.PendingRequests.Values.Single(); await d.Send(P6Tests.LeaseAck(key)); await pending.Finished.WaitAsync(Check.Timeout); Check.That(pending.FinalBody.AsSpan(16).SequenceEqual("original"u8), "READ after cache flush"); }
    static async Task Directory()
    { using var r = new P6Tests.Root(); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(); d.Connection.Dialect = SmbDialect.Smb300; d.Connection.ServerCapabilities |= Smb2Capabilities.Leasing; var req = P6AdvancedTests.LeaseCreate(RawSmb.Create("", true, 0, 1, 42), new LeaseKey(1, 2), LeaseState.ReadHandle, true); var response = await d.Send(req); Check.Equal((byte)0, response[66], "no directory lease grant"); Check.Equal(0u, RawSmb.U32(response, 148), "no directory lease response context"); }
    static async Task Stress()
    {
        for (var i = 0; i < 32; i++)
        {
            using var r = new P6Tests.Root(); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(); var clock = new ManualClock(); d.Options.TimeProvider = clock; var a = await d.Open(); var b = await d.Open(); d.Options.CacheCoordinator.RequestOplock(d.Session.Opens[a], OplockLevel.Batch); var t = new RecordingTransport(); t.Attach(d.Connection); await d.Send(RawSmb.Write(b, [42], 0, 0, 1, 42)); var pending = d.Connection.PendingRequests.Values.Single();
            if (i % 2 == 0) await d.Send(P6Tests.Ack(a, OplockLevel.None)); else clock.Advance(TimeSpan.FromSeconds(36)); await pending.Finished.WaitAsync(Check.Timeout); foreach (var operation in d.Connection.OrdinaryRequests.Values) await operation.PhysicalFinished.WaitAsync(Check.Timeout); await d.Send(RawSmb.Close(a, 0, 1, 42)); await d.Send(RawSmb.Close(b, 0, 1, 42));
            Check.That(d.Session.Opens.IsEmpty && d.Connection.PendingRequests.IsEmpty && d.Connection.AsyncRequests.IsEmpty && d.Connection.OrdinaryRequests.IsEmpty, "stress maps retired"); Check.Equal(0, d.Options.CacheCoordinator.GrantCount, "stress grants"); Check.Equal(0, d.Options.CacheCoordinator.PhysicalScopeCount, "stress physical scopes"); Check.Equal(0, clock.ActiveTimers, "stress timers"); Check.Equal(0L, d.Options.Metrics.OpenHandles, "stress metrics"); Check.Equal(0, Smb2Dispatcher.ActiveNamespaceCount, "stress namespace gates");
        }
    }
    static async Task ConcurrentAck()
    {
        using var r = new P6Tests.Root(); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(); var a = await d.Open(); var b = await d.Open(); d.Options.CacheCoordinator.RequestOplock(d.Session.Opens[a], OplockLevel.Batch); var t = new RecordingTransport(); t.Attach(d.Connection); await d.Send(RawSmb.Write(b, [42], 0, 0, 1, 42)); var pending = d.Connection.PendingRequests.Values.Single(); var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); var tasks = Enumerable.Range(0, 32).Select(index => Task.Run(async () => { await start.Task; return d.Options.CacheCoordinator.Acknowledge(d.Session.Opens[a], OplockLevel.None, out _); })).ToArray(); start.SetResult(); var statuses = await Task.WhenAll(tasks); Check.Equal(1, statuses.Count(x => x == NtStatus.Success), "one ACK winner under concurrent delivery"); await pending.Finished.WaitAsync(Check.Timeout);
    }
}
