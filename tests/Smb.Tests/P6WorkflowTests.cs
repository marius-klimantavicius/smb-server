using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server.Rpc;
using Smb.Server.State;
using Smb.Server.Witness;
using Smb.Testing;

static class P6WorkflowTests
{
    public static IEnumerable<(string Name, Func<Task> Run)> Cases()
    {
        yield return ("p6.profile.witness-preserved", Witness);
        yield return ("p6.copy.append-after-cache-flush", AppendAfterFlush);
        yield return ("p6.physical.early-cancel-response", EarlyCancel);
        yield return ("p6.create.cancel-before-publication", CancelCreate);
        yield return ("p6.grant.exclusive-with-other-open", ExclusiveOtherOpen);
        foreach (var cancel in new[] { false, true }) { var c = cancel; yield return ($"p6.copy.break-cancel-{c}", () => Copy(c)); }
        yield return ("p6.compound.create-write-close", Compound);
        yield return ("p6.teardown.pending-create-tree", PendingTree);
        yield return ("p6.physical.cancel-retains-scope", PhysicalCancel);
        yield return ("p6.alias.stable-conflict-domain", Alias);
        yield return ("p6.stream.independent-cache", Stream);
        yield return ("p6.lease.ack-client-scope", AckScope);
        yield return ("p6.lease.ack-duplicate-invalid", LeaseInvalidAck);
        yield return ("p6.lease.break-in-progress-context", LeaseBreakingContext);
        yield return ("p6.ack.batch-to-exclusive", BatchAck);
        yield return ("p6.ack.II-target-cannot-be-regranted", () => AckStatus(OplockLevel.LevelII, 0xc00000e2));
        yield return ("p6.ack.II-no-ack-required", NoAckRequired);
        yield return ("p6.ack.send-commit-before-other-waiter", AckBeforeSend);
        yield return ("p6.ack.lease-level-invalid-parameter", LeaseLevelAck);
    }
    static async Task ExclusiveOtherOpen()
    { using var r = new P6Tests.Root(); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(); await d.Open(); var req = d.Create(); req[67] = 9; var response = await d.Send(req); Check.That(response[66] != 9 && response[66] != 8, "MS-FSA exclusive acquisition cannot grant with another open"); }
    static async Task EarlyCancel()
    {
        using var r = new P6Tests.Root(); var store = new P6AdvancedTests.GatedStore(P6Tests.Local(r.Path)); await using var d = new P2Tests.Direct(store); d.Options.FeaturePolicy = P6Tests.Caching(); var id = await d.Open(); var gate = new AsyncBarrier(); store.WriteBarrier = gate;
        var write = d.Send(RawSmb.Write(id, [42], 0, 0, 1, 42)); await gate.Entered.WaitAsync(Check.Timeout); var physical = d.Connection.OrdinaryRequests.Values.Single(); physical.Cancel();
        try { await Task.WhenAny(write, Task.Delay(1000)); Check.That(write.IsCompleted, "cache profile preserves P4 early response cancellation while backend ignores token"); Check.Equal(0xc0000120u, RawSmb.U32(await write, 8), "early cancel status"); Check.That(!physical.PhysicalFinished.IsCompleted, "physical owner remains until backend completes"); }
        finally { gate.Release(); await write; await physical.PhysicalFinished.WaitAsync(Check.Timeout); }
    }
    static async Task CancelCreate()
    {
        await using var d = new P2Tests.Direct(); d.Options.FeaturePolicy = P6Tests.Caching(); var gate = new AsyncBarrier(); d.Store.Control.Enqueue("GetInfo", new OperationStep(Barrier: gate, IgnoreCancellation: true)); var create = d.Send(d.Create()); await gate.Entered.WaitAsync(Check.Timeout); var physical = d.Connection.OrdinaryRequests.Values.Single(); physical.Cancel();
        try { await Task.WhenAny(create, Task.Delay(1000)); Check.That(create.IsCompleted, "CREATE cancellation response does not wait for preparation backend"); }
        finally { gate.Release(); await create; await physical.PhysicalFinished.WaitAsync(Check.Timeout); }
        Check.That(d.Session.Opens.IsEmpty, "cancelled CREATE never publishes an unreturned open"); Check.Equal(0, d.Store.ActiveHandles, "cancelled CREATE rolls back acquired handle");
    }
    static async Task PendingTree()
    {
        using var r = new P6Tests.Root(); File.WriteAllText(r.Path + "/a", "original"); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(); var a = await d.Open(); d.Options.CacheCoordinator.RequestOplock(d.Session.Opens[a], OplockLevel.Batch); var t = new RecordingTransport(); t.Attach(d.Connection); var request = d.Create(); RawSmb.Put32(request, 100, 4); var response = await d.Send(request); Check.Equal(0x103u, RawSmb.U32(response, 8), "pending CREATE control"); var pending = d.Connection.PendingRequests.Values.Single();
        var close = d.Send(RawSmb.TreeDisconnect(0, 1, 42));
        try { await Task.WhenAny(close, Task.Delay(1000)); Check.That(close.IsCompleted, "tree disconnect cancels provisional CREATE before draining its tree reference"); Check.Equal("original", NativeHost.ReadAllText(r.Path + "/a"), "teardown never permits pending overwrite"); }
        finally { await d.Send(P6Tests.Ack(a, OplockLevel.None)); await close.WaitAsync(Check.Timeout); }
        Check.That(d.Session.Opens.IsEmpty && d.Connection.PendingRequests.IsEmpty, "teardown leaves no provisional open or pending response");
    }
    static async Task LeaseBreakingContext()
    {
        using var r = new P6Tests.Root(); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(); d.Connection.Dialect = SmbDialect.Smb210; d.Connection.ServerCapabilities |= Smb2Capabilities.Leasing; var a = await d.Open(); var b = await d.Open(); var key = new LeaseKey(71, 72); d.Options.CacheCoordinator.RequestLease(d.Session.Opens[a], new LeaseRequest { Key = key, RequestedState = LeaseState.ReadWrite }); var t = new RecordingTransport(); t.Attach(d.Connection); await d.Send(RawSmb.Write(b, [42], 0, 0, 1, 42)); var pending = d.Connection.PendingRequests.Values.Single();
        try { var created = await d.Send(P6AdvancedTests.LeaseCreate(d.Create(), key, LeaseState.ReadWrite)); var ctx = (int)RawSmb.U32(created, 144); var data = ctx + RawSmb.U16(created, ctx + 10); Check.Equal(2u, RawSmb.U32(created, data + 20), "same-key CREATE reports BREAK_IN_PROGRESS while retaining pending downgrade state"); }
        finally { await d.Send(P6Tests.LeaseAck(key)); await pending.Finished.WaitAsync(Check.Timeout); }
    }
    static async Task BatchAck() => await AckStatus(OplockLevel.Exclusive, 0);
    static async Task LeaseLevelAck() => await AckStatus(OplockLevel.Lease, 0xc000000d);
    static async Task AckStatus(OplockLevel level, uint status)
    { using var r = new P6Tests.Root(); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(); var a = await d.Open(); var b = await d.Open(); d.Options.CacheCoordinator.RequestOplock(d.Session.Opens[a], OplockLevel.Batch); var t = new RecordingTransport(); t.Attach(d.Connection); await d.Send(RawSmb.Write(b, [42], 0, 0, 1, 42)); var pending = d.Connection.PendingRequests.Values.Single(); var response = await d.Send(P6Tests.Ack(a, level)); await pending.Finished.WaitAsync(Check.Timeout); Check.Equal(status, RawSmb.U32(response, 8), "classic ACK uses specified level transition/status"); Check.Equal(OplockLevel.None, d.Session.Opens[a].OplockLevel, "ACK target cannot retain incompatible cached reads"); }
    static async Task NoAckRequired()
    {
        using var r = new P6Tests.Root(); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(); var a = await d.Open(); var b = await d.Open(); d.Options.CacheCoordinator.RequestOplock(d.Session.Opens[a], OplockLevel.LevelII); var gate = new AsyncBarrier(); var t = new RecordingTransport(); t.Attach(d.Connection); t.Control.Enqueue("Send", new OperationStep(Barrier: gate)); var write = d.Send(RawSmb.Write(b, [42], 0, 0, 1, 42)); await gate.Entered.WaitAsync(Check.Timeout);
        try { var response = await d.Send(P6Tests.Ack(a, OplockLevel.None)); Check.Equal(0xc0000184u, RawSmb.U32(response, 8), "II notification never admits an acknowledgment capable of releasing an uncommitted invalidation"); }
        finally { gate.Release(); var response = await write.WaitAsync(Check.Timeout); d.Connection.ResponseSent(response); foreach (var pending in d.Connection.PendingRequests.Values) await pending.Finished.WaitAsync(Check.Timeout); }
    }
    static async Task AckBeforeSend()
    {
        using var r = new P6Tests.Root(); File.WriteAllText(r.Path + "/a", "original"); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(); var a = await d.Open(); var b = await d.Open(); var c = await d.Open(); d.Options.CacheCoordinator.RequestOplock(d.Session.Opens[a], OplockLevel.Batch); var gate = new AsyncBarrier(); var t = new RecordingTransport(); t.Attach(d.Connection); t.Control.Enqueue("Send", new OperationStep(Barrier: gate)); var first = await d.Send(RawSmb.Write(b, [42], 0, 0, 1, 42)); await gate.Entered.WaitAsync(Check.Timeout);
        try { await d.Send(P6Tests.Ack(a, OplockLevel.None)); var second = await d.Send(RawSmb.Write(c, [43], 0, 0, 1, 42)); Check.Equal("original", NativeHost.ReadAllText(r.Path + "/a"), "ACK cannot release other conflict waiters before break sender commitment"); Check.Equal(0x103u, RawSmb.U32(second, 8), "second operation waits for actual invalidation send"); }
        finally { gate.Release(); foreach (var pending in d.Connection.PendingRequests.Values) await pending.Finished.WaitAsync(Check.Timeout); }
    }
    static async Task AppendAfterFlush()
    {
        using var r = new P6Tests.Root(); File.WriteAllText(r.Path + "/source", "source!!"); File.WriteAllText(r.Path + "/a", "original"); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(true); var src = await d.Open("source"); var dst = await d.Open(); var owner = await d.Open(); var resume = await d.Send(P5Tests.Ioctl(src, 0x140078, [], 32)); d.Options.CacheCoordinator.RequestOplock(d.Session.Opens[owner], OplockLevel.Batch); var t = new RecordingTransport(); t.Attach(d.Connection); var request = CopyPacket(dst, resume.AsSpan(112, 24).ToArray()); RawSmb.Put64(request, 160, ulong.MaxValue);
        var interim = await d.Send(request); Check.Equal(0x103u, RawSmb.U32(interim, 8), "append copy waits for dirty cache"); var pending = d.Connection.PendingRequests.Values.Single();
        var write = await d.Send(RawSmb.Write(owner, "grown"u8.ToArray(), 8, 0, 1, 42));
        if (RawSmb.U32(write, 8) == 0x103)
        {
            var asyncId = RawSmb.U64(write, 32);
            bool Final(RecordedSend send) => RawSmb.U16(send.Message, 12) == 9 && RawSmb.U64(send.Message, 32) == asyncId;
            while (!t.Sends.Any(Final)) await t.WaitForSendAsync();
            write = t.Sends.Single(Final).Message;
        }
        Check.Equal(0u, RawSmb.U32(write, 8), "owner WRITE final success before inspecting host bytes");
        Check.Equal(5u, RawSmb.U32(write, 68), "owner WRITE completed full cached flush");
        Check.Equal("originalgrown", NativeHost.ReadAllText(r.Path + "/a"), "owner flush extends EOF before ACK"); await d.Send(P6Tests.Ack(owner, OplockLevel.None)); await pending.Finished.WaitAsync(Check.Timeout); Check.Equal(NtStatus.Success, pending.FinalStatus, "append copy succeeds"); Check.Equal("originalgrownsource!!", NativeHost.ReadAllText(r.Path + "/a"), "append EOF is resolved after cache flush instead of overwriting flushed growth");
    }
    static async Task Witness()
    {
        await using var d = new P2Tests.Direct { CommitResponses = false }; d.Options.FeaturePolicy = P6Tests.Caching(); var id = await d.Open(); var store = d.State.WitnessRegistrations; var reg = store.Add(d.Connection.ConnectionId, 65537, null, null, null, null);
        d.Session.Opens[id].Pipe = new RpcPipe(new Smb.Server.Witness.WitnessEndpoint(store, d.Connection.ConnectionId, () => Array.Empty<Smb.Server.Witness.WitnessInterfaceInfo>()));
        var pdu = new byte[44]; pdu[0] = 5; pdu[3] = 3; pdu[4] = 16; RawSmb.Put16(pdu, 8, 44); RawSmb.Put32(pdu, 12, 7); RawSmb.Put32(pdu, 16, 20); RawSmb.Put16(pdu, 22, 3); reg.ContextHandle().CopyTo(pdu, 24);
        var t = new RecordingTransport(); t.Attach(d.Connection); var response = await d.Send(P5Tests.Ioctl(id, 0x11c017, pdu, 4096)); Check.Equal(0x103u, RawSmb.U32(response, 8), "cache profile preserves Witness pending ownership"); var pending = d.Connection.PendingRequests.Values.Single();
        reg.Notifications.Push(new WitnessNotification { Type = Smb.Server.Witness.WitnessNotifyType.ResourceChange, MessageCount = 1, MessageBuffer = [1] }); Check.Equal(0, t.Sends.Length, "Witness final still waits for actual sender"); await t.SendAsync(response, false); await pending.Finished.WaitAsync(Check.Timeout);
    }
    internal static byte[] CopyPacket((ulong P, ulong V) id, byte[] key)
    { var data = new byte[56]; key.CopyTo(data, 0); RawSmb.Put32(data, 24, 1); RawSmb.Put32(data, 48, 8); return P5Tests.Ioctl(id, 0x1440f2, data, 12); }
    static async Task Copy(bool cancel)
    {
        using var r = new P6Tests.Root(); File.WriteAllText(r.Path + "/source", "source!!"); File.WriteAllText(r.Path + "/a", "original"); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(true);
        var src = await d.Open("source"); var dst = await d.Open(); var owner = await d.Open(); var keyResponse = await d.Send(P5Tests.Ioctl(src, 0x140078, [], 32)); Check.Equal(0u, RawSmb.U32(keyResponse, 8), "caching copy variant resume key"); var key = keyResponse.AsSpan(112, 24).ToArray();
        d.Options.CacheCoordinator.RequestOplock(d.Session.Opens[owner], OplockLevel.Batch); var t = new RecordingTransport(); t.Attach(d.Connection);
        var response = await d.Send(CopyPacket(dst, key)); Check.Equal(0x103u, RawSmb.U32(response, 8), "COPY participates in common break wait"); Check.Equal("original", NativeHost.ReadAllText(r.Path + "/a"), "copy preserves destination until ACK"); var pending = d.Connection.PendingRequests.Values.Single();
        if (cancel)
        {
            pending.Cancel(); await pending.Finished.WaitAsync(Check.Timeout); Check.Equal(NtStatus.Cancelled, pending.FinalStatus, "copy wait cancellation response");
            var physical = d.Connection.OrdinaryRequests.Values.Select(x => x.PhysicalFinished).ToArray();
            // Logical cancellation must stop an unadmitted copy, rather than wait for owner's ACK.
            await Task.WhenAll(physical).WaitAsync(Check.Timeout); Check.That(physical.All(x => x.IsCompleted), "cancelled COPY retires its pre-mutation break wait");
        }
        await d.Send(P6Tests.Ack(owner, OplockLevel.None)); await pending.Finished.WaitAsync(Check.Timeout); foreach (var physical in d.Connection.OrdinaryRequests.Values) await physical.PhysicalFinished.WaitAsync(Check.Timeout);
        Check.Equal(cancel ? "original" : "source!!", NativeHost.ReadAllText(r.Path + "/a"), "COPY bytes after decision");
    }
    internal static byte[] Join(params byte[][] packets)
    { var result = new List<byte>(); for (var i = 0; i < packets.Length; i++) { var b = packets[i]; Array.Resize(ref b, i < packets.Length - 1 ? (b.Length + 7) & ~7 : b.Length); RawSmb.Put64(b, 24, (ulong)(20 + i)); RawSmb.Put32(b, 20, i < packets.Length - 1 ? (uint)b.Length : 0); if (i > 0) { RawSmb.Put32(b, 16, 4); RawSmb.Put32(b, 36, uint.MaxValue); RawSmb.Put64(b, 40, ulong.MaxValue); } RawSmb.Sign(b, new byte[16]); result.AddRange(b); } return result.ToArray(); }
    static async Task Compound()
    {
        using var r = new P6Tests.Root(); File.WriteAllText(r.Path + "/a", "original"); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(); var owner = await d.Open(); d.Options.CacheCoordinator.RequestOplock(d.Session.Opens[owner], OplockLevel.Batch); var t = new RecordingTransport(); t.Attach(d.Connection);
        var create = d.Create(); RawSmb.Put32(create, 100, 4); var chain = Join(create, RawSmb.Write((ulong.MaxValue, ulong.MaxValue), "changed!"u8.ToArray(), 0, 0, 1, 42), RawSmb.Close((ulong.MaxValue, ulong.MaxValue), 0, 1, 42));
        var interim = await d.Dispatcher.ProcessMessageAsync(d.Connection, chain); Check.Equal(0x103u, RawSmb.U32(interim, 8), "compound CREATE parks"); Check.Equal("original", NativeHost.ReadAllText(r.Path + "/a"), "compound CREATE does not truncate before ACK"); var pending = d.Connection.PendingRequests.Values.ToArray(); Check.Equal(3, pending.Length, "one P4 owner per related request"); await d.Send(P6Tests.Ack(owner, OplockLevel.None)); Check.That(t.Sends.All(x => RawSmb.U16(x.Message, 12) == 18), "no final before compound interim sent");
        await t.SendAsync(interim.ToArray(), false); await Task.WhenAll(pending.Select(x => x.Finished)).WaitAsync(Check.Timeout); Check.That(pending.All(x => x.FinalStatus == NtStatus.Success), "related continuation results"); Check.Equal("changed!", NativeHost.ReadAllText(r.Path + "/a"), "related WRITE after actual CREATE completion"); Check.Equal(1, d.Session.Opens.Count, "related close releases created handle");
    }
    static async Task PhysicalCancel()
    {
        using var r = new P6Tests.Root(); var store = new P6AdvancedTests.GatedStore(P6Tests.Local(r.Path)); await using var d = new P2Tests.Direct(store); d.Options.FeaturePolicy = P6Tests.Caching(); var a = await d.Open(); var b = await d.Open(); var gate = new AsyncBarrier(); store.WriteBarrier = gate;
        var write = d.Send(RawSmb.Write(a, [42], 0, 0, 1, 42)); await gate.Entered.WaitAsync(Check.Timeout); var physical = d.Connection.OrdinaryRequests.Values.Single(); physical.Cancel();
        try { Check.That(d.Options.CacheCoordinator.PhysicalScopeCount > 0, "cancel does not retire admitted physical scope"); Check.Equal(OplockLevel.None, d.Options.CacheCoordinator.RequestOplock(d.Session.Opens[b], OplockLevel.Batch).GrantedLevel, "no grant until actual backend completion"); }
        finally { gate.Release(); await write.WaitAsync(Check.Timeout); await physical.PhysicalFinished.WaitAsync(Check.Timeout); }
        Check.Equal(0, d.Options.CacheCoordinator.PhysicalScopeCount, "scope released on actual completion");
    }
    static async Task Alias()
    {
        using var r = new P6Tests.Root(); File.WriteAllText(r.Path + "/a", "original"); NativeHost.HardLink(r.Path + "/a", r.Path + "/alias"); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(); var a = await d.Open(); var b = await d.Open("alias"); d.Options.CacheCoordinator.RequestOplock(d.Session.Opens[a], OplockLevel.LevelII); var t = new RecordingTransport(); t.Attach(d.Connection); await d.Send(RawSmb.Write(b, [42], 0, 0, 1, 42)); Check.That(t.Sends.Any(), "hard-link alias shares cache conflict domain"); Check.Equal(OplockLevel.None, d.Session.Opens[a].OplockLevel, "alias revokes cached reads");
    }
    static async Task Stream()
    {
        using var r = new P6Tests.Root(); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(); var a = await d.Open(); var b = await d.Open("a:stream"); d.Options.CacheCoordinator.RequestOplock(d.Session.Opens[a], OplockLevel.LevelII); var t = new RecordingTransport(); t.Attach(d.Connection); await d.Send(RawSmb.Write(b, [42], 0, 0, 1, 42)); Check.Equal(0, t.Sends.Length, "alternate stream has distinct cache domain"); Check.Equal(OplockLevel.LevelII, d.Session.Opens[a].OplockLevel, "base stream grant retained");
    }
    static async Task AckScope()
    {
        using var r = new P6Tests.Root(); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(); var a = await d.Open(); var key = new LeaseKey(33, 34); d.Options.CacheCoordinator.RequestLease(d.Session.Opens[a], new LeaseRequest { Key = key, RequestedState = LeaseState.ReadWrite }); var other = new SmbConnection { ClientGuid = Enumerable.Repeat((byte)4, 16).ToArray() };
        Check.Equal(NtStatus.ObjectNameNotFound, d.Options.CacheCoordinator.Acknowledge(other, key, LeaseState.None, out _), "same lease key is scoped to ClientGuid");
    }
    static async Task LeaseInvalidAck()
    {
        using var r = new P6Tests.Root(); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(); var a = await d.Open(); var b = await d.Open(); var key = new LeaseKey(51, 52); d.Options.CacheCoordinator.RequestLease(d.Session.Opens[a], new LeaseRequest { Key = key, RequestedState = LeaseState.ReadWrite }); var t = new RecordingTransport(); t.Attach(d.Connection); await d.Send(RawSmb.Write(b, [42], 0, 0, 1, 42)); var pending = d.Connection.PendingRequests.Values.Single();
        Check.Equal(0xc00000d0u, RawSmb.U32(await d.Send(P6Tests.LeaseAck(key, LeaseState.Read)), 8), "ACK cannot retain rights beyond NONE target"); Check.That(!pending.Finished.IsCompleted, "invalid ACK does not release mutation"); await d.Send(P6Tests.LeaseAck(key)); await pending.Finished.WaitAsync(Check.Timeout); Check.Equal(0xc0000001u, RawSmb.U32(await d.Send(P6Tests.LeaseAck(key)), 8), "duplicate lease ACK rejected");
    }
}
