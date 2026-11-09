using Smb.Server.State;
using Smb.Testing;

internal static partial class UpstreamSambaMoreTests
{
    static IEnumerable<(string Name, Func<Task> Run)> LeaseCompletionCases()
    {
        yield return ("upstream.samba.more.lease.shared-members-one-break", LeaseSharedMembers);
        yield return ("upstream.samba.more.lease.v2.share-failure-two-breaks", LeaseTwoBreaks);
        yield return ("upstream.samba.more.lease.v2.cross-session-ack", CrossSessionLeaseAck);
        foreach (var state in new uint[] { 3, 7 }) yield return ($"upstream.samba.more.lease.unlink-sequence.{state}", () => LeaseUnlink(state));
        foreach (var mode in new[] { "tree", "logoff", "disconnect" }) yield return ($"upstream.samba.more.lease.initial-delete.{mode}", () => LeaseInitialDelete(mode));
        foreach (var closeTarget in new[] { false, true }) yield return ($"upstream.samba.more.lease.replace-target.{closeTarget}", () => LeaseReplaceTarget(closeTarget));
        foreach (var row in new (bool H1, bool C1, bool H2, bool C2, int Extra)[]
        { (true,true,true,true,0),(false,false,false,false,0),(true,false,true,true,0),(true,true,true,false,0),(true,true,false,false,0),(false,false,true,true,0),(true,true,true,true,1),(true,true,true,true,2) })
            yield return ($"upstream.samba.more.lease.rename-directory.{row.H1}.{row.C1}.{row.H2}.{row.C2}.{row.Extra}", () => LeaseRenameDirectory(row));
        yield return ("upstream.samba.more.lock.parallel-open-lock-progress", ParallelOpenLock);
        yield return ("upstream.samba.more.lock.pending-unlock-handoff", PendingLockHandoff);
        yield return ("upstream.samba.more.lease.three-client-range-locks", ThreeLeaseLocks);
        foreach (var overwrite in new[] { false, true }) yield return ($"upstream.samba.more.lease.lock-before-peer-open.{overwrite}", () => LockBeforePeer(overwrite));
        yield return ("upstream.samba.more.lease.epoch-with-declined-read-cache", DeclinedLeaseEpoch);
        yield return ("upstream.samba.more.lease.cross-version-epoch-lifetime", CrossVersionEpoch);
    }
    static async Task<byte[]> OtherComplete(CacheFixture f, SmbSession s, RecordingTransport transport, byte[] request)
    {
        var start = f.Transport.Sends.Length; var pending = await Send(f, s, request); if (RawSmb.U32(pending, 8) != 0x103) return pending;
        var seen = start;
        while (true)
        {
            var sends = f.Transport.Sends;
            while (seen < sends.Length)
            {
                var b = sends[seen++].Message;
                if (RawSmb.U16(b, 12) == 18 && RawSmb.U16(b, 64) == 44 && (RawSmb.U32(b, 68) & 1) != 0)
                    Status(await f.D.Send(LeaseAck(RawSmb.U64(b, 72), RawSmb.U32(b, 92))), Ok, "primary owner ACK while other session's command is pending");
                if (RawSmb.U16(b, 12) == 18 && RawSmb.U16(b, 64) == 24)
                {
                    var owner = (RawSmb.U64(b, 72), RawSmb.U64(b, 80));
                    if (f.Oplocks.TryGetValue(owner, out var old) && old is 8 or 9) Status(await f.D.Send(P6Tests.Ack(owner, (Smb.Protocol.Enums.OplockLevel)b[66])), Ok, "primary classic owner ACK for other established session");
                    f.Oplocks[owner] = b[66];
                }
            }
            var final = transport.Sends.LastOrDefault(x => RawSmb.U16(x.Message, 12) == RawSmb.U16(request, 12) && (RawSmb.U32(x.Message, 16) & 2) != 0 && RawSmb.U64(x.Message, 32) == RawSmb.U64(pending, 32));
            if (final != null) return final.Message; await transport.WaitForSendAsync().WaitAsync(Check.Timeout);
        }
    }
    static async Task LeaseSharedMembers()
    {
        await using var f = new CacheFixture(); var d = f.D; var a = await d.Send(Lease(Create(disposition: 3), 3)); var first = Id(a);
        LeaseState(a, 3, 1); var b = await d.Send(Lease(Create(), 7)); var member = Id(b); LeaseState(b, 7, 1);
        var before = f.Transport.Sends.Length; var other = await Complete(f, Lease(Create(), 7, 2)); LeaseState(other, 3, 2);
        var breaks = f.Transport.Sends.Skip(before).Where(x => RawSmb.U16(x.Message, 12) == 18).ToArray(); Check.Equal(1, breaks.Length, "two same-key members receive one common lease break");
        Check.Equal(1ul, RawSmb.U64(breaks[0].Message, 72), "break targets common key"); Check.Equal(7u, RawSmb.U32(breaks[0].Message, 88), "upgraded common state breaks from RWH"); Check.Equal(3u, RawSmb.U32(breaks[0].Message, 92), "competing reader downgrade to RH");
        await Close(d, first); await Close(d, member); await Close(d, Id(other));
        first = Id(await d.Send(Lease(Create(), 1))); var classic = await OpenOplock(f, 1, disposition: 1); Check.Equal((byte)1, classic[66], "READ lease coexists with level II");
        before = f.Transport.Sends.Length; var overwrite = Id(await Complete(f, Create(disposition: 5))); await Write(d, overwrite, Payload);
        breaks = f.Transport.Sends.Skip(before).Where(x => RawSmb.U16(x.Message, 12) == 18).ToArray();
        Check.Equal(1, breaks.Count(x => RawSmb.U16(x.Message, 64) == 44), "one read lease invalidation"); Check.Equal(1, breaks.Count(x => RawSmb.U16(x.Message, 64) == 24), "one level-II invalidation");
        await Data(d, first, Payload);
    }
    static async Task LeaseTwoBreaks()
    {
        await using var f = new CacheFixture(); var d = f.D; var original = await d.Send(Lease(Create(disposition: 3), 7, 1, true, 0x11)); Id(original);
        Check.Equal((ushort)0x12, RawSmb.U16(Context(original, "RqLs")!, 48), "initial v2 lease epoch increment");
        var start = f.Transport.Sends.Length; Status(await Complete(f, Lease(Create(share: 1), 7, 2, true, 0x22)), Sharing, "share failure after HANDLE break");
        var first = f.Transport.Sends.Skip(start).Single(x => RawSmb.U16(x.Message, 12) == 18).Message;
        Check.Equal(7u, RawSmb.U32(first, 88), "first break current RWH"); Check.Equal(5u, RawSmb.U32(first, 92), "source share conflict only removes HANDLE"); Check.Equal((ushort)0x13, RawSmb.U16(first, 66), "first break increments epoch");
        start = f.Transport.Sends.Length; var second = await Complete(f, Lease(Create(), 7, 2, true, 0x22)); LeaseState(second, 3, 2);
        var again = f.Transport.Sends.Skip(start).Single(x => RawSmb.U16(x.Message, 12) == 18).Message; Check.Equal(5u, RawSmb.U32(again, 88), "second break starts from RW"); Check.Equal(1u, RawSmb.U32(again, 92), "second contention removes WRITE"); Check.Equal((ushort)0x14, RawSmb.U16(again, 66), "second break epoch advances once");
    }
    static async Task CrossSessionLeaseAck()
    {
        await using var f = new CacheFixture(); var d = f.D; Id(await d.Send(Lease(Create(disposition: 3), 7, 1, true, 0x4711)));
        var s = Session(f); var transport = new RecordingTransport(); transport.Attach(s.Connection); var pending = await Send(f, s, Lease(Create(), 7, 2, true, 0x11)); Status(pending, 0x103, "foreign lease open pends");
        var notification = f.Transport.Sends.Single(x => RawSmb.U16(x.Message, 12) == 18).Message;
        Check.Equal((ushort)0x4713, RawSmb.U16(notification, 66), "cross-session break increments owner's epoch"); Check.Equal(3u, RawSmb.U32(notification, 92), "source cross-session RWH downgrade target RH");
        Status(await Send(f, s, LeaseAck(1, 3)), Ok, "same client GUID can ACK lease on a different session");
        var final = await AsyncFinal(transport, pending); LeaseState(final, 3, 2); Check.Equal((ushort)0x12, RawSmb.U16(Context(final, "RqLs")!, 48), "second key has its independent epoch");
    }
    static async Task LeaseUnlink(uint initial)
    {
        await using var f = new CacheFixture(); var d = f.D; var first = Id(await d.Send(Lease(Create(disposition: 3), initial))); await Write(d, first, Payload);
        var s = Session(f); s.Connection.ClientGuid = Guid.NewGuid().ToByteArray(); var transport = new RecordingTransport(); transport.Attach(s.Connection);
        var second = await OtherComplete(f, s, transport, Lease(Create(), initial, 2)); var peer = Id(second); LeaseState(second, 3, 2);
        await Send(f, s, RawSmb.Close(peer, 0, 1, 42)); var start = f.Transport.Sends.Length;
        peer = Id(await OtherComplete(f, s, transport, Create(access: 0x10000)));
        Status(await OtherComplete(f, s, transport, Set(peer, 13, [1])), Ok, "foreign unlink disposition after closing foreign lease member");
        Status(await Send(f, s, RawSmb.Close(peer, 0, 1, 42)), Ok, "close delete owner");
        Check.Equal(1, f.Transport.Sends.Skip(start).Count(x => RawSmb.U16(x.Message, 12) == 18), "unlink removes HANDLE caching once"); await Data(d, first, Payload);
        await Close(d, first); Status(await d.Send(Create()), Missing, "final original handle close removes unlinked name");
        var recreated = await d.Send(Lease(Create(disposition: 3), 3)); first = Id(recreated); LeaseState(recreated, 3, 1); Check.Equal(2u, RawSmb.U32(recreated, 68), "recreated path is a new object");
        peer = Id(await OtherComplete(f, s, transport, Lease(Create(), 3, 2))); start = f.Transport.Sends.Length;
        Status(await OtherComplete(f, s, transport, Set(peer, 13, [1])), Ok, "delete disposition on already-leased peer invalidates foreign HANDLE");
        Check.Equal(1, f.Transport.Sends.Skip(start).Count(x => RawSmb.U16(x.Message, 12) == 18), "direct disposition has one foreign break");
    }
    static async Task LeaseInitialDelete(string mode)
    {
        await using var f = new CacheFixture(); var d = f.D; var owner = Id(await d.Send(Lease(Create(disposition: 3), 3, 1, true)));
        var s = Session(f); var transport = new RecordingTransport(); transport.Attach(s.Connection); var b = Create(); RawSmb.Put32(b, 104, 0x1040);
        Id(await OtherComplete(f, s, transport, b));
        if (mode == "tree") Status(await Send(f, s, RawSmb.TreeDisconnect(0, 1, 42)), Ok, "TDIS initial-delete owner");
        else if (mode == "logoff") { var logoff = RawSmb.Header(2, 4, 0, 1); RawSmb.Put16(logoff, 64, 4); Status(await Send(f, s, logoff), Ok, "LOGOFF initial-delete owner"); }
        else await d.Dispatcher.OnConnectionClosedAsync(s.Connection);
        Check.Equal(1, f.Transport.Sends.Count(x => RawSmb.U16(x.Message, 12) == 18), "initial delete releases HANDLE cache once");
        await Close(d, owner); Status(await d.Send(Create()), Missing, "initial-delete teardown removes name after last original lease close");
    }
    static async Task LeaseReplaceTarget(bool closeTarget)
    {
        await using var f = new CacheFixture(); var d = f.D; var source = Id(await d.Send(Lease(Create(disposition: 3), 7, 1, true))); await Write(d, source, Payload);
        var target = Id(await d.Send(Lease(Create("target", 3), 7, 2, true))); await Write(d, target, [9]); var start = f.Transport.Sends.Length;
        var result = await Complete(f, Rename(source, "target", true), async b => { if (closeTarget && RawSmb.U64(b, 72) == 2) await Close(d, target); }, b => closeTarget && RawSmb.U64(b, 72) == 2);
        Status(result, closeTarget ? Ok : Denied, "source Windows rename-replacement policy depends on target close during HANDLE break");
        var breaks = f.Transport.Sends.Skip(start).Where(x => RawSmb.U16(x.Message, 12) == 18).ToArray(); Check.Equal(1, breaks.Length, "one target-only HANDLE downgrade"); Check.Equal(2ul, RawSmb.U64(breaks[0].Message, 72), "replacement breaks target key");
        if (!closeTarget) { var n = f.Transport.Sends.Length; Status(await Complete(f, Rename(source, "target", true)), Denied, "second replacement still denied with target open"); Check.Equal(n, f.Transport.Sends.Length, "already broken HANDLE state produces no new break"); }
        else { Status(await d.Send(Create()), Missing, "source name removed after replacement"); await Data(d, source, Payload); }
    }
    static async Task LeaseRenameDirectory((bool H1, bool C1, bool H2, bool C2, int Extra) row)
    {
        await using var f = new CacheFixture(); var d = f.D; var directory = await Open(d, "dir", 3, directory: true); var ids = new Dictionary<ulong,(ulong P,ulong V)>();
        foreach (var item in new[] { (Key:1ul, H:row.H1), (Key:2ul, H:row.H2) })
        { var request = Create("dir\\file" + item.Key, 3); if (item.H) request = Lease(request, 3, item.Key, true); ids[item.Key] = Id(await d.Send(request)); }
        var extra = false;
        var result = await Complete(f, Rename(directory, "renamed"), async b =>
        {
            var key = RawSmb.U64(b, 72); if (key is not (1 or 2)) return;
            if (key == 1 ? row.C1 : row.C2) await Close(d, ids[key]);
            if (!extra && row.Extra != 0)
            { extra = true; var request = Create("dir\\file3", 3); if (row.Extra == 1) request = Lease(request, 3, 3, true); Id(await d.Send(request)); }
        }, b => RawSmb.U64(b, 72) == 1 ? row.C1 : RawSmb.U64(b, 72) == 2 && row.C2);
        var success = row.H1 && row.C1 && row.H2 && row.C2 && row.Extra == 0;
        Status(result, success ? Ok : Denied, "source directory rename requires descendant handles to close; concurrent new descendant participates");
        if (success) { Status(await d.Send(Create("dir", directory: true)), Missing, "old directory name gone"); await Close(d, await Open(d, "renamed\\file1")); await Close(d, await Open(d, "renamed\\file2")); }
    }
    static async Task ParallelOpenLock()
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); await using var a = await h.ConnectAsync(); await using var b = await h.ConnectAsync();
        await a.CloseAsync(await a.CreateAsync("open")); var id = await b.CreateAsync("lock"); await b.WriteAsync(id, new byte[200]);
        await Task.WhenAll(Task.Run(async () => { for (var i = 0; i < 100; i++) await a.CloseAsync(await a.CreateAsync("open")); }), Task.Run(async () =>
        {
            for (var i = 0; i < 100; i++) { await b.ExchangeAsync(Route(Lock(id, 0, 1, 2), b)); await b.ExchangeAsync(Route(Lock(id, 0, 1, 4), b)); }
        })).WaitAsync(Check.Timeout); await b.CloseAsync(id);
    }
    static async Task PendingLockHandoff()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var transport = new RecordingTransport(); transport.Attach(d.Connection);
        var a = await Open(d, disposition: 3); var b = await Open(d); await Write(d, a, new byte[200]);
        Status(await d.Send(Lock(a, 100, 50, 2)), Ok, "first exclusive range"); var pending = await d.Send(Lock(b, 100, 50, 2)); Status(pending, 0x103, "second non-immediate lock pends");
        Status(await d.Send(Lock(a, 100, 50, 4)), Ok, "release original range"); Status(await AsyncFinal(transport, pending, 10), Ok, "pending lock acquires after exact unlock");
        Status(await d.Send(Lock(a, 100, 50)), 0xc0000055, "new owner excludes old owner"); Status(await d.Send(Lock(b, 100, 50, 4)), Ok, "new owner can unlock exact grant");
    }
    static async Task ThreeLeaseLocks()
    {
        await using var f = new CacheFixture(); var d = f.D; var first = Id(await d.Send(Lease(Create(disposition: 3), 7, 1)));
        var two = Session(f); var t2 = new RecordingTransport(); t2.Attach(two.Connection); var second = await OtherComplete(f, two, t2, Lease(Create(), 7, 2)); var secondId = Id(second); LeaseState(second, 3, 2);
        var three = Session(f, 3, 44); three.Connection.ClientGuid = Guid.NewGuid().ToByteArray(); var t3 = new RecordingTransport(); t3.Attach(three.Connection);
        var third = await Send(f, three, Lease(Create(), 7, 3)); var thirdId = Id(third); LeaseState(third, 3, 3);
        var lanes = new[] { (Session:d.Session, Transport:f.Transport),(Session:two,Transport:t2),(Session:three,Transport:t3) };
        async Task<byte[]> CompleteMulti(SmbSession session, byte[] request)
        {
            var starts = lanes.Select(x => x.Transport.Sends.Length).ToArray(); var result = session == d.Session ? await d.Send(request) : await Send(f, session, request);
            if (RawSmb.U32(result, 8) != 0x103) return result;
            while (true)
            {
                for (var i = 0; i < lanes.Length; i++)
                {
                    var messages = lanes[i].Transport.Sends;
                    while (starts[i] < messages.Length)
                    {
                        var b = messages[starts[i]++].Message;
                        if (RawSmb.U16(b, 12) == 18 && (RawSmb.U32(b, 68) & 1) != 0)
                        { var ack = LeaseAck(RawSmb.U64(b, 72), RawSmb.U32(b, 92)); Status(lanes[i].Session == d.Session ? await d.Send(ack) : await Send(f, lanes[i].Session, ack), Ok, "lease owner ACK on its own established session"); }
                    }
                }
                var transport = lanes.Single(x => x.Session == session).Transport; var final = transport.Sends.LastOrDefault(x => RawSmb.U16(x.Message, 12) == RawSmb.U16(request, 12) && (RawSmb.U32(x.Message, 16) & 2) != 0 && RawSmb.U64(x.Message, 32) == RawSmb.U64(result, 32));
                if (final != null) return final.Message;
                using var timeout = new CancellationTokenSource(Check.Timeout); await Task.WhenAny(lanes.Select(x => x.Transport.WaitForSendAsync(timeout.Token))).WaitAsync(Check.Timeout); await timeout.CancelAsync();
            }
        }
        var before = t2.Sends.Concat(t3.Sends).Count(x => RawSmb.U16(x.Message, 12) == 18); Status(await CompleteMulti(d.Session, Lock(first, 0, 1, 2)), Ok, "owner exclusive lock invalidates both foreign READ caches");
        Check.Equal(before + 2, t2.Sends.Concat(t3.Sends).Count(x => RawSmb.U16(x.Message, 12) == 18), "both same-client and foreign-client keys invalidated exactly once");
        LeaseState(await d.Send(Lease(Create(), 0, 1)), 3, 1); LeaseState(await Send(f, two, Lease(Create(), 0, 2)), 0, 2); LeaseState(await Send(f, three, Lease(Create(), 0, 3)), 0, 3);
        before = f.Transport.Sends.Count(x => RawSmb.U16(x.Message, 12) == 18); Status(await CompleteMulti(three, Lock(thirdId, 100, 1, 2)), Ok, "new exclusive lock at disjoint range invalidates original remaining READ cache");
        Check.Equal(before + 1, f.Transport.Sends.Count(x => RawSmb.U16(x.Message, 12) == 18), "one original-owner invalidation");
        Status(await Send(f, two, Lock(secondId, 0, 1)), 0xc0000055, "foreign invalidated cache does not change BRL ownership");
    }
    static async Task LockBeforePeer(bool overwrite)
    {
        await using var f = new CacheFixture(); var d = f.D; var first = Id(await d.Send(Lease(Create(disposition: 3), 7))); await Write(d, first, [120]);
        Status(await d.Send(Lock(first, 0, 1, 2)), Ok, "lock before contended lease acquisition");
        var peer = await Complete(f, Lease(Create(disposition: overwrite ? 4u : 1u), 7, 2)); Id(peer); LeaseState(peer, 3, 2);
        var notice = f.Transport.Sends.Single(x => RawSmb.U16(x.Message, 12) == 18).Message; Check.Equal(overwrite ? 0u : 3u, RawSmb.U32(notice, 92), "overwrite removes original READ cache; nondestructive open retains RH");
        Status(await d.Send(Lock(Id(peer), 0, 1)), 0xc0000055, "overwrite/open does not silently release original range lock");
    }
    static async Task DeclinedLeaseEpoch()
    {
        await using var f = new CacheFixture(true); var d = f.D; var owner = await Open(d, disposition: 3); await Write(d, owner, [120]); Status(await d.Send(Lock(owner, 0, 1)), Ok, "ordinary unleased locked opener");
        var b = Lease(ReplayCreate("none", Guid.NewGuid(), 1), 1, 1, true, 100); var created = await d.Send(b); Id(created); LeaseState(created, 0, 1);
        Check.Equal((ushort)100, RawSmb.U16(Context(created, "RqLs")!, 48), "declined READ grant preserves supplied epoch without a successful promotion"); Check.That(Context(created, "DH2Q") == null, "declined HANDLE state cannot become durable");
    }
    static async Task CrossVersionEpoch()
    {
        await using var f = new CacheFixture(); var d = f.D; var first = Id(await d.Send(Lease(Create(disposition: 3), 1)));
        var v2 = await d.Send(Lease(Create(), 5, 1, true, 0x4711)); var second = Id(v2); LeaseState(v2, 5, 1); Check.Equal(52, Context(v2, "RqLs")!.Length, "MS-SMB2 3.3.5.9.11 constructs the response requested by the v2 CREATE; common lease version stays v1");
        Check.Equal((ushort)0, RawSmb.U16(Context(v2, "RqLs")!, 48), "v2 response cannot initialize the common v1 lease epoch from the incoming request");
        var contender = await Complete(f, Lease(Create(), 3, 2, true), notification =>
        { Check.Equal((ushort)0, RawSmb.U16(notification, 66), "common v1 lease still sends NewEpoch zero after v2 CREATE"); return Task.CompletedTask; });
        await Close(d, Id(contender));
        await Close(d, first); var upgraded = await d.Send(Lease(Create(), 7)); first = Id(upgraded); LeaseState(upgraded, 7, 1); await Close(d, first);
        await Close(d, Id(await Complete(f, Create()))); await Close(d, second);
        var fresh = await d.Send(Lease(Create(), 7, 1, true, 0x4711)); Id(fresh); Check.Equal(52, Context(fresh, "RqLs")!.Length, "after last v1 member closes key can create a genuine v2 lease"); Check.Equal((ushort)0x4712, RawSmb.U16(Context(fresh, "RqLs")!, 48), "new v2 lease increments its supplied epoch");
    }
}
