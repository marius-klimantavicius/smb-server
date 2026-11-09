using Smb.Protocol.Enums;
using Smb.Auth.Ntlm;
using Smb.Server;
using Smb.Server.State;
using Smb.Testing;

internal static partial class UpstreamSambaMoreTests
{
    static IEnumerable<(string Name, Func<Task> Run)> FinalCases()
    {
        foreach (var leased in new[] { false, true })
        {
            yield return ($"upstream.samba.more.cache.source-stat-table.{leased}", () => StatAccessTable(leased));
            foreach (var durablePeer in new[] { false, true })
                yield return ($"upstream.samba.more.durable.disconnected-conflict.{leased}.{durablePeer}", () => DisconnectedConflict(leased, durablePeer));
            foreach (var v1 in new[] { false, true })
                yield return ($"upstream.samba.more.durable.previous-session-wire.{v1}.{leased}", () => PreviousDurableSession(v1, leased));
        }
        yield return ("upstream.samba.more.lease.stat-owner-share-none", LeaseStatOwner);
        yield return ("upstream.samba.more.lease.two-handle-breaks-before-close", TwoHandleBreaks);
        foreach (var same in new[] { false, true }) yield return ($"upstream.samba.more.lease.rename-single-interim-policy.{same}", () => RenameInterim(same));
        foreach (var shape in new[] { "batch-same", "batch-none", "batch-share", "batch-to-lease", "lease-upgrade", "lease-sidegrade", "lease-wrong-key", "lease-to-batch" })
            yield return ($"upstream.samba.more.replay.source.{shape}", () => ReplaySource(shape));
        yield return ("upstream.samba.more.replay.notify-sequence-wrap", NotifySequenceWrap);
        yield return ("upstream.samba.more.replay.bound-channel-roundtrip", BoundReplay);
        yield return ("upstream.samba.more.replay.query-retires-cache", ReplayAfterQuery);
        yield return ("upstream.samba.more.durable.app-instance-unavailable", AppInstanceUnavailable);
        yield return ("upstream.samba.more.ioctl.limited-tree-controls", LimitedTreeControls);
        yield return ("upstream.samba.more.lease.pending-client-disconnect", PendingClientDisconnect);
        foreach (var mode in new[] { "disconnected", "active-other-session", "previous-session", "twice-after-reconnect" })
            yield return ($"upstream.samba.more.replay.recovery.{mode}", () => RecoveryReplay(mode));
        yield return ("upstream.samba.more.durable.previous-session-delete-on-close", () => PreviousDurableSession(true, false, true));
    }
    static async Task StatAccessTable(bool leased)
    {
        foreach (var mask in new uint[] { 1, 2, 8, 16, 32, 0x80, 0x100, 0x10000, 0x20000, 0x40000, 0x80000, 0x100000 })
        {
            await using var f = new CacheFixture(); var d = f.D;
            if (leased) LeaseState(await d.Send(Lease(Create(disposition: 3), 7)), 7, 1); else Check.Equal((byte)9, (await OpenOplock(f, 9))[66], "batch source grant");
            // Selected object-store metadata policy includes EA reads, consistent
            // with the preserved exact 0x100088 stat-under-batch compound. The
            // native Windows IRP table's narrower READ_EA row is not universal.
            Id(await Complete(f, Create(access: mask))); var stat = mask is 8 or 0x80 or 0x100 or 0x100000 || leased && mask == 0x20000;
            Check.Equal(stat ? 0 : 1, f.Transport.Sends.Count(x => RawSmb.U16(x.Message, 12) == 18), $"source stat-only partition mask {mask:x}, lease={leased}");
            if (leased && stat) LeaseState(await d.Send(Lease(Create(access: 2), 7)), 7, 1);
        }
    }
    static async Task LeaseStatOwner()
    {
        await using var f = new CacheFixture(); var d = f.D; await Close(d, Id(await d.Send(Lease(Create(disposition: 3), 7))));
        var stat = await d.Send(Lease(Create(access: 0x80, share: 0), 7)); LeaseState(stat, 7, 1); var id = Id(stat);
        var member = await d.Send(Lease(Create(), 0)); LeaseState(member, 7, 1); await Close(d, Id(member)); Check.Equal(0, f.Transport.Sends.Length, "same-key data member does not conflict with stat share NONE");
        var peer = await Complete(f, Lease(Create(), 7, 2)); LeaseState(peer, 3, 2); Check.Equal(1, f.Transport.Sends.Count(x => RawSmb.U16(x.Message, 12) == 18), "stat owner still receives common-key data cache break"); await Close(d, id);
    }
    static async Task DisconnectedConflict(bool leased, bool durablePeer)
    {
        await using var f = new CacheFixture(true); var d = f.D; var guid = Guid.NewGuid(); var request = DurableRequest(true, guid, leased ? "lock-lease" : "lock-batch");
        if (leased && !durablePeer) { var at = (int)RawSmb.U32(request, 112); while (RawSmb.U32(request, at) != 0) at += (int)RawSmb.U32(request, at); RawSmb.Put32(request, at + 24 + 16, 3); RawSmb.Put32(request, 96, 0); }
        var first = Id(await d.Send(request)); await Write(d, first, Payload); await d.Dispatcher.OnConnectionClosedAsync(d.Connection);
        var s = Session(f); s.Connection.ClientGuid = Guid.NewGuid().ToByteArray(); var next = durablePeer ? DurableRequest(true, Guid.NewGuid(), leased ? "lock-lease" : "lock-batch") : Create();
        var response = await Send(f, s, next); var peer = Id(response);
        if (durablePeer) { Check.That(Context(response, "DHnQ") != null, "new client durable grant after purging incompatible disconnected owner"); if (leased) LeaseState(response, 7, 1); else Check.Equal((byte)9, response[66], "new client gets batch after old disconnected batch purged"); }
        s.Connection.ClientGuid = d.Connection.ClientGuid.ToArray(); // make old claim otherwise valid, including lease ClientGuid
        var claim = Reconnect(first, guid, true); if (leased) claim = Lease(claim, 7);
        Status(await Send(f, s, claim), Missing, "conflicting new acquisition purges old durable claim");
        Status(await Send(f, s, RawSmb.Close(peer, 0, 1, 42)), Ok, "new client closes replacement open");
    }
    static async Task TwoHandleBreaks()
    {
        await using var f = new CacheFixture(true); var d = f.D; await Close(d, await Open(d, disposition: 3)); var owners = new Dictionary<ulong,(ulong P,ulong V)>();
        foreach (var key in new ulong[] { 1, 2 })
        { var b = ReplayCreate("none", Guid.NewGuid(), key, 1); b = Lease(b, 3, key, true); RawSmb.Put32(b, 88, 0x120089); var created = await Complete(f, b); owners[key] = Id(created); LeaseState(created, 3, key); }
        var s = Session(f); s.Connection.ClientGuid = Guid.NewGuid().ToByteArray(); var transport = new RecordingTransport(); transport.Attach(s.Connection);
        var request = ReplayCreate("lease", Guid.NewGuid(), 3, 0); var pending = await Send(f, s, request); Status(pending, 0x103, "sharing contender pends behind both HANDLE leases");
        while (f.Transport.Sends.Count(x => RawSmb.U16(x.Message, 12) == 18) < 2) await f.Transport.WaitForSendAsync().WaitAsync(Check.Timeout);
        var breaks = f.Transport.Sends.Where(x => RawSmb.U16(x.Message, 12) == 18).Select(x => x.Message).ToArray(); Check.That(breaks.Select(x => RawSmb.U64(x, 72)).Order().SequenceEqual(new ulong[] { 1, 2 }), "each independent HANDLE key notified before either owner closes");
        foreach (var b in breaks) { Check.Equal(3u, RawSmb.U32(b, 88), "RH current state"); Check.Equal(1u, RawSmb.U32(b, 92), "share failure removes HANDLE"); Check.Equal((ushort)2, RawSmb.U16(b, 66), "each key advances epoch independently"); }
        await Close(d, owners[RawSmb.U64(breaks[0], 72)]); Check.Equal(2, f.Transport.Sends.Count(x => RawSmb.U16(x.Message, 12) == 18), "closing one member does not duplicate other break");
        await Close(d, owners[RawSmb.U64(breaks[1], 72)]); Id(await AsyncFinal(transport, pending));
    }
    static async Task RenameInterim(bool same)
    {
        await using var f = new CacheFixture(); var d = f.D; var owner = Id(await d.Send(Lease(Create(disposition: 3), 3))); await Write(d, owner, Payload);
        var peer = Id(await Complete(f, Lease(Create(), 3, 2))); var before = f.Transport.Sends.Length;
        var response = await d.Send(Rename(peer, same ? "file" : "renamed"));
        // The upstream Windows scheduling convention is synchronous. MS-SMB2
        // 3.3.4.2 explicitly permits an interim for SET_INFO too; completion,
        // signatures, withheld-ACK safety and metadata remain mandatory here.
        if (RawSmb.U32(response, 8) == 0x103)
        {
            Check.That((RawSmb.U32(response, 16) & 2) != 0 && RawSmb.U64(response, 32) != 0, "valid rename interim");
            Check.That(File.ReadAllBytes(Path.Combine(f.Root.Path, "file")).SequenceEqual(Payload), "rename preserves original bytes before ACK");
            Check.That(!File.Exists(Path.Combine(f.Root.Path, "renamed")), "rename has no namespace mutation before ACK");
            var notice = f.Transport.Sends.Skip(before).Single(x => RawSmb.U16(x.Message, 12) == 18).Message;
            var target = RawSmb.U32(notice, 92);
            Check.That((target & ~1u) == 0, "foreign RH key loses HANDLE without acquiring new rights");
            Check.That(!f.Transport.Sends.Skip(before).Any(x => RawSmb.U16(x.Message, 12) == 17), "no terminal rename before ACK");
            Status(await d.Send(LeaseAck(1, target)), Ok, "ACK exact advertised foreign HANDLE downgrade");
            while (!f.Transport.Sends.Skip(before).Any(x => RawSmb.U16(x.Message, 12) == 17))
            {
                Check.Equal(1, f.Transport.Sends.Skip(before).Count(x => RawSmb.U16(x.Message, 12) == 18), "source and same-object destination need only one foreign-key break");
                await f.Transport.WaitForSendAsync().WaitAsync(Check.Timeout);
            }
            var final = Split(await AsyncFinal(f.Transport, response, 17), d.Connection.Dialect).Single();
            Check.Equal(RawSmb.U64(response, 24), RawSmb.U64(final, 24), "rename final retains MessageId");
            Check.Equal(RawSmb.U64(response, 32), RawSmb.U64(final, 32), "rename final retains AsyncId");
            using (var timeout = new CancellationTokenSource(Check.Timeout))
                while (!d.Connection.PendingRequests.IsEmpty) await Task.Delay(1, timeout.Token);
            Check.Equal(1, f.Transport.Sends.Skip(before).Count(x => RawSmb.U16(x.Message, 12) == 17), "rename completes exactly once");
            response = final;
        }
        Status(response, Ok, "standalone rename completes after lease downgrade");
        Check.Equal(1, f.Transport.Sends.Skip(before).Count(x => RawSmb.U16(x.Message, 12) == 18), "same/different-name rename invalidates foreign HANDLE key once");
        Check.That(File.Exists(Path.Combine(f.Root.Path, same ? "file" : "renamed")), "final destination exists");
        if (!same) Check.That(!File.Exists(Path.Combine(f.Root.Path, "file")), "old name gone after final");
        await Data(d, peer, Payload); await Close(d, peer);

    }
    static async Task ReplaySource(string shape)
    {
        await using var f = new CacheFixture(true); var d = f.D; var guid = Guid.NewGuid(); var leased = shape.StartsWith("lease");
        var request = ReplayCreate("batch", guid, 1, leased ? 7u : 0u); if (leased) request = Lease(request, 3);
        var initial = await d.Send(request); var owner = Id(initial); f.Oplocks[owner] = initial[66]; Check.That(Context(initial, "DH2Q") != null, "actual durable replay grant");
        if (leased)
        { var upgrade = Lease(ReplayCreate("batch", Guid.NewGuid(), 1), 7); Id(await Complete(f, upgrade)); }
        byte[] replay = shape switch
        {
            "batch-none" => ReplayCreate("none", guid, 1, 0), "batch-share" => ReplayCreate("batch", guid, 1, 7), "batch-to-lease" => Lease(ReplayCreate("none", guid, 1, 0), 3),
            "lease-sidegrade" => Lease(ReplayCreate("none", guid, 1), 1), "lease-wrong-key" => Lease(ReplayCreate("none", guid, 1), 3, 9),
            "lease-to-batch" => ReplayCreate("batch", guid, 1), _ => request.ToArray()
        };
        RawSmb.Put32(replay, 16, 0x20000000); var count = f.Transport.Sends.Length; var result = await d.Send(replay);
        if (shape is "batch-to-lease" or "lease-wrong-key" or "lease-to-batch") { Status(result, Denied, "replay requires matching original lease presence and key"); return; }
        Status(result, Ok, "source modified/repeated CREATE replay"); Check.Equal(owner, Id(result), "replay is the existing open identity");
        Check.Equal(RawSmb.U32(initial, 68), RawSmb.U32(result, 68), "replay preserves original CREATE action");
        Check.Equal(count, f.Transport.Sends.Length, "replay does not cause a new cache break");
        if (shape == "batch-none") { Check.Equal((byte)9, result[66], "MS-SMB2 3.3.5.9 response uses retained Open.OplockLevel"); Check.That(Context(result, "DH2Q") != null, "replayed durable open retains its durable response"); }
        else if (!leased) Check.Equal((byte)9, result[66], "replay preserves batch grant");
        else if (shape != "lease-to-batch") LeaseState(result, 7, 1); // source returns the upgraded common lease state
        if (!leased && shape != "batch-same") Status(await Complete(f, ReplayCreate("batch", Guid.NewGuid(), 1, 0)), Sharing, "replay share/oplock changes did not relax original underlying sharing");
    }
    static async Task NotifySequenceWrap()
    {
        await using var f = new CacheFixture(); var d = f.D; d.Options.EnableMultichannel = true; d.Options.FeaturePolicy = SmbFeaturePolicy.MultichannelWithCaching; d.Connection.ServerCapabilities |= Smb2Capabilities.MultiChannel; d.Options.DirectoryWatcher = new FakeWatcher();
        var id = await Open(d, "", directory: true); var pending = await d.Send(Notify(id)); Status(pending, 0x103, "long-lived notify at sequence zero");
        foreach (var sequence in new ushort[] { 30000, 60000, 0 }) { var q = Query(id, 14); RawSmb.Put16(q, 8, sequence); Output(await d.Send(q)); }
        var cancel = RawSmb.Header(12, 4, 0, 1); RawSmb.Put16(cancel, 64, 4); RawSmb.Put32(cancel, 16, 2); RawSmb.Put64(cancel, 32, RawSmb.U64(pending, 32)); await d.Send(cancel);
        Status(await AsyncFinal(f.Transport, pending, 15), 0xc0000120, "notify retires once after sequence wraps back to original value");
        var size = new byte[8]; RawSmb.Put64(size, 0, 7); var file = await Open(d, disposition: 3); Status(await d.Send(Set(file, 20, size)), Ok, "sequence accounting remains usable after old notify completes");
    }
    static async Task BoundReplay()
    {
        await using var f = new CacheFixture(true); var d = f.D; d.Options.EnableMultichannel = true; d.Options.FeaturePolicy = SmbFeaturePolicy.DurableWithMultichannel;
        var c = d.Channel(); c.Dialect = SmbDialect.Smb300; c.ClientGuid = d.Connection.ClientGuid.ToArray(); c.ServerCapabilities = d.Connection.ServerCapabilities | Smb2Capabilities.MultiChannel; c.Sessions.TryAdd(1, d.Session); d.State.Connections.TryAdd(c.ConnectionId, c); d.Session.TryAttachChannel(new SmbChannel { Connection = c, SigningKey = d.Session.SigningKey });
        var request = ReplayCreate("batch", Guid.NewGuid(), 1); var original = await d.Send(request); var id = Id(original);
        var replay = request.ToArray(); RawSmb.Put32(replay, 16, 0x20000000); var copy = await d.Send(replay, c); Check.Equal(id, Id(copy), "completed CREATE replay across established bound channels");
        await Write(d, id, Payload);
        var read = RawSmb.Read(id, (uint)Payload.Length, 0, 0, 1, 42); RawSmb.Put16(read, 8, 1); Status(await d.Send(read, c), Ok, "new channel sequence read advances durable sequence");
        foreach (var replayed in new[] { false, true }) { var write = RawSmb.Write(id, [9], 0, 0, 1, 42); if (replayed) RawSmb.Put32(write, 16, 0x20000000); Status(await d.Send(write), 0xc0000467, "stale WRITE rejected on original channel, including replay flag"); }
        var data = new byte[8]; RawSmb.Put64(data, 0, 0x1000); Status(await d.Send(Set(id, 14, data)), 0xc0000467, "stale SET_INFO position rejected");
        await Data(d, id, Payload); var current = RawSmb.Write(id, [9], 0, 0, 1, 42); RawSmb.Put16(current, 8, 1); RawSmb.Put32(current, 16, 0x20000000); Status(await d.Send(current, c), Ok, "current WRITE replay permitted");
        current = RawSmb.Write(id, [8], 0, 0, 1, 42); RawSmb.Put16(current, 8, 1); RawSmb.Put32(current, 16, 0x20000000); Status(await d.Send(current, c), Ok, "same sequence replay WRITE uses current submitted data");
        await Data(d, id, new byte[] { 8 }.Concat(Payload[1..]).ToArray());
    }
    static async Task ReplayAfterQuery()
    {
        await using var f = new CacheFixture(true); var d = f.D; var request = ReplayCreate("batch", Guid.NewGuid(), 1); var first = Id(await d.Send(request)); f.Oplocks[first] = 9;
        Output(await d.Send(Query(first, 14))); RawSmb.Put32(request, 16, 0x20000000); var next = await Complete(f, request); var second = Id(next);
        Check.That(first != second, "source non-CREATE retires original CREATE replay response; later replay opens independently");
        Check.Equal((byte)1, next[66], "independent replay-open contends with retained batch");
    }
    static byte[] NamedContext(byte[] request, byte[] name, byte[] data)
    {
        var start = (request.Length + 7) & ~7; var dataAt = (16 + name.Length + 7) & ~7; var size = (dataAt + data.Length + 7) & ~7; var previous = (int)RawSmb.U32(request, 112);
        if (previous != 0) { while (RawSmb.U32(request, previous) != 0) previous += (int)RawSmb.U32(request, previous); RawSmb.Put32(request, previous, (uint)(start - previous)); }
        Array.Resize(ref request, start + size); RawSmb.Put16(request, start + 4, 16); RawSmb.Put16(request, start + 6, (ushort)name.Length); RawSmb.Put16(request, start + 10, (ushort)dataAt); RawSmb.Put32(request, start + 12, (uint)data.Length); name.CopyTo(request, start + 16); data.CopyTo(request, start + dataAt);
        if (previous == 0) RawSmb.Put32(request, 112, (uint)start); RawSmb.Put32(request, 116, (uint)(request.Length - RawSmb.U32(request, 112))); return request;
    }
    static async Task AppInstanceUnavailable()
    {
        await using var f = new CacheFixture(true); var d = f.D; byte[] name = [0x45,0xbc,0xa6,0x6a,0xef,0xa7,0xf7,0x4a,0x90,0x08,0xfa,0x46,0x2e,0x14,0x4d,0x74]; var data = new byte[20]; RawSmb.Put16(data, 0, 20); Guid.NewGuid().ToByteArray().CopyTo(data, 4);
        byte[] Request() { var b = DurableRequest(false, Guid.NewGuid(), "lock-batch"); RawSmb.Put32(b, 96, 0); return NamedContext(b, name, data); }
        var first = await d.Send(Request()); var id = Id(first); f.Oplocks[id] = 9;
        Status(await Complete(f, Request()), Sharing, "unsupported AppInstanceId must not evict active original open"); await Write(d, id, Payload); await Data(d, id, Payload);
    }
    static async Task LimitedTreeControls()
    {
        await using var f = new CacheFixture(); var d = f.D; d.Options.EnableMultichannel = true; d.Options.FeaturePolicy = SmbFeaturePolicy.MultichannelWithCaching;
        var limited = new SmbTreeConnect { TreeId = 44, Session = d.Session, Share = d.Tree.Share, MaximalAccess = 0 }; d.Session.TreeConnects.TryAdd(44, limited); d.Options.Metrics.OnTreeConnected();
        foreach (var tree in new uint[] { 42, 44 })
        {
            async Task<byte[]> Submit(byte[] b) { RawSmb.Put32(b, 36, tree); return await d.Send(b); }
            foreach (var n in new uint[] { 1, 65535 })
            {
                var valid = await Submit(P5Tests.Ioctl(Inherit, 0x1401fc, [], n)); Status(valid, n == 1 ? 0xc0000023u : Ok, "server network-interface control independent of file/share access");
                Status(await Submit(P5Tests.Ioctl(((ulong)long.MaxValue,(ulong)long.MaxValue), 0x1401fc, [], n)), Invalid, "non-sentinel FileId validation precedes network-interface buffer size");
            }
            var data = new byte[26]; RawSmb.Put32(data, 0, (uint)d.Connection.ClientCapabilities); d.Connection.ClientGuid.CopyTo(data, 4); RawSmb.Put16(data, 20, (ushort)d.Connection.ClientSecurityMode); RawSmb.Put16(data, 22, 1); RawSmb.Put16(data, 24, 0x300);
            Status(await Submit(P5Tests.Ioctl(Inherit, 0x140204, data, 24)), Ok, "validate negotiate uses connection facts even through zero-access tree");
        }
    }
    static async Task PendingClientDisconnect()
    {
        await using var f = new CacheFixture(true); var d = f.D; var request = DurableRequest(true, Guid.NewGuid(), "lock-no-write-lease"); RawSmb.Put32(request, 96, 0); var id = Id(await d.Send(request));
        var s = Session(f); var transport = new RecordingTransport(); transport.Attach(s.Connection); var pending = await Send(f, s, Create()); Status(pending, 0x103, "share conflict waits for disconnected-candidate HANDLE lease");
        await d.Dispatcher.OnConnectionClosedAsync(s.Connection); await d.Dispatcher.OnConnectionClosedAsync(d.Connection);
        var fresh = Session(f); var echo = RawSmb.Header(13, 4, 0, 1, 42); RawSmb.Put16(echo, 64, 4); Status(await Send(f, fresh, echo), Ok, "fresh connection remains responsive after contender and lease owner disconnect during outstanding break");
    }
    static async Task RecoveryReplay(string mode)
    {
        await using var f = new CacheFixture(true); var client = Guid.NewGuid(); var first = new NegotiatedPeer(f); await first.Login(client);
        Check.Equal(0u, (uint)first.Connection.ServerCapabilities & 0x10u, "persistent handles not advertised by actual SMB300 negotiation");
        var recoveryGuid = Guid.NewGuid(); var request = Lease(ReplayCreate("none", recoveryGuid, 1), 7, 1, true, 1);
        if (mode != "twice-after-reconnect") { var at = (int)RawSmb.U32(request, 112); RawSmb.Put32(request, at + RawSmb.U16(request, at + 10) + 4, 2); }
        var response = await first.Exchange(request); var id = Id(response); var durable = Context(response, "DH2Q"); Check.That(durable != null, "ordinary durable grant available"); Check.Equal(0u, RawSmb.U32(durable!, 4) & 2u, "optional persistent request cannot manufacture persistent support");
        if (mode is "disconnected" or "twice-after-reconnect") await f.D.Dispatcher.OnConnectionClosedAsync(first.Connection);
        var second = new NegotiatedPeer(f); await second.Login(client, mode == "previous-session" ? first.Session : 0);
        if (mode == "previous-session") Status(await first.Exchange(Query(id, 14)), 0xc0000203, "previous-session replacement invalidates old query handle");
        RawSmb.Put32(request, 16, RawSmb.U32(request, 16) | 0x20000000); var replayed = await second.Exchange(request);
        if (mode == "active-other-session") { Status(replayed, 0xc000022a, "source replay in independent active session is DUPLICATE_OBJECTID"); Status(await first.Exchange(RawSmb.Write(id, Payload, 0, 0, 1, 42)), Ok, "rejected replay leaves old authenticated handle usable"); return; }
        // MS-SMB2 3.3.5.9: ordinary replay cannot move an open to a new session.
        // The persistent/CA-only branch of the original source is not this profile.
        Status(replayed, 0xc000022a, "non-CA cross-session replay is DUPLICATE_OBJECTID");
        var reconnect = Reconnect(id, recoveryGuid, false);
        reconnect = Lease(reconnect, 0, 1, true, RawSmb.U16(Context(response, "RqLs")!, 48));
        var connected = await second.Exchange(reconnect); var reconnected = Id(connected);
        Check.Equal(id.P, reconnected.P, "explicit DH2C retains original object"); Check.Equal(1u, RawSmb.U32(connected, 68), "reconnect reports EXISTED");
        replayed = await second.Exchange(request); var recovered = Id(replayed);
        Check.Equal(reconnected, recovered, "same-session replay after explicit reconnect returns reattached open");
        Check.Equal(2u, RawSmb.U32(replayed, 68), "same-session replay retains original CREATED action");
        if (mode == "twice-after-reconnect")
        {
            var repeated = await second.Exchange(request.ToArray()); Check.Equal(recovered, Id(repeated), "second replay returns same recovered identity"); Check.Equal(2u, RawSmb.U32(repeated, 68), "second replay retains CREATED action");
        }
        Status(await second.Exchange(RawSmb.Write(recovered, Payload, 0, 0, 1, 42)), Ok, "authenticated replay-recovered write");
        var read = await second.Exchange(RawSmb.Read(recovered, (uint)Payload.Length, 0, 0, 1, 42)); Status(read, Ok, "authenticated replay-recovered read"); Check.That(RawSmb.Buffer(read, read[66], RawSmb.U32(read, 68)).SequenceEqual(Payload), "replay recovery bytes exact");
        if (mode == "twice-after-reconnect") { var fresh = await second.Exchange(request); Check.That(Id(fresh) != recovered, "ordinary WRITE retires cached CREATE response so later replay opens independently"); Check.Equal(1u, RawSmb.U32(fresh, 68), "later independent open action EXISTED"); Status(await second.Exchange(RawSmb.Close(Id(fresh), 0, 1, 42)), Ok, "close fresh post-write replay acquisition"); }
        Status(await second.Exchange(RawSmb.Close(recovered, 0, 1, 42)), Ok, "close explicitly reconnected open");
    }
    sealed class NegotiatedPeer(CacheFixture fixture)
    {
        internal readonly SmbConnection Connection = new(); internal ulong Session; internal uint Tree; ulong mid; byte[]? key;
        internal async Task Login(Guid client, ulong previous = 0)
        {
            fixture.D.State.Connections.TryAdd(Connection.ConnectionId, Connection); var negotiate = RawSmb.Negotiate(); RawSmb.Put16(negotiate, 100, 0x300); RawSmb.Put32(negotiate, 72, 4); client.ToByteArray().CopyTo(negotiate, 76);
            Status(await Exchange(negotiate, false), Ok, "actual SMB300 NEGOTIATE for previous-session recovery");
            var ntlm = new NtlmClient("P0", "user", "password"); var request = RawSmb.SessionSetup(ntlm.BuildNegotiate(), 0); RawSmb.Put64(request, 80, previous); var challenge = await Exchange(request, false); Status(challenge, 0xc0000016, "unsigned fresh-session NTLM challenge"); Session = RawSmb.U64(challenge, 40);
            request = RawSmb.SessionSetup(ntlm.BuildAuthenticate(RawSmb.Buffer(challenge, RawSmb.U16(challenge, 68), RawSmb.U16(challenge, 70))), 0, Session); RawSmb.Put64(request, 80, previous); Status(await Exchange(request, false), Ok, "actual authenticated replacement session");
            key = Smb.Crypto.Smb3KeyDerivation.Derive(SmbDialect.Smb300, SmbCipherId.None, ntlm.ExportedSessionKey, ntlm.ExportedSessionKey, new byte[64]).SigningKey;
            var tree = await Exchange(RawSmb.TreeConnect("\\\\localhost\\P0", 0, Session), false); Status(tree, Ok, "signed replacement tree connect"); Tree = RawSmb.U32(tree, 36);
        }
        internal async Task<byte[]> Exchange(byte[] b, bool route = true)
        {
            RawSmb.Put64(b, 24, mid++); if (route) { RawSmb.Put64(b, 40, Session); RawSmb.Put32(b, 36, Tree); }
            if (key != null) { RawSmb.Put32(b, 16, RawSmb.U32(b, 16) | 8); b.AsSpan(48, 16).Clear(); Smb.Crypto.AesCmac.Compute(key, b).CopyTo(b, 48); }
            var result = await fixture.D.Dispatcher.ProcessMessageAsync(Connection, b); Connection.ResponseSent(result);
            Check.Equal(RawSmb.U64(b, 24), RawSmb.U64(result, 24), "authenticated direct response matches submitted MessageId");
            Check.Equal(RawSmb.U16(b, 12), RawSmb.U16(result, 12), "authenticated direct response command");
            // MS-SMB2 3.2.5.1.3 skips signature verification for STATUS_PENDING.
            // Terminal replies still require the negotiated channel signature.
            if (key != null && RawSmb.U32(result, 8) is not (0xc0000203 or 0x103))
            {
                Check.That((RawSmb.U32(result, 16) & 8) != 0, $"authenticated direct response signed, command={RawSmb.U16(result, 12)}, status=0x{RawSmb.U32(result, 8):x8}"); var unsigned = result.ToArray(); unsigned.AsSpan(48, 16).Clear();
                Check.That(Smb.Crypto.AesCmac.Compute(key, unsigned).SequenceEqual(result.AsSpan(48, 16).ToArray()), "independent response CMAC using negotiated peer key");
            }
            return result;
        }
        internal async Task FailedReauthentication()
        {
            var ntlm = new NtlmClient("P0", "unknown-user", "password"); var request = RawSmb.SessionSetup(ntlm.BuildNegotiate(), 0, Session); var challenge = await Exchange(request, false); Status(challenge, 0xc0000016, "signed reauthentication challenge on existing session");
            request = RawSmb.SessionSetup(ntlm.BuildAuthenticate(RawSmb.Buffer(challenge, RawSmb.U16(challenge, 68), RawSmb.U16(challenge, 70))), 0, Session); Status(await Exchange(request, false), 0xc000006d, "invalid reauthentication fails LOGON_FAILURE");
        }
    }
    static async Task PreviousDurableSession(bool v1, bool leased, bool deleteOnClose = false)
    {
        await using var f = new CacheFixture(true); var client = Guid.NewGuid(); var first = new NegotiatedPeer(f); await first.Login(client); var guid = Guid.NewGuid();
        var request = DurableRequest(v1, guid, deleteOnClose ? "delete-on-close" : leased ? "lock-lease" : "lock-batch"); var created = await first.Exchange(request); var id = Id(created); Check.That(Context(created, v1 ? "DHnQ" : "DH2Q") != null, "authenticated session obtains real durable grant");
        Status(await first.Exchange(RawSmb.Write(id, Payload, 0, 0, 1, 42)), Ok, "initial authenticated durable bytes");
        for (var cycle = 0; cycle < 2; cycle++)
        {
            var next = new NegotiatedPeer(f); await next.Login(leased ? client : Guid.NewGuid(), first.Session);
            Status(await first.Exchange(Reconnect(id, guid, v1)), 0xc0000203, "previous-session replacement invalidates old signed session");
            var claim = Reconnect(id, guid, v1); if (leased) claim = Lease(claim, 0); var recovered = await next.Exchange(claim); id = Id(recovered);
            Check.Equal(1u, RawSmb.U32(recovered, 68), "previous-session durable recovery action EXISTED");
            var read = await next.Exchange(RawSmb.Read(id, (uint)Payload.Length, 0, 0, 1, 42)); Status(read, Ok, "replacement session recovered usable original data"); Check.That(RawSmb.Buffer(read, read[66], RawSmb.U32(read, 68)).SequenceEqual(Payload), "authenticated recovery preserves exact original bytes"); first = next;
        }
        Status(await first.Exchange(RawSmb.Close(id, 0, 1, 42)), Ok, "close after two actual previous-session replacements");
        if (deleteOnClose)
        {
            Status(await first.Exchange(Create()), Missing, "recovered DELETE_ON_CLOSE removes original name");
            var fresh = await first.Exchange(DurableRequest(true, Guid.NewGuid(), "delete-on-close")); Id(fresh); Check.Equal(2u, RawSmb.U32(fresh, 68), "later durable OPEN_IF creates a new object"); Check.Equal(0ul, RawSmb.U64(fresh, 112), "new object does not retain deleted data");
        }
    }
}
