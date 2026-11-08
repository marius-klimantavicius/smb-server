using Smb.Auth;
using Smb.Testing;

internal static partial class UpstreamSambaMoreTests
{
    static IEnumerable<(string Name, Func<Task> Run)> RecoveryCases()
    {
        foreach (var v1 in new[] { false, true })
        {
            yield return ($"upstream.samba.more.durable.failed-active-does-not-poison.{v1}", () => FailedActiveReconnect(v1));
            yield return ($"upstream.samba.more.durable.different-owner.{v1}", () => DifferentDurableOwner(v1));
            yield return ($"upstream.samba.more.durable.cross-version.{v1}", () => CrossVersionReconnect(v1));
        }
        yield return ("upstream.samba.more.durable.zero-timeout-default", () => DurableDeadline(false));
        yield return ("upstream.samba.more.durable.millisecond-expiry", () => DurableDeadline(true));
        foreach (var shape in new[] { "stat-first", "nonstat-first", "stat-lease-first", "same-key", "different-key", "set-eof" })
            yield return ($"upstream.samba.more.durable.multi-open.{shape}", () => DurableMultiOpen(shape));
        foreach (var v1 in new[] { false, true })
            foreach (var leased in new[] { false, true })
                yield return ($"upstream.samba.more.durable.ignored-reconnect-fields.{v1}.{leased}", () => IgnoredReconnectFields(v1, leased));
        yield return ("upstream.samba.more.durable.stat-only-v1", DurableStatOnly);
        foreach (var operation in new[] { "stat", "rh", "rwh", "share-none", "write", "rename" })
            yield return ($"upstream.samba.more.durable.retained-two-owners.{operation}", () => RetainedTwoOwners(operation));
        yield return ("upstream.samba.more.durable.initial-allocation-unsupported", DurableAllocationIgnored);
        yield return ("upstream.samba.more.durable.delete-disconnect-new-create", DurableDeleteFreshCreate);
    }
    static byte[] Reconnect((ulong P, ulong V) id, Guid guid, bool v1)
    {
        var data = new byte[v1 ? 16 : 36]; RawSmb.Put64(data, 0, id.P); RawSmb.Put64(data, 8, id.V); if (!v1) guid.ToByteArray().CopyTo(data, 16);
        return P7cTests.Context(Create(), v1 ? "DHnC" : "DH2C", data);
    }
    static async Task FailedActiveReconnect(bool v1)
    {
        await using var f = new CacheFixture(true); var d = f.D; var guid = Guid.NewGuid(); var id = Id(await d.Send(DurableRequest(v1, guid, "lock-batch"))); await Write(d, id, Payload);
        var failed = Session(f); failed.Connection.ClientGuid = Guid.NewGuid().ToByteArray();
        Status(await Send(f, failed, Reconnect(id, guid, v1)), Missing, "active open is not eligible for reconnect on another connection");
        await d.Dispatcher.OnConnectionClosedAsync(d.Connection); await d.Dispatcher.OnConnectionClosedAsync(failed.Connection);
        var valid = Session(f); var response = await Send(f, valid, Reconnect(id, guid, v1)); var recovered = Id(response);
        var data = await Send(f, valid, RawSmb.Read(recovered, (uint)Payload.Length, 0, 0, 1, 42)); Status(data, Ok, "valid claim after failed active claimant disconnects");
        Check.That(RawSmb.Buffer(data, data[66], RawSmb.U32(data, 68)).SequenceEqual(Payload), "failed claimant lifetime cannot poison retained object bytes");
        Status(await Send(f, valid, RawSmb.Close(recovered, 0, 1, 42)), Ok, "close recovered object");
    }
    static async Task DifferentDurableOwner(bool v1)
    {
        await using var f = new CacheFixture(true); var d = f.D;
        // Established named identities belong to this direct-session fixture;
        // no claim that these two users authenticated through NTLM is made.
        var owner = new SecurityIdentity { DomainName = "UPSTREAM", UserName = "owner" }; d.Session.Identity = owner;
        var guid = Guid.NewGuid(); var id = Id(await d.Send(DurableRequest(v1, guid, "lock-batch"))); await Write(d, id, Payload); await d.Dispatcher.OnConnectionClosedAsync(d.Connection);
        var s = Session(f); s.Identity = new SecurityIdentity { DomainName = "UPSTREAM", UserName = "different-owner" };
        Status(await Send(f, s, Reconnect(id, guid, v1)), Denied, "different established security identity cannot claim another user's durable open");
        s.Identity = owner; var response = await Send(f, s, Reconnect(id, guid, v1)); var recovered = Id(response);
        Status(await Send(f, s, RawSmb.Read(recovered, (uint)Payload.Length, 0, 0, 1, 42)), Ok, "denied owner claim leaves rightful claim usable");
        Status(await Send(f, s, RawSmb.Close(recovered, 0, 1, 42)), Ok, "rightful owner closes recovered file");
    }
    static async Task CrossVersionReconnect(bool initialV1)
    {
        await using var f = new CacheFixture(true); var d = f.D; var guid = Guid.NewGuid(); var id = Id(await d.Send(DurableRequest(initialV1, guid, "lock-batch")));
        await Write(d, id, Payload); await d.Dispatcher.OnConnectionClosedAsync(d.Connection); var s = Session(f);
        Status(await Send(f, s, Reconnect(id, initialV1 ? guid : Guid.Empty, false)), Missing, "wrong/nonexistent v2 CreateGuid cannot reconnect");
        var response = await Send(f, s, Reconnect(id, guid, true)); var recovered = Id(response);
        Check.Equal(id.P, recovered.P, "v1 reconnect uses persistent FileId independent of original request version");
        Check.That(Context(response, "DH2Q") == null, "reconnect is not a new v2 durable grant");
        var data = await Send(f, s, RawSmb.Read(recovered, (uint)Payload.Length, 0, 0, 1, 42)); Status(data, Ok, "cross-version retained bytes accessible");
        Check.That(RawSmb.Buffer(data, data[66], RawSmb.U32(data, 68)).SequenceEqual(Payload), "cross-version recovery retains original object");
        Status(await Send(f, s, RawSmb.Close(recovered, 0, 1, 42)), Ok, "cross-version close");
    }
    static async Task DurableDeadline(bool expire)
    {
        await using var f = new CacheFixture(true); var d = f.D; var clock = new ManualClock(); d.Options.TimeProvider = clock;
        d.Options.DurableHandleTimeout = TimeSpan.FromMilliseconds(expire ? 1 : 100); var guid = Guid.NewGuid(); var request = DurableRequest(false, guid, "lock-batch");
        var at = (int)RawSmb.U32(request, 112); RawSmb.Put32(request, at + RawSmb.U16(request, at + 10), 0);
        var response = await d.Send(request); var id = Id(response); var context = Context(response, "DH2Q"); Check.That(context != null, "durable grant with requested timeout zero");
        Check.Equal(expire ? 1u : 100u, RawSmb.U32(context!, 0), "zero timeout selects configured local timeout"); await d.Dispatcher.OnConnectionClosedAsync(d.Connection);
        if (expire) clock.Advance(TimeSpan.FromMilliseconds(2)); var s = Session(f); response = await Send(f, s, Reconnect(id, guid, false));
        Status(response, expire ? Missing : Ok, "durable reconnect checks the negotiated expiry deadline without a private scavenger call");
        if (!expire) Status(await Send(f, s, RawSmb.Close(Id(response), 0, 1, 42)), Ok, "default-timeout recovered close");
    }
    static async Task DurableMultiOpen(string shape)
    {
        await using var f = new CacheFixture(true); var d = f.D; var one = Guid.NewGuid(); var two = Guid.NewGuid(); var multiple = shape is "same-key" or "different-key";
        byte[] Request(Guid guid, uint state, ulong key, ushort epoch = 0) => Lease(DurableRequest(false, guid, "lock-batch"), state, key, true, epoch);
        (ulong P, ulong V) first = default;
        if (shape == "stat-first") first = await Open(d, disposition: 3, access: 0x100180);
        if (shape == "nonstat-first") first = await Open(d, disposition: 3, access: 0x120180);
        if (shape == "stat-lease-first") { var b = await d.Send(Lease(Create(disposition: 3, access: 0x80), 3, 2, true)); first = Id(b); LeaseState(b, 3, 2); }
        if (multiple) { var b = await d.Send(Request(one, shape == "same-key" ? 7u : 3u, 1)); first = Id(b); Check.That(Context(b, "DH2Q") != null, "first actual durable grant"); }
        var expected = shape is "nonstat-first" or "stat-lease-first" or "different-key" ? 3u : 7u; var key2 = shape == "different-key" ? 2ul : 1ul;
        var created = await Complete(f, Request(two, shape == "different-key" ? 3u : 7u, key2)); var second = Id(created);
        LeaseState(created, expected, key2); Check.That(Context(created, "DH2Q") != null, "second durable grant under exact stat/lease sharing policy");
        var ctx = Context(created, "RqLs")!; var epoch = RawSmb.U16(ctx, 48);
        if (shape == "set-eof") { var size = new byte[8]; RawSmb.Put64(size, 0, 0x100000); Status(await d.Send(Set(second, 20, size)), Ok, "SET EOF before durable disconnect"); }
        await d.Dispatcher.OnConnectionClosedAsync(d.Connection); var s = Session(f);
        async Task ReopenOne((ulong P, ulong V) id, Guid guid, ulong key, uint state)
        {
            var b = await Send(f, s, Lease(Reconnect(id, guid, false), 0, key, true, epoch)); var recovered = Id(b);
            Check.Equal(id.P, recovered.P, "independent durable identity retained"); Check.Equal(1u, RawSmb.U32(b, 68), "reconnect CREATE action EXISTED");
            LeaseState(b, state, key); Check.That(Context(b, "DH2Q") == null, "reconnect returns no new durable grant");
            Check.Equal(epoch, RawSmb.U16(Context(b, "RqLs")!, 48), "lease epoch retained across reconnect");
            if (shape == "set-eof") Check.Equal(0x100000ul, RawSmb.U64(b, 112), "EOF mutation survives reconnect");
            Status(await Send(f, s, RawSmb.Close(recovered, 0, 1, 42)), Ok, "close individually recovered open");
        }
        if (multiple) await ReopenOne(first, one, 1, shape == "same-key" ? 7u : 3u);
        await ReopenOne(second, two, key2, expected);
    }
    static async Task IgnoredReconnectFields(bool v1, bool leased)
    {
        await using var f = new CacheFixture(true); var d = f.D; var guid = Guid.NewGuid(); var req = DurableRequest(v1, guid, leased ? "lock-lease" : "lock-batch");
        var created = await d.Send(req); var id = Id(created); await Write(d, id, Payload); await d.Dispatcher.OnConnectionClosedAsync(d.Connection); var s = Session(f);
        var reconnect = Reconnect(id, guid, v1); reconnect[66] = 0x78; reconnect[67] = 0x78;
        foreach (var at in new[] { 68, 72, 80, 88, 92, 96, 100, 104 }) RawSmb.Put32(reconnect, at, 0x12345678);
        if (leased) reconnect = Lease(reconnect, 0); // requested state ignored, established key checked
        var recovered = await Send(f, s, reconnect); var next = Id(recovered); Check.Equal(id.P, next.P, "non-authoritative ordinary CREATE fields ignored on durable reconnect");
        Check.Equal(1u, RawSmb.U32(recovered, 68), "reconnect action EXISTED"); Check.That(Context(recovered, v1 ? "DHnQ" : "DH2Q") == null, "reconnect is not a fresh durable grant");
        if (leased) LeaseState(recovered, 7, 1); else Check.Equal((byte)9, recovered[66], "batch grant retained independent of RequestedOplockLevel");
        var read = await Send(f, s, RawSmb.Read(next, (uint)Payload.Length, 0, 0, 1, 42)); Status(read, Ok, "retained access rights and bytes after ignored desired-access field");
        Check.That(RawSmb.Buffer(read, read[66], RawSmb.U32(read, 68)).SequenceEqual(Payload), "ignored-field reconnect data unchanged");
        Status(await Send(f, s, RawSmb.Close(next, 0, 1, 42)), Ok, "close ignored-field recovered open");
    }
    static async Task DurableStatOnly()
    {
        await using var f = new CacheFixture(true); var d = f.D; await Close(d, await Open(d, disposition: 3));
        var b = DurableRequest(true, Guid.NewGuid(), "lock-no-write-lease"); RawSmb.Put32(b, 88, 0x80); RawSmb.Put32(b, 100, 1);
        var response = await d.Send(b); var id = Id(response); LeaseState(response, 3, 1); Check.That(Context(response, "DHnQ") != null, "RH stat-only open receives durable v1 grant");
        Check.Equal(1u, RawSmb.U32(response, 68), "stat-only durable open does not replace existing file"); await Close(d, id);
    }
    static async Task RetainedTwoOwners(string operation)
    {
        await using var f = new CacheFixture(true); var d = f.D; var owners = new List<((ulong P, ulong V) Id, Guid Guid, ulong Key, ushort Epoch)>();
        foreach (var key in new ulong[] { 1, 2 })
        {
            var guid = Guid.NewGuid(); var created = await Complete(f, Lease(ReplayCreate("none", guid, key), 3, key, true)); var id = Id(created); LeaseState(created, 3, key);
            Check.That(Context(created, "DH2Q") != null, "each independent RH owner receives actual durable grant"); owners.Add((id, guid, key, RawSmb.U16(Context(created, "RqLs")!, 48)));
        }
        await d.Dispatcher.OnConnectionClosedAsync(d.Connection); var peer = Session(f); peer.Connection.ClientGuid = Guid.NewGuid().ToByteArray(); var transport = new RecordingTransport(); transport.Attach(peer.Connection);
        var request = Create(access: operation == "stat" ? 0x100180u : All, share: operation == "share-none" ? 0u : 7u);
        if (operation is "rh" or "rwh") request = Lease(ReplayCreate("none", Guid.NewGuid(), 3), operation == "rh" ? 3u : 7u, 3, true);
        var response = await Send(f, peer, request); var idPeer = Id(response);
        if (operation is "rh" or "rwh") LeaseState(response, 3, 3);
        if (operation == "write") Status(await Send(f, peer, RawSmb.Write(idPeer, [7], 0, 0, 1, 42)), Ok, "write purges both disconnected READ owners");
        if (operation == "rename") Status(await Send(f, peer, Rename(idPeer, "renamed")), Ok, "rename purges both disconnected HANDLE owners");
        var claimant = Session(f, 3, 44); var keep = operation is "stat" or "rh" or "rwh";
        foreach (var owner in owners)
        {
            var reconnect = Lease(Reconnect(owner.Id, owner.Guid, false), 0, owner.Key, true, owner.Epoch); var claimed = await Send(f, claimant, reconnect);
            Status(claimed, keep ? Ok : Missing, "source keep/purge decision applies to every independent disconnected owner");
            if (keep) { LeaseState(claimed, 3, owner.Key); Check.Equal(owner.Epoch, RawSmb.U16(Context(claimed, "RqLs")!, 48), "retained epoch is independent per key"); Check.That(Context(claimed, "DH2Q") == null, "reconnect does not create another durable grant"); Status(await Send(f, claimant, RawSmb.Close(Id(claimed), 0, 1, 42)), Ok, "close individually reclaimed owner"); }
        }
        Status(await Send(f, peer, RawSmb.Close(idPeer, 0, 1, 42)), Ok, "close foreign acquisition after both claims checked");
    }
    static async Task DurableAllocationIgnored()
    {
        await using var f = new CacheFixture(true); var data = new byte[8]; RawSmb.Put64(data, 0, 4096); var guid = Guid.NewGuid(); var request = DurableRequest(true, guid, "lock-batch");
        // MS-SMB2 3.3.5.9.3: an unsupported AlSi context MUST be ignored.
        // This backend cannot reserve physical allocation; it must not report
        // the requested reservation or turn the optional context into a denial.
        var created = await f.D.Send(P7cTests.Context(request, "AlSi", data)); var id = Id(created);
        Check.Equal(0ul, RawSmb.U64(created, 104), "unsupported allocation context does not fabricate a physical reservation"); Check.Equal(0ul, RawSmb.U64(created, 112), "allocation request does not extend EOF");
        Check.That(Context(created, "DHnQ") != null, "ignored allocation context preserves ordinary durable grant"); await Write(f.D, id, Payload);
        await f.D.Dispatcher.OnConnectionClosedAsync(f.D.Connection); var session = Session(f); var recovered = Id(await Send(f, session, Reconnect(id, guid, true)));
        var read = await Send(f, session, RawSmb.Read(recovered, (uint)Payload.Length, 0, 0, 1, 42)); Status(read, Ok, "durable recovery after ignored optional allocation");
        Check.That(RawSmb.Buffer(read, read[66], RawSmb.U32(read, 68)).SequenceEqual(Payload), "allocation context does not compromise recovered bytes"); Status(await Send(f, session, RawSmb.Close(recovered, 0, 1, 42)), Ok, "close recovered allocation-context open");
    }
    static async Task DurableDeleteFreshCreate()
    {
        await using var f = new CacheFixture(true); var d = f.D; var request = DurableRequest(true, Guid.NewGuid(), "delete-on-close"); RawSmb.Put32(request, 96, 0); var old = Id(await d.Send(request)); await Write(d, old, [7]); await d.Dispatcher.OnConnectionClosedAsync(d.Connection);
        var s = Session(f); s.Connection.ClientGuid = Guid.NewGuid().ToByteArray(); var fresh = Create(disposition: 3, share: 0); fresh[67] = 9; RawSmb.Put32(fresh, 104, 0x1040);
        var response = await Send(f, s, fresh); var id = Id(response); Check.Equal(2u, RawSmb.U32(response, 68), "fresh client acquisition closes disconnected DELETE_ON_CLOSE owner before recreating name"); Check.Equal(0ul, RawSmb.U64(response, 112), "fresh object contains none of the old durable data");
        Check.That(Context(response, "DHnQ") == null, "ordinary new acquisition is not a durable grant"); Status(await Send(f, s, RawSmb.Close(id, 0, 1, 42)), Ok, "close new delete-on-close object"); Status(await Send(f, s, Create()), Missing, "fresh object also deletes on final close");
    }
}
