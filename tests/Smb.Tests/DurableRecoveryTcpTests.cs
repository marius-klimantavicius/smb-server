using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.Crypto;
using Smb.FileSystem;
using Smb.Host;
using Smb.Server;
using Smb.Testing;

// Public TCP acceptance for MS-SMB2 3.3.5.9.6/.7/.11/.12, 3.3.5.5.3 and 3.3.7.1.
// FileIds, statuses, contexts and retained bytes are wire oracles. Keys use BCL
// SP800-108/HMAC and SHA512 transcripts, independent of server KDF/transcript code.
internal static class DurableRecoveryTcpTests
{
    const uint Missing = 0xc0000034, Denied = 0xc0000022;
    static readonly byte[] Payload = "pinned durable object bytes"u8.ToArray();
    public static IEnumerable<(string Name, Func<Task> Run)> Cases()
    {
        foreach (var dialect in new ushort[] { 0x202, 0x210, 0x300, 0x302, 0x311 })
            foreach (var v1 in dialect < 0x300 ? new[] { true } : new[] { true, false })
            {
                foreach (var mode in new[] { "cycle", "previous", "claims", "expiry", "close", "tree", "logoff", "shutdown", "delete-retain", "rename" })
                    yield return ($"durable.tcp.{dialect:x}.v{(v1 ? 1 : 2)}.{mode}", () => Recovery(dialect, v1, mode));
                if (dialect >= 0x210)
                    foreach (var state in new uint[] { 3, 7 })
                        yield return ($"durable.tcp.{dialect:x}.v{(v1 ? 1 : 2)}.lease{state}", () => Recovery(dialect, v1, "lease", state));
                if (dialect >= 0x300)
                    yield return ($"durable.tcp.{dialect:x}.v{(v1 ? 1 : 2)}.lease-v2", () => Recovery(dialect, v1, "lease", 7, true));
                if (!v1) foreach (var mode in new[] { "disconnect", "previous", "active" })
                    yield return ($"durable.tcp.replay.{dialect:x}.{mode}", () => Replay(dialect, mode));
            }
        foreach (var dialect in new ushort[] { 0x210, 0x300, 0x302, 0x311 })
            yield return ($"durable.tcp.lock-replay.{dialect:x}", () => LockReplay(dialect));
        foreach (var dialect in new ushort[] { 0x202, 0x210 })
            yield return ($"durable.tcp.v2-ignored.{dialect:x}", () => V2Ignored(dialect));
        foreach (var dialect in new ushort[] { 0x202, 0x210, 0x300, 0x302, 0x311 })
            yield return ($"durable.tcp.claim-race.{dialect:x}", () => ClaimRace(dialect));
        foreach (var dialect in new ushort[] { 0x300, 0x302, 0x311 })
            foreach (var initialV1 in new[] { true, false })
                foreach (var leased in new[] { false, true })
                    yield return ($"durable.tcp.claim-matrix.{dialect:x}.{initialV1}.{leased}", () => ClaimMatrix(dialect, initialV1, leased));
        foreach (var dialect in new ushort[] { 0x300, 0x302, 0x311 })
            yield return ($"durable.tcp.replay.no-cache.{dialect:x}", () => ReplayNoCache(dialect));
        foreach (var dialect in new ushort[] { 0x210, 0x300, 0x302, 0x311 })
            foreach (var mode in new[] { "rh", "stat", "share", "delete" })
                yield return ($"durable.tcp.cache.{dialect:x}.{mode}", () => Cache(dialect, mode));
    }
    static async Task Eventually(Func<bool> predicate, string why)
    { using var timeout = new CancellationTokenSource(Check.Timeout); while (!predicate()) await Task.Delay(1, timeout.Token); Check.That(predicate(), why); }
    static byte[] Lock((ulong P, ulong V) id, uint sequence, uint flags)
    { var b = RawSmb.Header(10, 48, 0); RawSmb.Put16(b, 64, 48); RawSmb.Put16(b, 66, 1); RawSmb.Put32(b, 68, sequence); RawSmb.Put64(b, 72, id.P); RawSmb.Put64(b, 80, id.V); RawSmb.Put64(b, 96, 1); RawSmb.Put32(b, 104, flags); return b; }
    static byte[] Query((ulong P, ulong V) id, byte info)
    { var b = RawSmb.Header(16, 40, 0); RawSmb.Put16(b, 64, 41); b[66] = 1; b[67] = info; RawSmb.Put32(b, 68, 4096); RawSmb.Put64(b, 88, id.P); RawSmb.Put64(b, 96, id.V); return b; }
    static byte[] Set((ulong P, ulong V) id, byte info, byte[] data)
    { var b = RawSmb.Header(17, 32 + data.Length, 0); RawSmb.Put16(b, 64, 33); b[66] = 1; b[67] = info; RawSmb.Put32(b, 68, (uint)data.Length); RawSmb.Put16(b, 72, 96); RawSmb.Put64(b, 80, id.P); RawSmb.Put64(b, 88, id.V); data.CopyTo(b, 96); return b; }
    static async Task Cache(ushort dialect, string mode)
    {
        await using var f = new Fixture(); await f.Server.StartAsync(); var client = Guid.NewGuid(); var create = Guid.NewGuid(); var v1 = dialect == 0x210;
        await using var a = await f.Connect(dialect, client); var request = Request(v1, create, 3);
        if (mode == "delete") { RawSmb.Put32(request, 88, 0x10003); RawSmb.Put32(request, 104, 0x1040); }
        var first = await a.Exchange(request); var id = Id(first); await a.Exchange(RawSmb.Write(id, Payload, 0, 0, 0, 0)); var session = a.Session; await a.DisposeAsync();
        await Eventually(() => !f.Server.State.SessionGlobalList.ContainsKey(session), "cache owner detached");
        await using var peer = await f.Connect(dialect, Guid.NewGuid()); var fresh = RawSmb.Create("file", false, 0, 0, 0);
        if (mode == "rh") fresh = Leased(fresh, 3, 9);
        if (mode == "stat") RawSmb.Put32(fresh, 88, 0x80);
        if (mode is "share" or "delete") RawSmb.Put32(fresh, 96, 0);
        var opened = await peer.Exchange(fresh); var other = Id(opened);
        await using var owner = await f.Connect(dialect, client);
        var result = await owner.Exchange(Reconnect(id, create, v1, 3), mode is "stat" or "rh" ? 0u : Missing);
        if (mode is "stat" or "rh")
        { var restored = Id(result); var read = await owner.Exchange(RawSmb.Read(restored, (uint)Payload.Length, 0, 0, 0, 0)); Check.That(Payload.SequenceEqual(RawSmb.Buffer(read, read[66], RawSmb.U32(read, 68))), "compatible peer preserves disconnected bytes"); await owner.Exchange(RawSmb.Close(restored, 0, 0, 0)); }
        if (mode == "delete") { Check.Equal(2u, RawSmb.U32(opened, 68), "closed delete-on-close owner recreates name"); Check.Equal(0ul, RawSmb.U64(opened, 112), "new object has no stale bytes"); }
        await peer.Exchange(RawSmb.Close(other, 0, 0, 0));
    }
    sealed class Fixture : IAsyncDisposable
    {
        internal readonly P7cTests.Root Root = new();
        internal readonly ManualClock Clock = new();
        internal readonly SmbServer Server;
        internal Fixture()
        {
            Server = SmbServerBuilder.Create().WithEndpoint(IPAddress.Loopback, 0)
                .UseAuthentication(new NtlmSpnegoNegotiator(new InMemoryIdentityBackend()
                    .AddUser(HostFixture.Domain, HostFixture.User, HostFixture.Password)
                    .AddUser(HostFixture.Domain, "foreign", HostFixture.Password)))
                .AddShare(new Share { Name = "P0", FileStore = Root.Store() })
                .AddShare(new Share { Name = "OTHER", FileStore = Root.Store() })
                .Configure(o => { o.FeaturePolicy = SmbFeaturePolicy.Durable; o.TimeProvider = Clock; o.DurableHandleTimeout = TimeSpan.FromSeconds(2); }).Build();
        }
        internal async Task<Peer> Connect(ushort dialect, Guid client, ulong previous = 0, string? user = null)
        { var p = new Peer(); await p.Login(Server.Endpoint, dialect, client, previous, user); return p; }
        public async ValueTask DisposeAsync() { await Server.StopAsync(TimeSpan.Zero).WaitAsync(Check.Timeout); await Server.DisposeAsync(); Root.Dispose(); }
    }
    static byte[] Request(bool v1, Guid create, uint lease = 0, bool leaseV2 = false)
    {
        var b = RawSmb.Create("file", false, 0, 0, 0); b[67] = 9;
        var data = new byte[v1 ? 16 : 32]; if (!v1) { RawSmb.Put32(data, 0, 2000); create.ToByteArray().CopyTo(data, 16); }
        return Leased(P7cTests.Context(b, v1 ? "DHnQ" : "DH2Q", data), lease, v2: leaseV2);
    }
    static byte[] Leased(byte[] b, uint lease, ulong key = 1, bool v2 = false)
    {
        if (lease == 0) return b;
        var data = new byte[v2 ? 52 : 32]; RawSmb.Put64(data, 0, key); RawSmb.Put64(data, 8, 2); RawSmb.Put32(data, 16, lease); b[67] = 255;
        return P7cTests.Context(b, "RqLs", data);
    }
    static byte[] Reconnect((ulong P, ulong V) id, Guid create, bool v1, uint lease = 0, ulong key = 1, bool leaseV2 = false)
    {
        var data = new byte[v1 ? 16 : 36]; RawSmb.Put64(data, 0, id.P); RawSmb.Put64(data, 8, id.V); if (!v1) create.ToByteArray().CopyTo(data, 16);
        return Leased(P7cTests.Context(RawSmb.Create("file", false, 0, 0, 0), v1 ? "DHnC" : "DH2C", data), lease, key, leaseV2);
    }
    static byte[]? Context(byte[] b, string name)
    {
        int at = (int)RawSmb.U32(b, 144), end = at + (int)RawSmb.U32(b, 148);
        while (at >= 152 && at + 16 <= end && end <= b.Length)
        {
            if (Encoding.ASCII.GetString(b, at + RawSmb.U16(b, at + 4), RawSmb.U16(b, at + 6)) == name)
                return RawSmb.Buffer(b, at + RawSmb.U16(b, at + 10), RawSmb.U32(b, at + 12));
            var next = (int)RawSmb.U32(b, at); if (next == 0) break; Check.That(next >= 16 && next % 8 == 0, "bounded response contexts"); at += next;
        }
        return null;
    }
    static (ulong P, ulong V) Id(byte[] b) => (RawSmb.U64(b, 128), RawSmb.U64(b, 136));
    static async Task Recovery(ushort dialect, bool v1, string mode, uint lease = 0, bool leaseV2 = false)
    {
        await using var f = new Fixture(); await f.Server.StartAsync().WaitAsync(Check.Timeout);
        var client = Guid.NewGuid(); var create = Guid.NewGuid(); await using var a = await f.Connect(dialect, client);
        var request = Request(v1, create, lease, leaseV2);
        if (mode == "rename") RawSmb.Put32(request, 88, 0x10003);
        if (mode == "delete-retain") { RawSmb.Put32(request, 88, 0x10003); RawSmb.Put32(request, 104, 0x1040); }
        var initial = await a.Exchange(request); var id = Id(initial);
        Check.That(Context(initial, v1 ? "DHnQ" : "DH2Q") != null, "actual dialect-legal durable grant");
        if (lease != 0) Check.Equal(lease, RawSmb.U32(Context(initial, "RqLs")!, 16), "actual requested lease grant");
        await a.Exchange(RawSmb.Write(id, Payload, 0, 0, 0, 0));
        // Offset and locks are retained object state, interrogated through public SMB.
        var position = new byte[8]; RawSmb.Put64(position, 0, 17); await a.Exchange(Set(id, 14, position));
        await a.Exchange(Lock(id, 0x10, 2 | 16));
        if (mode == "rename")
        {
            var name = Encoding.Unicode.GetBytes("renamed"); var rename = new byte[20 + name.Length]; RawSmb.Put32(rename, 16, (uint)name.Length); name.CopyTo(rename, 20);
            await a.Exchange(Set(id, 10, rename));
        }
        var oldSession = a.Session;
        if (mode is "close" or "tree" or "logoff" or "shutdown")
        {
            if (mode == "close") await a.Exchange(RawSmb.Close(id, 0, 0, 0));
            if (mode == "tree") await a.Exchange(RawSmb.TreeDisconnect(0, 0, 0));
            if (mode == "logoff") { var b = RawSmb.Header(2, 4, 0); RawSmb.Put16(b, 64, 4); await a.Exchange(b); }
            if (mode == "shutdown") { await f.Server.StopAsync(TimeSpan.Zero); await f.Server.StartAsync(); }
            await using var denied = await f.Connect(dialect, client); await denied.Exchange(Reconnect(id, create, v1, lease, leaseV2: leaseV2), Missing); return;
        }
        if (mode != "previous")
        {
            await a.DisposeAsync();
            await Eventually(() => !f.Server.State.SessionGlobalList.ContainsKey(oldSession), "transport loss retired session");
        }
        if (mode == "expiry") f.Clock.Advance(TimeSpan.FromSeconds(3));
        await using var bpeer = await f.Connect(dialect, client, mode == "previous" ? oldSession : 0);
        if (mode == "expiry")
        {
            await bpeer.Exchange(Reconnect(id, create, v1, lease, leaseV2: leaseV2), Missing);
            var fresh = RawSmb.Create("file", false, 0, 0, 0); RawSmb.Put32(fresh, 96, 0); var free = Id(await bpeer.Exchange(fresh));
            await bpeer.Exchange(Lock(free, 0, 2 | 16)); await bpeer.Exchange(RawSmb.Close(free, 0, 0, 0)); return;
        }
        if (mode == "claims")
        {
            await using var foreign = await f.Connect(dialect, client, user: "foreign"); await foreign.Exchange(Reconnect(id, create, v1, lease, leaseV2: leaseV2), Denied);
            if (!v1) await bpeer.Exchange(Reconnect(id, Guid.NewGuid(), v1, lease), Missing);
            var otherTree = await bpeer.Exchange(RawSmb.TreeConnect(@"\\localhost\OTHER", 0, 0));
            var tree = bpeer.Tree; bpeer.Tree = RawSmb.U32(otherTree, 36); await bpeer.Exchange(Reconnect(id, create, v1, lease, leaseV2: leaseV2), Missing); bpeer.Tree = tree;
        }
        if (lease != 0)
        {
            await bpeer.Exchange(Reconnect(id, create, v1), Missing);
            await bpeer.Exchange(Reconnect(id, create, v1, lease, 9, leaseV2), Missing);
            await using var foreignClient = await f.Connect(dialect, Guid.NewGuid()); await foreignClient.Exchange(Reconnect(id, create, v1, lease, leaseV2: leaseV2), Missing);
        }
        for (var cycle = 0; cycle < (mode == "cycle" ? 2 : 1); cycle++)
        {
            // Only Persistent participates in lookup, per 3.3.5.9.7/.12.
            var recovered = await bpeer.Exchange(Reconnect((id.P, ulong.MaxValue), create, v1, lease, leaseV2: leaseV2)); var next = Id(recovered);
            Check.Equal(id.P, next.P, "persistent FileId unchanged"); Check.That(id.V != next.V, "new volatile FileId");
            Check.Equal(1u, RawSmb.U32(recovered, 68), "reconnect action OPENED");
            Check.That(Context(recovered, "DH2Q") == null && Context(recovered, "DHnQ") == null, "reconnect does not renew durable grant");
            await bpeer.Exchange(Reconnect(id, create, v1, lease, leaseV2: leaseV2), Missing);
            var all = await bpeer.Exchange(Query(next, 14)); var data = RawSmb.Buffer(all, RawSmb.U16(all, 66), RawSmb.U32(all, 68));
            Check.Equal(17ul, RawSmb.U64(data, 0), "byte position retained");
            var read = await bpeer.Exchange(RawSmb.Read(next, (uint)Payload.Length, 0, 0, 0, 0));
            Check.That(Payload.SequenceEqual(RawSmb.Buffer(read, read[66], RawSmb.U32(read, 68))), "retained exact bytes");
            await bpeer.Exchange(Lock(next, 0x11, 4)); id = next;
            if (cycle == 0 && mode == "cycle")
            {
                await bpeer.Exchange(Lock(id, 0x12, 2 | 16)); var session = bpeer.Session; await bpeer.DisposeAsync();
                await Eventually(() => !f.Server.State.SessionGlobalList.ContainsKey(session), "second loss completed");
                // Reuse the wrapper with a new TCP transport; no private session/open injection.
                await bpeer.ReconnectTransport(f.Server.Endpoint, dialect, client);
            }
        }
        await bpeer.Exchange(RawSmb.Close(id, 0, 0, 0));
        if (mode == "delete-retain") { var absent = RawSmb.Create("file", false, 0, 0, 0); RawSmb.Put32(absent, 100, 1); await bpeer.Exchange(absent, Missing); }
        if (mode == "rename") { var exists = RawSmb.Create("renamed", false, 0, 0, 0); RawSmb.Put32(exists, 100, 1); var other = Id(await bpeer.Exchange(exists)); await bpeer.Exchange(RawSmb.Close(other, 0, 0, 0)); }
    }
    sealed class PausedInfo(IFileHandle inner, AsyncBarrier gate) : IFileHandle
    {
        public FileIdentity? Identity => inner.Identity; public string Path => inner.Path; public bool IsDirectory => inner.IsDirectory;
        public string? PhysicalPath => inner.PhysicalPath; public bool DeletePending => inner.DeletePending;
        public FileEntryInfo GetInfo() => inner.GetInfo();
        public async ValueTask<FileEntryInfo> GetInfoAsync(CancellationToken ct = default) { await gate.WaitAsync(ct); return await inner.GetInfoAsync(ct); }
        public void Dispose() => inner.Dispose(); public ValueTask DisposeAsync() => inner.DisposeAsync(); public ValueTask<Smb.Protocol.Enums.NtStatus> CloseAsync() => inner.CloseAsync();
    }
    static async Task ClaimRace(ushort dialect)
    {
        await using var f = new Fixture(); await f.Server.StartAsync(); var client = Guid.NewGuid(); var create = Guid.NewGuid(); var v1 = dialect < 0x300;
        await using var a = await f.Connect(dialect, client); var id = Id(await a.Exchange(Request(v1, create))); var session = a.Session;
        var open = f.Server.State.SessionGlobalList[session].Opens[id]; await a.DisposeAsync(); await Eventually(() => !f.Server.State.SessionGlobalList.ContainsKey(session), "race owner detached");
        await using var b = await f.Connect(dialect, client); await using var c = await f.Connect(dialect, client);
        // Scheduling hook only: the open and retained record were granted over TCP.
        var inner = open.LocalOpen!; var gate = new AsyncBarrier(); open.LocalOpen = new PausedInfo(inner, gate);
        var winner = b.Exchange(Reconnect(id, create, v1)); await gate.Entered;
        var loser = c.Exchange(Reconnect(id, create, v1), Missing);
        try { Check.That(!winner.IsCompleted && !loser.IsCompleted, "first claim owns suspended metadata; second waits for the same retained open"); }
        finally { gate.Release(); }
        var response = await winner.WaitAsync(Check.Timeout); await loser.WaitAsync(Check.Timeout);
        open.LocalOpen = inner; Check.Equal(id.P, Id(response).P, "race winner retains original identity"); await b.Exchange(RawSmb.Close(Id(response), 0, 0, 0));
    }
    static async Task V2Ignored(ushort dialect)
    {
        await using var f = new Fixture(); await f.Server.StartAsync(); await using var a = await f.Connect(dialect, Guid.NewGuid());
        var response = await a.Exchange(Request(false, Guid.NewGuid()));
        Check.That(Context(response, "DH2Q") == null, "v2 grants are restricted to SMB3"); await a.Exchange(RawSmb.Close(Id(response), 0, 0, 0));
    }
    static async Task LockReplay(ushort dialect)
    {
        await using var f = new Fixture(); await f.Server.StartAsync(); var client = Guid.NewGuid(); var create = Guid.NewGuid(); var v1 = dialect == 0x210;
        await using var a = await f.Connect(dialect, client); var id = Id(await a.Exchange(Request(v1, create))); var session = a.Session;
        await a.Exchange(Lock(id, 0x11, 0x12)); await a.DisposeAsync(); await Eventually(() => !f.Server.State.SessionGlobalList.ContainsKey(session), "LOCK replay owner detached");
        await using var b = await f.Connect(dialect, client); var restored = Id(await b.Exchange(Reconnect(id, create, v1)));
        await b.Exchange(Lock(restored, 0x11, 0x12)); // Duplicate grant must not acquire a second lock.
        await b.Exchange(Lock(restored, 0x12, 4)); await b.Exchange(Lock(restored, 0x12, 4));
        await b.Exchange(Lock(restored, 0x13, 4), 0xc000007e); // Fresh unlock proves the original grant was released exactly once.
        await b.Exchange(Lock(restored, 0x14, 0x12)); await b.Exchange(RawSmb.Close(restored, 0, 0, 0));
    }
    static async Task ClaimMatrix(ushort dialect, bool initialV1, bool leased)
    {
        await using var f = new Fixture(); await f.Server.StartAsync(); var client = Guid.NewGuid(); var create = initialV1 ? Guid.Empty : Guid.NewGuid();
        await using var a = await f.Connect(dialect, client); var first = await a.Exchange(Request(initialV1, create, leased ? 3u : 0)); var id = Id(first); var session = a.Session;
        await a.DisposeAsync(); await Eventually(() => !f.Server.State.SessionGlobalList.ContainsKey(session), "claim matrix owner detached");
        await using var b = await f.Connect(dialect, client);
        if (leased)
        {
            var wrongVersion = Reconnect(id, create, false); var data = new byte[52]; RawSmb.Put64(data, 0, 1); RawSmb.Put64(data, 8, 2);
            wrongVersion = P7cTests.Context(wrongVersion, "RqLs", data); await b.Exchange(wrongVersion, Missing);
            var wrongName = Reconnect(id, create, true, 3); // name length is fixed at eight UTF16 bytes.
            Encoding.Unicode.GetBytes("xxxx").CopyTo(wrongName, 120); await b.Exchange(wrongName, 0xc000000d);
            var wrongV2Name = Reconnect(id, create, false, 3); Encoding.Unicode.GetBytes("xxxx").CopyTo(wrongV2Name, 120); await b.Exchange(wrongV2Name, Missing);
        }
        var flags = Reconnect(id, create, false, leased ? 3u : 0); var at = (int)RawSmb.U32(flags, 112); RawSmb.Put32(flags, at + 24 + 32, 2);
        await b.Exchange(flags, 0xc000000d); // Ordinary opens never acquire persistent semantics.
        var conflict = P7cTests.Context(Reconnect(id, create, false, leased ? 3u : 0), "DHnQ", new byte[16]); await b.Exchange(conflict, Missing);
        // Cross-version recovery is legal: Persistent lookup is authoritative. A
        // v1 original has zero CreateGuid and can satisfy a v2 zero-GUID claim.
        var valid = Reconnect(id, create, !initialV1, leased ? 3u : 0); var restored = Id(await b.Exchange(valid)); Check.Equal(id.P, restored.P, "legal cross-version retained identity");
        await b.Exchange(RawSmb.Close(restored, 0, 0, 0));
    }
    static async Task ReplayNoCache(ushort dialect)
    {
        await using var f = new Fixture(); await f.Server.StartAsync(); await using var a = await f.Connect(dialect, Guid.NewGuid()); var create = Guid.NewGuid();
        var request = Request(false, create); request[67] = 0; var first = await a.Exchange(request); var id = Id(first);
        Check.Equal((byte)0, first[66], "ordinary no-cache grant"); Check.That(Context(first, "DH2Q") == null, "durability declined without cache promise");
        RawSmb.Put32(request, 16, 0x20000000); var replay = await a.Exchange(request);
        Check.Equal(id, Id(replay), "completed v2 CREATE replay even when durability declined"); Check.Equal(2u, RawSmb.U32(replay, 68), "original action preserved");
        await a.Exchange(RawSmb.Close(id, 0, 0, 0));
    }
    static async Task Replay(ushort dialect, string mode)
    {
        await using var f = new Fixture(); await f.Server.StartAsync(); var client = Guid.NewGuid(); var create = Guid.NewGuid();
        await using var a = await f.Connect(dialect, client); var initial = await a.Exchange(Request(false, create)); var id = Id(initial); var session = a.Session;
        Check.That(Context(initial, "DH2Q") != null, "actual replay-eligible durable grant");
        if (mode == "disconnect") { await a.DisposeAsync(); await Eventually(() => !f.Server.State.SessionGlobalList.ContainsKey(session), "loss completed"); }
        await using var b = await f.Connect(dialect, client, mode == "previous" ? session : 0);
        var req = Request(false, create); RawSmb.Put32(req, 16, 0x20000000);
        await b.Exchange(req, 0xc000022a); // 3.3.5.9: a different session cannot replay an ordinary open.
        if (mode == "active") return;
        await b.Exchange(Reconnect(id, create, false));
        var response = await b.Exchange(req);
        var recovered = Id(response); Check.Equal(id.P, recovered.P, "CREATE replay recovers retained identity"); Check.Equal(2u, RawSmb.U32(response, 68), "original CREATED action retained");
        var again = await b.Exchange(req); Check.Equal(recovered, Id(again), "repeated replay stable identity");
        await b.Exchange(RawSmb.Write(recovered, Payload, 0, 0, 0, 0));
        var read = await b.Exchange(RawSmb.Read(recovered, (uint)Payload.Length, 0, 0, 0, 0)); Check.That(Payload.SequenceEqual(RawSmb.Buffer(read, read[66], RawSmb.U32(read, 68))), "replay recovered handle usable");
        await b.Exchange(RawSmb.Close(recovered, 0, 0, 0));
    }
    sealed class Peer : IAsyncDisposable
    {
        TcpClient client = new(); byte[] preauth = new byte[64]; ulong mid;
        public ulong Session; public uint Tree; public ushort Dialect; public byte[] SessionKey = [], ChannelKey = [];
        public ulong Next() => mid++;
        public void Route(byte[] b, bool sessionSetup = false)
        { RawSmb.Put64(b, 24, Next()); RawSmb.Put64(b, 40, Session); if (!sessionSetup) RawSmb.Put32(b, 36, Tree); }
        public void Sign(byte[] b)
        {
            if (ChannelKey.Length == 0) return;
            RawSmb.Put32(b, 16, RawSmb.U32(b, 16) | 8); b.AsSpan(48, 16).Clear();
            (Dialect < 0x300 ? HMACSHA256.HashData(ChannelKey, b)[..16] : AesCmac.Compute(ChannelKey, b)).CopyTo(b, 48);
        }
        public async Task Send(byte[] b)
        {
            using var timeout = new CancellationTokenSource(Check.Timeout); var frame = new byte[4 + b.Length];
            frame[1] = (byte)(b.Length >> 16); frame[2] = (byte)(b.Length >> 8); frame[3] = (byte)b.Length; b.CopyTo(frame, 4);
            await client.GetStream().WriteAsync(frame, timeout.Token);
        }
        public async Task<byte[]> Receive()
        {
            using var timeout = new CancellationTokenSource(Check.Timeout); var prefix = new byte[4]; await client.GetStream().ReadExactlyAsync(prefix, timeout.Token);
            Check.Equal((byte)0, prefix[0], "direct TCP framing"); var length = prefix[1] << 16 | prefix[2] << 8 | prefix[3];
            Check.That(length is >= 64 and <= 1048576, "bounded TCP response"); var b = new byte[length]; await client.GetStream().ReadExactlyAsync(b, timeout.Token); return b;
        }
        public async Task<byte[]> Exchange(byte[] b, uint status = 0, bool sessionSetup = false)
        {
            Route(b, sessionSetup); Sign(b); await Send(b); var response = await Receive();
            Check.Equal(RawSmb.U64(b, 24), RawSmb.U64(response, 24), "response MessageId");
            Check.Equal(RawSmb.U16(b, 12), RawSmb.U16(response, 12), "response command"); Check.Equal(status, RawSmb.U32(response, 8), "TCP response status"); if (ChannelKey.Length != 0 && status != 0xc0000203) Signature(response, ChannelKey, Dialect); return response;
        }
        public async Task Negotiate(IPEndPoint endpoint, ushort dialect, Guid clientGuid)
        {
            using var timeout = new CancellationTokenSource(Check.Timeout); await client.ConnectAsync(endpoint, timeout.Token); Dialect = dialect;
            var b = RawSmb.Negotiate(); RawSmb.Put16(b, 100, dialect); RawSmb.Put32(b, 72, 8);
            if (dialect == 0x311)
            {
                Array.Resize(ref b, 132); RawSmb.Put32(b, 92, 104); RawSmb.Put16(b, 96, 2);
                RawSmb.Put16(b, 104, 1); RawSmb.Put16(b, 106, 6); RawSmb.Put16(b, 112, 1); RawSmb.Put16(b, 116, 1);
                RawSmb.Put16(b, 120, 8); RawSmb.Put16(b, 122, 4); RawSmb.Put16(b, 128, 1); RawSmb.Put16(b, 130, 1);
            }
            clientGuid.ToByteArray().CopyTo(b, 76); var response = await Exchange(b); Check.Equal(dialect, RawSmb.U16(response, 68), "actual negotiated dialect");
            Check.That((RawSmb.U16(response, 66) & 2) != 0, "required signing retained");
            if (dialect == 0x311) { Append(b); Append(response); }
        }
        void Append(byte[] b) => preauth = SHA512.HashData(preauth.Concat(b).ToArray());
        byte[] Key(NtlmClient ntlm)
        {
            if (Dialect < 0x300) return ntlm.ExportedSessionKey;
            var label = Encoding.ASCII.GetBytes(Dialect == 0x311 ? "SMBSigningKey\0" : "SMB2AESCMAC\0");
            var context = Dialect == 0x311 ? preauth : "SmbSign"u8.ToArray().Concat(new byte[] { 0 }).ToArray();
            var input = new byte[4 + label.Length + 1 + context.Length + 4]; input[3] = 1;
            label.CopyTo(input, 4); context.CopyTo(input, 5 + label.Length); input[^1] = 128;
            return HMACSHA256.HashData(ntlm.ExportedSessionKey, input)[..16];
        }
        static void Signature(byte[] b, byte[] key, ushort dialect)
        {
            Check.That((RawSmb.U32(b, 16) & 8) != 0, "signed TCP response"); var copy = b.ToArray(); copy.AsSpan(48, 16).Clear();
            Check.That((dialect < 0x300 ? HMACSHA256.HashData(key, copy)[..16] : AesCmac.Compute(key, copy)).SequenceEqual(b.AsSpan(48, 16).ToArray()), "independently derived key verifies signature");
        }
        public async Task Login(IPEndPoint endpoint, ushort dialect, Guid clientGuid, ulong previous = 0, string? user = null)
        {
            await Negotiate(endpoint, dialect, clientGuid); var ntlm = new NtlmClient(HostFixture.Domain, user ?? HostFixture.User, HostFixture.Password);
            var b = RawSmb.SessionSetup(ntlm.BuildNegotiate(), 0); RawSmb.Put64(b, 80, previous); var challenge = await Exchange(b, 0xc0000016, true); Session = RawSmb.U64(challenge, 40);
            if (dialect == 0x311) { Append(b); Append(challenge); }
            b = RawSmb.SessionSetup(ntlm.BuildAuthenticate(RawSmb.Buffer(challenge, RawSmb.U16(challenge, 68), RawSmb.U16(challenge, 70))), 0, Session);
            RawSmb.Put64(b, 80, previous); var success = await Exchange(b, sessionSetup: true); if (dialect == 0x311) Append(b);
            SessionKey = ChannelKey = Key(ntlm); Signature(success, SessionKey, dialect);
            var tree = await Exchange(RawSmb.TreeConnect("\\\\localhost\\P0", 0, Session)); Tree = RawSmb.U32(tree, 36); Signature(tree, ChannelKey, dialect);
        }
        public async Task ReconnectTransport(IPEndPoint endpoint, ushort dialect, Guid clientGuid)
        { client = new TcpClient(); mid = 0; Session = 0; Tree = 0; ChannelKey = []; SessionKey = []; preauth = new byte[64]; await Login(endpoint, dialect, clientGuid); }
        public ValueTask DisposeAsync() { client.Dispose(); return ValueTask.CompletedTask; }
    }
}
