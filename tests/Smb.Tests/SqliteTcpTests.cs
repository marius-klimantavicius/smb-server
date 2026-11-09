using Smb.Host;
using Smb.FileSystem;
using Smb.FileSystem.Sqlite;
using Smb.Server;
using Smb.Testing;
using ProtectedPeer = MultichannelWireTests.Peer;

internal static partial class DurableRecoveryTcpTests
{
    public static IEnumerable<(string Name, Func<Task> Run)> SqliteCases()
    {
        foreach (ushort dialect in new ushort[] { 0x202, 0x210, 0x300, 0x302, 0x311 })
        {
            yield return ($"sqlite.tcp.io.{dialect:x}", () => SqliteWorkload.RunAsync(dialect));
            yield return ($"sqlite.tcp.durable.{dialect:x}", () => SqliteDurable(dialect));
        }
        foreach (ushort dialect in new ushort[] { 0x202, 0x300, 0x311 })
        {
            yield return ($"sqlite.tcp.authorization.{dialect:x}", () => SqliteAuthorization(dialect));
            yield return ($"sqlite.tcp.namespace.{dialect:x}", () => SqliteNamespace(dialect));
            yield return ($"sqlite.tcp.unsupported.{dialect:x}", () => SqliteUnsupported(dialect));
        }
        foreach (ushort dialect in new ushort[] { 0x300, 0x311 })
        foreach (bool encrypted in new[] { false, true })
        foreach (bool lease in new[] { false, true })
            yield return ($"sqlite.tcp.cache.{dialect:x}.{encrypted}.{lease}", () => SqliteCache(dialect, encrypted, lease));
    }
    sealed class SqliteFixture : IAsyncDisposable
    {
        internal readonly SqliteFileStore Store;
        internal readonly HostFixture Host = new();
        internal SmbServer Server => Host.Server;
        internal SqliteFixture(string database, SmbFeaturePolicy? policy = null)
        {
            Store = new SqliteFileStore(database);
            var o = Server.State.Options;
            o.Shares.Add(new Share { Name = "P0", FileStore = Store });
            o.Shares.Add(new Share { Name = "OTHER", FileStore = Store });
            if (policy is not null) o.FeaturePolicy = policy;
        }
        internal async Task<Peer> Connect(ushort dialect, Guid? guid = null)
        { var p = new Peer(); await p.Login(Server.Endpoint, dialect, guid ?? Guid.NewGuid()); return p; }
        public async ValueTask DisposeAsync() { await Host.DisposeAsync(); await Store.DisposeAsync(); }
    }
    static byte[] SqliteCreate(string name, uint disposition = 1, uint access = 0x1f01ff, bool directory = false)
        => ProfileCreate(name, disposition, access, directory);
    static async Task SqliteAuthorization(ushort dialect)
    {
        using var scratch = new SqliteProcessTests.Scratch(); byte[] security, metadata, index;
        await using (var f = new SqliteFixture(scratch.Database))
        {
            Check.Equal(SmbFeaturePolicy.Restricted, f.Server.State.Options.FeaturePolicy, "unchanged default");
            await f.Server.StartAsync(); await using var p = await f.Connect(dialect);
            var h = Id(await p.Exchange(SqliteCreate("sentinel", 2))); await p.Exchange(RawSmb.Write(h, Payload, 0, 0, 0, 0));
            var basic = new byte[40]; RawSmb.Put64(basic, 0, 132000000000000000); RawSmb.Put32(basic, 32, 2); await p.Exchange(Set(h, 4, basic));
            var sd = ProfileDescriptor(0x8004, 0, 0); RawSmb.Put32(sd, 56, 0x10002); // deny implicit write/truncate and DELETE
            await p.Exchange(ProfileSecuritySet(h, sd));
            security = ProfileOutput(await p.Exchange(ProfileSecurityQuery(h))); metadata = ProfileOutput(await p.Exchange(Query(h, 4))); index = ProfileOutput(await p.Exchange(Query(h, 6)));
            foreach (uint disposition in new uint[] { 0, 4, 5 })
            {
                var denied = SqliteCreate("sentinel", disposition, 1); RawSmb.Put32(denied, 92, 4);
                await p.Exchange(denied, Denied); await Bytes(p, h, Payload);
                Check.That(ProfileOutput(await p.Exchange(Query(h, 4))).SequenceEqual(metadata), "denied destructive CREATE preserves metadata");
                Check.That(ProfileOutput(await p.Exchange(ProfileSecurityQuery(h))).SequenceEqual(security), "denied destructive CREATE preserves descriptor");
                Check.That(ProfileOutput(await p.Exchange(Query(h, 6))).SequenceEqual(index), "denied destructive CREATE preserves identity");
            }
            var root = Id(await p.Exchange(SqliteCreate("", directory: true)));
            var rootSd = ProfileDescriptor(0x8004, 0, 0); RawSmb.Put32(rootSd, 56, 6); await p.Exchange(ProfileSecuritySet(root, rootSd));
            await p.Exchange(SqliteCreate("unauthorized", 2), Denied);
            await p.Exchange(SqliteCreate("unauthorized-dir", 2, directory: true), Denied);
            await p.Exchange(SqliteCreate("unauthorized", access: 1), Missing);
            await p.Exchange(SqliteCreate("unauthorized-dir", access: 1, directory: true), Missing);
            Check.That(await f.Store.ResolveIdentityAsync("unauthorized") is null, "denied new CREATE never publishes backend row");
            await p.Exchange(RawSmb.Close(root, 0, 0, 0)); await p.Exchange(RawSmb.Close(h, 0, 0, 0));
        }
        await using (var f = new SqliteFixture(scratch.Database))
        {
            await f.Server.StartAsync(); await using var p = await f.Connect(dialect);
            var h = Id(await p.Exchange(SqliteCreate("SENTINEL", access: 0x20081))); await Bytes(p, h, Payload);
            Check.That(ProfileOutput(await p.Exchange(ProfileSecurityQuery(h))).SequenceEqual(security), "security survives shutdown/reopen");
            Check.That(ProfileOutput(await p.Exchange(Query(h, 4))).SequenceEqual(metadata), "metadata survives shutdown/reopen");
            Check.That(ProfileOutput(await p.Exchange(Query(h, 6))).SequenceEqual(index), "index survives shutdown/reopen");
            await p.Exchange(SqliteCreate("unauthorized", 2), Denied); await p.Exchange(RawSmb.Close(h, 0, 0, 0));
        }
    }
    static async Task SqliteNamespace(ushort dialect)
    {
        using var scratch = new SqliteProcessTests.Scratch(); await using var f = new SqliteFixture(scratch.Database);
        f.Server.State.Options.MaxDirectoryEnumerationEntries = 3; await f.Server.StartAsync();
        await using var a = await f.Connect(dialect); await using var b = await f.Connect(dialect);
        var otherTree = await b.Exchange(RawSmb.TreeConnect(@"\\localhost\OTHER", 0, 0)); b.Tree = RawSmb.U32(otherTree, 36);
        var source = Id(await a.Exchange(SqliteCreate("source", 2))); var target = Id(await b.Exchange(SqliteCreate("target", 2)));
        await a.Exchange(RawSmb.Write(source, [1, 3, 5], 0, 0, 0, 0)); await b.Exchange(RawSmb.Write(target, [2, 4], 0, 0, 0, 0));
        var oldIndex = ProfileOutput(await b.Exchange(Query(target, 6))); var sourceIndex = ProfileOutput(await a.Exchange(Query(source, 6)));
        await a.Exchange(RenameRequest(source, "target", true)); await Bytes(a, source, [1, 3, 5]); await Bytes(b, target, [2, 4]);
        Check.That(ProfileOutput(await b.Exchange(Query(target, 6))).SequenceEqual(oldIndex), "replaced live open keeps identity");
        var current = Id(await a.Exchange(SqliteCreate("target"))); Check.That(ProfileOutput(await a.Exchange(Query(current, 6))).SequenceEqual(sourceIndex), "replacement name points to source identity");
        await a.Exchange(Set(source, 13, [1])); await b.Exchange(SqliteCreate("target"), 0xc0000056);
        await a.Exchange(Set(current, 13, [0])); var another = Id(await b.Exchange(SqliteCreate("target")));
        await a.Exchange(Set(source, 13, [1])); await a.Exchange(RawSmb.Close(source, 0, 0, 0)); await a.Exchange(RawSmb.Close(current, 0, 0, 0));
        await Bytes(b, another, [1, 3, 5]); await b.Exchange(SqliteCreate("target"), 0xc0000056);
        await b.Exchange(RawSmb.Close(another, 0, 0, 0)); await b.Exchange(SqliteCreate("target"), Missing); await Bytes(b, target, [2, 4]); await b.Exchange(RawSmb.Close(target, 0, 0, 0));
        var dir = Id(await a.Exchange(SqliteCreate("dir", 2, directory: true)));
        for (var i = 0; i < 17; i++) { var h = Id(await a.Exchange(SqliteCreate($"dir\\item-{i:D2}", 2))); await a.Exchange(RawSmb.Close(h, 0, 0, 0)); }
        await a.Exchange(RenameRequest(dir, "moved"));
        var names = new List<string>();
        for (var page = 0; page < 20; page++)
        {
            var request = RawSmb.Enumerate(dir, 0, 0, 0, "item-*", page == 0 ? (byte)1 : (byte)0); RawSmb.Put32(request, 92, 80);
            var response = await a.Exchange(request, names.Count == 17 ? 0x80000006u : 0);
            if (RawSmb.U32(response, 8) == 0x80000006) break;
            Check.That(RawSmb.U32(response, 68) <= 80, "wire page bounded by requested output");
            var next = RawSmb.Names(ProfileOutput(response)); Check.That(next.Length is > 0 and <= 3, "backend cursor cap respected"); names.AddRange(next);
        }
        Check.That(names.SequenceEqual(Enumerable.Range(0, 17).Select(i => $"item-{i:D2}")), "bounded enumeration exact once, complete after rename");
        await a.Exchange(RawSmb.Close(dir, 0, 0, 0));
    }
    static async Task SqliteUnsupported(ushort dialect)
    {
        using var scratch = new SqliteProcessTests.Scratch(); await using var f = new SqliteFixture(scratch.Database); await f.Server.StartAsync(); await using var p = await f.Connect(dialect);
        var h = Id(await p.Exchange(SqliteCreate("file", 2))); await p.Exchange(SqliteCreate("file:ads", 3), 0xc00000bb);
        // Explicit unnamed-stream spelling still opens the same object.
        var unnamed = Id(await p.Exchange(SqliteCreate("file::$DATA"))); await p.Exchange(RawSmb.Close(unnamed, 0, 0, 0));
        await p.Exchange(Set(h, 15, [0, 0, 0, 0, 0, 1, 1, 0, (byte)'x', 0, 9]), 0xc00000bb);
        var eas = await p.Exchange(Query(h, 15)); Check.Equal(0u, RawSmb.U32(eas, 68), "no EAs returned");
        var streams = ProfileOutput(await p.Exchange(Query(h, 22))); Check.Equal("::$DATA", System.Text.Encoding.Unicode.GetString(streams, 24, (int)RawSmb.U32(streams, 4)), "only unnamed stream advertised");
        var dir = Id(await p.Exchange(SqliteCreate("", directory: true))); var notify = RawSmb.Header(15, 32, 0); RawSmb.Put16(notify, 64, 32); RawSmb.Put32(notify, 68, 4096); RawSmb.Put64(notify, 72, dir.P); RawSmb.Put64(notify, 80, dir.V); RawSmb.Put32(notify, 88, 1);
        await p.Exchange(notify, 0xc00000bb);
        // Restricted declines requested durable/cache state.
        var request = Request(dialect < 0x300, Guid.NewGuid(), dialect >= 0x210 ? 7u : 0); var result = await p.Exchange(request);
        Check.Equal((byte)0, result[66], "Restricted grants no caching"); Check.That(Context(result, "DHnQ") is null && Context(result, "DH2Q") is null, "Restricted grants no durable state");
        await p.Exchange(RawSmb.Close(Id(result), 0, 0, 0)); await p.Exchange(RawSmb.Close(dir, 0, 0, 0)); await p.Exchange(RawSmb.Close(h, 0, 0, 0));
    }
    static async Task SqliteDurable(ushort dialect)
    {
        using var scratch = new SqliteProcessTests.Scratch(); var client = Guid.NewGuid(); var guid = Guid.NewGuid(); (ulong P, ulong V) old; byte[] index;
        await using (var f = new SqliteFixture(scratch.Database, SmbFeaturePolicy.Durable))
        {
            await f.Server.StartAsync(); await using var a = await f.Connect(dialect, client);
            var opened = await a.Exchange(Request(dialect < 0x300, guid)); old = Id(opened);
            Check.That(Context(opened, dialect < 0x300 ? "DHnQ" : "DH2Q") != null, "SQLite durable grant");
            index = ProfileOutput(await a.Exchange(Query(old, 6))); await a.Exchange(RawSmb.Write(old, Payload, 0, 0, 0, 0)); await a.Exchange(Lock(old, 0, 0x12));
            var session = a.Session; await a.DisposeAsync(); await Eventually(() => !f.Server.State.SessionGlobalList.ContainsKey(session), "SQLite durable owner detached");
            await using var b = await f.Connect(dialect, client); var next = Id(await b.Exchange(Reconnect(old, guid, dialect < 0x300)));
            Check.Equal(old.P, next.P, "durable FileId retains persistent part"); Check.That(old.V != next.V, "durable volatile part changes"); await Bytes(b, next, Payload);
            Check.That(ProfileOutput(await b.Exchange(Query(next, 6))).SequenceEqual(index), "reconnect object index");
            await using var competitor = await f.Connect(dialect);
            var contended = SqliteCreate("file"); competitor.Route(contended); competitor.Sign(contended); await competitor.Send(contended);
            var pending = await competitor.Receive(); Check.Equal(0x103u, RawSmb.U32(pending, 8), "second opener waits for recovered batch downgrade");
            var notice = await b.Receive(); Check.Equal((ushort)24, RawSmb.U16(notice, 64), "recovered batch break"); Check.Equal((byte)1, notice[66], "recovered batch target II");
            var ack = RawSmb.Header(18, 24, 0); RawSmb.Put16(ack, 64, 24); ack[66] = 1; RawSmb.Put64(ack, 72, next.P); RawSmb.Put64(ack, 80, next.V); await b.Exchange(ack);
            var completed = await competitor.Receive(); Check.Equal(0u, RawSmb.U32(completed, 8), "second opener after ACK"); Peer.Signature(completed, competitor.ChannelKey, dialect); var other = Id(completed);
            await competitor.Exchange(RawSmb.Write(other, [9], 0, 0, 0, 0), 0xc0000054);
            var invalidation = await b.Receive(); Check.Equal(ulong.MaxValue, RawSmb.U64(invalidation, 24), "write attempt invalidates recovered READ cache"); Check.Equal((byte)0, invalidation[66], "recovered READ cache target NONE");
            await b.Exchange(Lock(next, 1, 4));
            await competitor.Exchange(RawSmb.Write(other, [Payload[0]], 0, 0, 0, 0)); await competitor.Exchange(RawSmb.Close(other, 0, 0, 0));
            // Shutdown while this durable open is active drains SMB state before the store.
        }
        await using (var f = new SqliteFixture(scratch.Database, SmbFeaturePolicy.Durable))
        {
            await f.Server.StartAsync(); await using var p = await f.Connect(dialect, client); await p.Exchange(Reconnect(old, guid, dialect < 0x300), Missing);
            var h = Id(await p.Exchange(SqliteCreate("file"))); await Bytes(p, h, Payload); Check.That(ProfileOutput(await p.Exchange(Query(h, 6))).SequenceEqual(index), "data/index persist without SMB recovery records");
            await p.Exchange(Lock(h, 0, 0x12)); await p.Exchange(Lock(h, 1, 4)); await p.Exchange(RawSmb.Close(h, 0, 0, 0));
        }
    }
    static async Task SqliteCache(ushort dialect, bool encrypted, bool leased)
    {
        using var scratch = new SqliteProcessTests.Scratch(); await using var f = new SqliteFixture(scratch.Database, SmbFeaturePolicy.Caching);
        f.Server.State.Options.RequireEncryption = encrypted; await f.Host.StartAsync();
        await using var a = new ProtectedPeer(); await a.Login(f.Host, dialect, encrypted ? (ushort)1 : (ushort)0);
        await using var b = new ProtectedPeer(); await b.Login(f.Host, dialect, encrypted ? (ushort)1 : (ushort)0);
        var initial = SqliteCreate("file", 2); initial[67] = 9; if (leased) initial = Leased(initial, 7);
        var first = await a.Exchange(initial); var owner = Id(first);
        if (leased) Check.Equal(7u, RawSmb.U32(Context(first, "RqLs")!, 16), "SQLite full lease granted"); else Check.Equal((byte)9, first[66], "SQLite batch granted");
        await b.SendRequest(SqliteCreate("file")); var pending = await b.Receive(); Check.Equal(0x103u, RawSmb.U32(pending, 8), "conflict waits for ACK");
        var notice = await a.Receive(); Check.Equal(encrypted, a.LastEncrypted, "protected cache break"); if (!encrypted && (RawSmb.U32(notice, 16) & 8) != 0) a.Verify(notice);
        Check.Equal((ushort)18, RawSmb.U16(notice, 12), "break command"); Check.Equal(ulong.MaxValue, RawSmb.U64(notice, 24), "unsolicited break MID");
        byte[] ack;
        if (leased)
        {
            Check.Equal((ushort)44, RawSmb.U16(notice, 64), "lease break shape"); Check.Equal(7u, RawSmb.U32(notice, 88), "lease held RWH"); Check.Equal(3u, RawSmb.U32(notice, 92), "lease target RH");
            ack = RawSmb.Header(18, 36, 0); RawSmb.Put16(ack, 64, 36); notice.AsSpan(72, 16).CopyTo(ack.AsSpan(72)); RawSmb.Put32(ack, 88, 3);
        }
        else
        { Check.Equal((ushort)24, RawSmb.U16(notice, 64), "oplock break shape"); Check.Equal((byte)1, notice[66], "batch target II"); ack = RawSmb.Header(18, 24, 0); RawSmb.Put16(ack, 64, 24); ack[66] = 1; RawSmb.Put64(ack, 72, owner.P); RawSmb.Put64(ack, 80, owner.V); }
        await a.Exchange(ack); var opened = await b.Receive(); Check.Equal(0u, RawSmb.U32(opened, 8), "CREATE completes after ACK"); if (!encrypted) b.Verify(opened); else Check.That(b.LastEncrypted, "encrypted CREATE final"); var other = Id(opened);
        await b.SendRequest(RawSmb.Write(other, Payload, 0, 0, 0, 0));
        if (leased)
        {
            var wait = await b.Receive(); Check.Equal(0x103u, RawSmb.U32(wait, 8), "foreign WRITE waits for RH lease invalidation");
            var revoke = await a.Receive(); Check.Equal(3u, RawSmb.U32(revoke, 88), "RH current"); Check.Equal(0u, RawSmb.U32(revoke, 92), "lease target NONE"); RawSmb.Put32(ack, 88, 0); await a.Exchange(ack);
        }
        else { var revoke = await a.Receive(); Check.Equal((byte)0, revoke[66], "READ cache invalidated"); Check.Equal(encrypted, a.LastEncrypted, "invalidation protected"); if (!encrypted && (RawSmb.U32(revoke, 16) & 8) != 0) a.Verify(revoke); }
        var written = await b.Receive(); Check.Equal(0u, RawSmb.U32(written, 8), "write completes after invalidation"); if (!encrypted) b.Verify(written); else Check.That(b.LastEncrypted, "encrypted WRITE final");
        var read = await a.Exchange(RawSmb.Read(owner, (uint)Payload.Length, 0, 0, 0, 0)); Check.That(RawSmb.Buffer(read, read[66], RawSmb.U32(read, 68)).SequenceEqual(Payload), "coherent SQLite data after break/ACK");
        await b.Exchange(RawSmb.Close(other, 0, 0, 0)); await a.Exchange(RawSmb.Close(owner, 0, 0, 0)); Check.Equal(0, f.Server.State.Options.CacheCoordinator.GrantCount, "cache grants drain");
    }
}
