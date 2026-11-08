using Smb.Server;
using Smb.FileSystem;
using Smb.Testing;

internal static partial class UpstreamSambaMoreTests
{
    static IEnumerable<(string Name, Func<Task> Run)> AdditionalCases()
    {
        foreach (var first in new uint[] { 1, 2, 3 })
            foreach (var second in new uint[] { 1, 2, 3 })
                yield return ($"upstream.samba.more.deny.access-pair.{first}.{second}", () => DenyPairs(first, second));
        yield return ("upstream.samba.more.attributes.open-if-does-not-change", OpenIfAttributes);
        foreach (var path in new[] { "file", "file:stream", "", "directory" })
            yield return ($"upstream.samba.more.snapshot.unavailable.{(path.Length == 0 ? "root" : path.Replace(':', '-'))}", () => TimewarpUnavailable(path));
        foreach (var length in new ushort[] { 4, 5, 6, 7, 8, 16, 17, 34 })
            yield return ($"upstream.samba.more.context.unknown-name.{length}", () => UnknownCreateContext(length));
        yield return ("upstream.samba.more.lock.zero-count", ZeroLockCount);
        yield return ("upstream.samba.more.lock.reserved-sequence-ignored-202", LockReserved);
        yield return ("upstream.samba.more.lock.repeated-conflict-status", RepeatedConflict);
        yield return ("upstream.samba.more.lock.pid-independent-unlock", PidUnlock);
        yield return ("upstream.samba.more.set.mode-unsupported", SetModeUnsupported);
        yield return ("upstream.samba.more.set.absent-zero-ea", AbsentZeroEa);
        yield return ("upstream.samba.more.delete.second-tree-lifetime", DeleteSecondTree);
        yield return ("upstream.samba.more.quota.unsupported", QuotaUnsupported);
        yield return ("upstream.samba.more.stream.backend-no-streams", BackendNoStreams);
        yield return ("upstream.samba.more.stream.case-aliases", StreamCaseAliases);
        yield return ("upstream.samba.more.ioctl.stream-object-id-unsupported", StreamObjectIdUnsupported);
        yield return ("upstream.samba.more.query.source-access-table", QuerySourceAccess);
        yield return ("upstream.samba.more.context.metadata-optional", MetadataContexts);
        yield return ("upstream.samba.more.pipe.lsarpc-unavailable", LsaUnavailable);
        foreach (var directory in new[] { false, true })
            yield return ($"upstream.samba.more.attributes.set-preserves-security.{directory}", () => AttributeSecurity(directory));
        yield return ("upstream.samba.more.stream.creation-time-lifetime", StreamCreationLifetime);
        yield return ("upstream.samba.more.set.change-time-atomic-rejection", ChangeTimeRejected);
        foreach (var mode in new[] { "tree", "logoff", "close" })
            foreach (var v1 in new[] { false, true })
                yield return ($"upstream.samba.more.durable.explicit-teardown.{mode}.{v1}", () => ExplicitDurableTeardown(mode, v1));
    }
    static async Task DenyPairs(uint firstAccess, uint secondAccess)
    {
        // Nine access-pair workflows, each has sixteen share-mask partitions in
        // each source session arrangement and both source filename categories.
        // These are not 576 independently registered tests.
        await using var h = await UpstreamLocalFixture.StartAsync(); await using var a = await h.ConnectAsync(); await using var b = await h.ConnectAsync();
        foreach (var ext in new[] { "dat", "exe" })
        {
            var seed = await a.CreateAsync("deny." + ext); await a.WriteAsync(seed, [41]); await a.CloseAsync(seed);
            foreach (var same in new[] { false, true })
                foreach (var firstShare in new uint[] { 0, 5, 6, 7 })
                    foreach (var secondShare in new uint[] { 0, 5, 6, 7 })
                    {
                        var c = same ? a : b;
                        var one = Create("deny." + ext, access: firstAccess, share: firstShare); var owner = Id(await a.ExchangeAsync(Route(one, a)));
                        var two = Create("deny." + ext, access: secondAccess, share: secondShare);
                        var allowed = ((firstShare & secondAccess) == secondAccess) && ((secondShare & firstAccess) == firstAccess);
                        var response = await c.ExchangeAsync(Route(two, c), allowed ? Ok : Sharing, allowed ? (ushort)89 : (ushort)9);
                        if (allowed)
                        {
                            var peer = Id(response);
                            var read = await c.ExchangeAsync(Route(RawSmb.Read(peer, 1, 0, 0, 1, 42), c), (secondAccess & 1) != 0 ? Ok : Denied, (secondAccess & 1) != 0 ? (ushort)17 : (ushort)9);
                            if ((secondAccess & 1) != 0) Check.Equal(1u, RawSmb.U32(read, 68), "allowed READ transfers one byte");
                            await c.ExchangeAsync(Route(RawSmb.Write(peer, [41], 0, 0, 1, 42), c), (secondAccess & 2) != 0 ? Ok : Denied, (secondAccess & 2) != 0 ? (ushort)17 : (ushort)9);
                            await c.CloseAsync(peer);
                        }
                        await a.CloseAsync(owner);
                    }
        }
    }
    static async Task OpenIfAttributes()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var b = Create(disposition: 3, access: 1, share: 0); RawSmb.Put32(b, 92, 0x20);
        await Close(d, Id(await d.Send(b))); b = Create(disposition: 3, access: 1, share: 0); RawSmb.Put32(b, 92, 0x27);
        var response = await d.Send(b); var id = Id(response); Check.Equal(0x20u, RawSmb.U32(response, 120), "OPEN_IF existing ignores requested replacement attributes"); await Close(d, id);
    }
    static async Task StreamObjectIdUnsupported()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var b = Create(disposition: 2); RawSmb.Put32(b, 92, 2);
        var file = Id(await d.Send(b)); await Write(d, file, Payload); await Close(d, file); var stream = await Open(d, "file:stream", 2); await Write(d, stream, [7, 11, 13]);
        Status(await d.Send(P5Tests.Ioctl(stream, 0x900c0, [], 64)), 0xc0000010, "optional object-ID FSCTL on a valid stream is unsupported");
        await Data(d, stream, [7, 11, 13]); var original = await Open(d); await Data(d, original, Payload);
        Check.That((RawSmb.U32(Output(await d.Send(Query(original, 4))), 32) & 2) != 0, "stream IOCTL rejection preserves hidden base attributes");
        Check.That((await StreamNames(d, original)).Order().SequenceEqual(new[] { "::$DATA", ":stream:$DATA" }.Order()), "stream IOCTL rejection preserves both stream names");
    }
    static async Task TimewarpUnavailable(string path)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        await Close(d, await Open(d, disposition: 3)); await Close(d, await Open(d, "file:stream", 3)); await Close(d, await Open(d, "directory", 3, directory: true));
        var data = new byte[8]; RawSmb.Put64(data, 0, 10000);
        var response = await d.Send(P7cTests.Context(Create(path, directory: path is "" or "directory"), "TWrp", data));
        Status(response, Missing, "unavailable historical snapshot cannot fall back to live namespace");
    }
    static async Task UnknownCreateContext(ushort length)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        var request = Create(disposition: 3); var start = (request.Length + 7) & ~7; var size = (16 + length + 7) & ~7;
        Array.Resize(ref request, start + size); RawSmb.Put16(request, start + 4, 16); RawSmb.Put16(request, start + 6, length);
        request.AsSpan(start + 16, length).Fill((byte)'x'); RawSmb.Put32(request, 112, (uint)start); RawSmb.Put32(request, 116, (uint)size);
        var id = Id(await d.Send(request)); await Write(d, id, Payload); await Data(d, id, Payload);
    }
    static async Task ZeroLockCount()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var id = await Open(d, disposition: 3); var b = Lock(id, 0, 0, 0); RawSmb.Put16(b, 66, 0);
        Status(await d.Send(b), Invalid, "zero-element LOCK invalid"); b = Lock(id, 0, 0, 1); RawSmb.Put16(b, 66, 0);
        Status(await d.Send(b), Invalid, "nonzero flags cannot make zero-count LOCK valid");
    }
    static async Task LockReserved()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var id = await Open(d, disposition: 3); var b = Lock(id, uint.MaxValue, uint.MaxValue);
        RawSmb.Put32(b, 68, 0x12345678); RawSmb.Put32(b, 108, 0x87654321); var response = await d.Send(b); Status(response, Ok, "SMB202 ignores LockSequence and element Reserved");
        Check.Equal((ushort)0, RawSmb.U16(response, 66), "LOCK response reserved zero"); Status(await d.Send(Lock(id, uint.MaxValue, uint.MaxValue, 4)), Ok, "ignored request fields do not alter exact range");
    }
    static async Task RepeatedConflict()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var a = await Open(d, disposition: 3); var b = await Open(d);
        Status(await d.Send(Lock(a, 100, 10)), Ok, "seed lock");
        foreach (var id in new[] { a, b, a, b })
        {
            var req = Lock(id, 100, 10); RawSmb.Put32(req, 32, 0x12345678);
            Status(await d.Send(req), 0xc0000055, "every conflict remains LOCK_NOT_GRANTED regardless of request count/ProcessId");
        }
        Status(await d.Send(Lock(a, 100, 10, 4)), Ok, "conflict probes preserve original ownership");
    }
    static async Task PidUnlock()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var a = await Open(d, disposition: 3); var b = await Open(d);
        Status(await d.Send(Lock(a, 0, 10)), Ok, "acquire with original ProcessId"); var unlock = Lock(a, 0, 10, 4); RawSmb.Put32(unlock, 32, 0x12345678);
        Status(await d.Send(unlock), Ok, "ProcessId is not SMB2 lock ownership"); Status(await d.Send(unlock), 0xc000007e, "second unlock cannot fabricate a grant");
        Status(await d.Send(Lock(b, 0, 10)), Ok, "different open can acquire after owner unlock with changed PID");
    }
    static async Task ExplicitDurableTeardown(string mode, bool v1)
    {
        await using var f = new CacheFixture(true); var d = f.D; var guid = Guid.NewGuid(); var id = Id(await d.Send(DurableRequest(v1, guid, "lock-batch")));
        if (mode == "close") await Close(d, id);
        else if (mode == "tree") Status(await d.Send(RawSmb.TreeDisconnect(0, 1, 42)), Ok, "explicit TDIS closes durable open");
        else { var b = RawSmb.Header(2, 4, 0, 1); RawSmb.Put16(b, 64, 4); Status(await d.Send(b), Ok, "explicit LOGOFF closes durable open"); }
        var s = Session(f); var data = new byte[v1 ? 16 : 36]; RawSmb.Put64(data, 0, id.P); RawSmb.Put64(data, 8, id.V); if (!v1) guid.ToByteArray().CopyTo(data, 16);
        Status(await Send(f, s, P7cTests.Context(Create(), v1 ? "DHnC" : "DH2C", data)), Missing, "explicit close/teardown is not a transport disconnect retention event");
    }
    static async Task SetModeUnsupported()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var id = await Open(d, disposition: 3); await Write(d, id, Payload);
        foreach (var mode in new uint[] { 2, 1, 0 })
        {
            var data = new byte[4]; RawSmb.Put32(data, 0, mode); Status(await d.Send(Set(id, 16, data)), 0xc0000003, "unsupported FileModeInformation SET cannot acknowledge a change");
        }
        await Data(d, id, Payload);
    }
    static byte[] Ea(string name, byte[] data)
    {
        var n = System.Text.Encoding.ASCII.GetBytes(name); var b = new byte[9 + n.Length + data.Length]; b[5] = (byte)n.Length; RawSmb.Put16(b, 6, (ushort)data.Length);
        n.CopyTo(b, 8); data.CopyTo(b, 9 + n.Length); return b;
    }
    static async Task AbsentZeroEa()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var id = await Open(d, disposition: 3);
        Status(await d.Send(Set(id, 15, Ea("keep", [42]))), Ok, "seed unrelated nonempty EA"); Status(await d.Send(Set(id, 15, Ea("ZeroEA", []))), Ok, "setting absent EA to empty succeeds as no-op deletion");
        var q = Query(id, 15); RawSmb.Put32(q, 84, 1); var data = Output(await d.Send(q)); Check.Equal(0u, RawSmb.U32(data, 0), "only existing unrelated EA remains");
        Check.Equal("keep", System.Text.Encoding.ASCII.GetString(data, 8, data[5]).ToLowerInvariant(), "zero-length absent EA not materialized");
        Check.Equal((ushort)1, RawSmb.U16(data, 6), "retained EA value length"); Check.Equal((byte)42, data[9 + data[5]], "retained EA value");
    }
    static async Task DeleteSecondTree()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var id = await Open(d, disposition: 3); await Write(d, id, Payload); await Close(d, id);
        var treeResponse = await d.Send(RawSmb.TreeConnect("\\\\localhost\\P0", 0, 1)); Status(treeResponse, Ok, "second tree under same session"); var tree = RawSmb.U32(treeResponse, 36);
        async Task<byte[]> Other(byte[] b) { RawSmb.Put32(b, 36, tree); return await d.Send(b); }
        var deleter = Id(await Other(Create(access: 0x10000))); Status(await Other(Set(deleter, 13, [1])), Ok, "delete through second tree");
        Status(await Other(RawSmb.Close(deleter, 0, 1, tree)), Ok, "second tree close completes deletion");
        Status(await Other(RawSmb.TreeDisconnect(0, 1, tree)), Ok, "retire second tree after deletion");
        Status(await d.Send(Create()), Missing, "second tree teardown cannot resurrect deleted path"); var fresh = await Open(d, disposition: 2); await Write(d, fresh, [7]); await Data(d, fresh, [7]);
    }
    static async Task QuotaUnsupported()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var rejected = await d.Send(Create("$Extend\\$Quota:$Q:$INDEX_ALLOCATION", access: 0x81));
        Check.That(RawSmb.U32(rejected, 8) is 0xc0000033 or 0xc0000034 or 0xc000003a or 0xc00000bb, "unsupported NTFS quota pseudo-object rejects without a fabricated virtual file");
        var id = await Open(d, disposition: 3); var q = Query(id, 0, type: 4); Array.Resize(ref q, 120); RawSmb.Put16(q, 72, 104); RawSmb.Put32(q, 76, 16); q[105] = 1;
        Status(await d.Send(q), 0xc00000bb, "quota query rejects explicitly when no quota provider is supported");
    }
    static async Task BackendNoStreams()
    {
        await using var d = new P2Tests.Direct(); var id = await Open(d, disposition: 3); await Write(d, id, Payload);
        foreach (var row in new[] { ("file:stream",0xc00000bbu),("file:stream:$DATA",0xc00000bbu),("file::invalid",0xc0000033u) })
            Status(await d.Send(Create(row.Item1)), row.Item2, "backend without named stream capability gives its defined rejection");
        await Data(d, await Open(d, "file::$DATA"), Payload);
    }
    static async Task StreamCaseAliases()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var file = await Open(d, disposition: 3); var stream = await Open(d, "file:StreamName", 3); await Write(d, stream, Payload);
        foreach (var suffix in new[] { ":StreamName", ":streamname", ":STREAMNAME", ":StreamName:$dAtA", ":streamname:$data", ":STREAMNAME:$DATA" })
            await Data(d, await Open(d, "file" + suffix), Payload);
        Check.That((await StreamNames(d, file)).SequenceEqual(new[] { "::$DATA", ":StreamName:$DATA" }.Order(StringComparer.Ordinal)), "case aliases retain one original-cased stream name");
    }
    static async Task QuerySourceAccess()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var seed = await Open(d, disposition: 3); Status(await d.Send(Set(seed, 15, Ea("seed", [7]))), Ok, "source complex file EA prerequisite"); await Close(d, seed);
        // Literal wire-level partitions of getinfo.c:file_levels_access. Optional
        // unimplemented FSCC classes are covered by their explicit rejections.
        foreach (var row in new (byte Class, uint Weak, uint Strong, bool Unrestricted)[]
        { (5,0x100000,0x80,true),(6,0x100000,0x80,true),(14,0x100000,0x80,true),(22,0x100000,0x80,true),(7,0x100000,8,true),
          (4,0x100000,0x80,false),(18,0x100000,0x80,false),(34,0x100000,0x80,false),(35,0x100000,0x80,false),(15,0x100000,8,false),(15,0x80,8,false) })
        {
            foreach (var strong in new[] { false, true })
            {
                var id = await Open(d, access: strong ? row.Strong : row.Weak); var q = Query(id, row.Class); if (row.Class == 15) RawSmb.Put32(q, 84, 1);
                Status(await d.Send(q), strong || row.Unrestricted ? Ok : Denied, $"source query access class {row.Class}, mask {(strong ? row.Strong : row.Weak):x}"); await Close(d, id);
            }
        }
    }
    static async Task MetadataContexts()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        var b = P7cTests.Context(P7cTests.Context(Create(disposition: 3), "MxAc", new byte[8]), "QFid", []);
        var response = await d.Send(b); var id = Id(response);
        // These optional response contexts are not implemented by the local
        // profile. Ignoring an unsupported context is the CREATE contract.
        Check.That(Context(response, "MxAc") == null && Context(response, "QFid") == null, "no fabricated optional maximal-access or on-disk-ID response");
        await Write(d, id, Payload); await Data(d, id, Payload); Check.That(RawSmb.U64(Output(await d.Send(Query(id, 6))), 0) != 0, "ordinary supported file identity remains available");
    }
    static async Task LsaUnavailable()
    {
        await using var d = new P2Tests.Direct(); d.Options.Shares.Add(new Share { Name = "IPC$", Type = Smb.FileSystem.ShareType.Pipe });
        var treeResponse = await d.Send(RawSmb.TreeConnect("\\\\localhost\\IPC$", 0, 1)); Status(treeResponse, Ok, "IPC tree exists independently of LSA endpoint availability");
        var tree = RawSmb.U32(treeResponse, 36); var create = Create("lsarpc", 1, access: 0x2019f); RawSmb.Put32(create, 36, tree);
        Status(await d.Send(create), Missing, "source LSA credit workload cannot open an unsupported RPC endpoint");
        Status(await d.Send(RawSmb.TreeDisconnect(0, 1, tree)), Ok, "unsupported endpoint leaves the IPC tree usable");
    }
    static async Task AttributeSecurity(bool directory)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var id = await Open(d, disposition: 3, access: 0x1f01ff, directory: directory);
        Status(await d.Send(SecuritySet(id, DaclWithFallback(0, true))), Ok, "nontrivial descriptor before DOS attribute changes"); var descriptor = Output(await d.Send(SecurityQuery(id, 7)));
        try
        {
            foreach (var attr in new uint[] { 0x80, 0x20, 1, 2, 4, 0x21, 0x22, 0x24, 0x23, 0x25, 0x26, 3, 5, 7 })
            {
                var data = new byte[40]; RawSmb.Put32(data, 32, attr); Status(await d.Send(Set(id, 4, data)), Ok, "apply distinct source DOS attribute combination");
                Check.Equal(directory ? (attr & ~0x80u) | 16u : attr, RawSmb.U32(Output(await d.Send(Query(id, 4))), 32), "exact DOS attribute result with immutable DIRECTORY bit");
                Check.That(Output(await d.Send(SecurityQuery(id, 7))).SequenceEqual(descriptor), "DOS attribute SET preserves owner/group/ordered DACL bytes");
                Status(await d.Send(Create(access: 1, directory: directory)), Denied, "DOS attributes do not remove descriptor enforcement");
            }
        }
        finally { var normal = new byte[40]; RawSmb.Put32(normal, 32, 0x80); await d.Send(Set(id, 4, normal)); }
    }
    static async Task StreamCreationLifetime()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var b = Create(disposition: 3); RawSmb.Put32(b, 92, 2); var file = Id(await d.Send(b));
        var initial = RawSmb.U64(Output(await d.Send(Query(file, 4))), 0); await Write(d, file, Payload); await Close(d, file); file = await Open(d);
        Check.Equal(initial, RawSmb.U64(Output(await d.Send(Query(file, 4))), 0), "base write and last close preserve creation time");
        var stream = await Open(d, "file:stream", 3); Check.Equal(initial, RawSmb.U64(Output(await d.Send(Query(stream, 4))), 0), "new stream shares base creation time");
        var time = (ulong)new DateTime(2020, 2, 3, 4, 5, 6, DateTimeKind.Utc).ToFileTimeUtc(); var data = new byte[40]; RawSmb.Put64(data, 0, time);
        Status(await d.Send(Set(stream, 4, data)), Ok, "set base creation time through stream"); await Write(d, stream, Payload); await Close(d, stream); await Close(d, file);
        foreach (var name in new[] { "file", "file:stream" }) { var id = await Open(d, name); Check.Equal(time, RawSmb.U64(Output(await d.Send(Query(id, 4))), 0), "stream creation time update persists across both last closes and later write"); await Close(d, id); }
    }
    static async Task ChangeTimeRejected()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var id = await Open(d, disposition: 3); await Write(d, id, Payload); var before = Output(await d.Send(Query(id, 4)));
        var update = new byte[40]; var time = (ulong)new DateTime(2020, 1, 2, 3, 4, 5, DateTimeKind.Utc).ToFileTimeUtc();
        foreach (var at in new[] { 0, 8, 16, 24 }) RawSmb.Put64(update, at, time); RawSmb.Put32(update, 32, 1);
        Status(await d.Send(Set(id, 4, update)), 0xc00000bb, "backend cannot set explicit ChangeTime; combined basic update rejects before mutation");
        var after = Output(await d.Send(Query(id, 4))); Check.That(before.SequenceEqual(after), "rejected ChangeTime must not partially change supported times or readonly attribute"); await Data(d, id, Payload);
    }
}
