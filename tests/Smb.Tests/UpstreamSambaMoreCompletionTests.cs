using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Server;
using Smb.Testing;

internal static partial class UpstreamSambaMoreTests
{
    static IEnumerable<(string Name, Func<Task> Run)> CompletionCases()
    {
        foreach (var shape in new[] { "denied-ioctl", "denied-notify", "invalid-first-reset", "invalid-session-reset", "unrelated-then-related", "object-id-unsupported", "stat-under-batch" })
            yield return ($"upstream.samba.more.compound.complete.{shape}", () => CompoundCompletion(shape));
        foreach (var reopen in new[] { false, true })
            yield return ($"upstream.samba.more.compound.notify-last-cancel.{reopen}", () => CompoundNotifyCancel(reopen));
        foreach (var shape in new[] { "one", "closed-source", "two", "zero-key" })
            yield return ($"upstream.samba.more.copy.second-tree.{shape}", () => CopySecondTree(shape));
        foreach (var shape in new[] { "flush-close", "flush-flush", "write-write", "read-read", "copy-close", "read-cancel" })
            yield return ($"upstream.samba.more.io.gated.{shape}", () => GatedIo(shape));
        foreach (var copy in new[] { false, true }) yield return ($"upstream.samba.more.io.independent-close-drain.{copy}", () => IndependentDrain(copy));
        foreach (var shape in new[] { "getinfo-middle", "rename-last", "rename-middle" }) yield return ($"upstream.samba.more.compound.withheld-cache-break.{shape}", () => CacheCompound(shape));
    }
    static async Task CompoundCompletion(string shape)
    {
        await using var f = new CacheFixture(); var d = f.D;
        if (shape == "stat-under-batch")
        {
            var held = await OpenOplock(f, 9); Check.Equal((byte)9, held[66], "batch grant before stat compound");
        }
        byte[][] packets; uint[] expected; bool[]? related = null;
        if (shape.StartsWith("denied-"))
        {
            var admin = await Open(d, disposition: 3, access: 0x1f01ff);
            var sd = SingleAce(Sid(3, 0), 0x1f0089);
            Status(await d.Send(SecuritySet(admin, sd)), Ok, "install source CREATOR_OWNER read-only descriptor before chain");
            packets = [Create(access: 2), shape == "denied-ioctl" ? P5Tests.Ioctl(Inherit, 0x900c0, [], 64) : Notify(Inherit), RawSmb.Close(Inherit, 0, 1, 42), SecuritySet(Inherit, sd)];
            expected = [Denied, Denied, Denied, Denied];
        }
        else if (shape == "invalid-first-reset")
        { packets = [Create(disposition: 3), RawSmb.Close(Inherit, 0, 1, 42), RawSmb.Close(Inherit, 0, 1, 42)]; expected = [Invalid, Invalid, Closed]; related = [true, true, false]; }
        else if (shape == "invalid-session-reset")
        {
            var bad = RawSmb.Close(Inherit, 0, ulong.MaxValue, uint.MaxValue);
            packets = [Create(disposition: 3), RawSmb.Close(Inherit, 0, 1, 42), bad, bad.ToArray(), bad.ToArray()];
            expected = [Ok, Ok, 0xc0000203, 0xc0000203, Invalid]; related = [false, true, false, false, true];
        }
        else if (shape == "unrelated-then-related")
        { packets = [Create(disposition: 3), RawSmb.Close(Inherit, 0, 1, 42), RawSmb.Close(Inherit, 0, 1, 42), RawSmb.Close(Inherit, 0, 1, 42), RawSmb.Close(Inherit, 0, 1, 42)]; expected = [Ok, Closed, Closed, Closed, Closed]; related = [false, false, false, true, true]; }
        else if (shape == "object-id-unsupported")
        { packets = [Create(disposition: 3), P5Tests.Ioctl(Inherit, 0x900c0, [], 64), RawSmb.Close(Inherit, 0, 1, 42)]; expected = [Ok, 0xc0000010, 0xc0000010]; }
        else
        { packets = [Create(access: 0x100088), Query(Inherit, 22)]; expected = [Ok, Ok]; }
        var result = Split(await Chain(d, packets, related), d.Connection.Dialect); Check.Equal(expected.Length, result.Count, "exact source compound vector length");
        for (var i = 0; i < expected.Length; i++) Status(result[i], expected[i], shape + " component " + i);
        if (shape == "stat-under-batch") Check.Equal(0, f.Transport.Sends.Length, "stat-only compound leaves batch cache intact");
    }
    static async Task CompoundNotifyCancel(bool reopen)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); d.Options.DirectoryWatcher = new FakeWatcher();
        var trace = new List<string>(); d.Dispatcher = new Smb2Dispatcher(d.State, trace.Add);
        if (!reopen) { var control = await d.Send(Create("control", 2, directory: true)); Status(control, Ok, "standalone directory CREATE control before exact compound"); await Close(d, Id(control)); }
        var transport = new RecordingTransport(); transport.Attach(d.Connection);
        byte[][] packets = reopen
            ? [Create("dir", 3, directory: true), RawSmb.Close(Inherit, 0, 1, 42), Create("dir", directory: true), Notify(Inherit, recursive: true)]
            : [Create("dir", 2, directory: true), Notify(Inherit, recursive: true)];
        var response = Split(await Chain(d, packets)); Check.Equal(packets.Length, response.Count, "all nonpending commands and last notify interim returned");
        for (var i = 0; i < response.Count - 1; i++) Status(response[i], Ok, "commands before last pending notify complete in order: " + string.Join("; ", trace));
        var pending = response[^1]; Status(pending, 0x103, "last compound CHANGE_NOTIFY pends"); Check.That((RawSmb.U32(pending, 16) & 2) != 0, "pending notify has async header");
        var cancel = RawSmb.Header(12, 4, 0, 1); RawSmb.Put16(cancel, 64, 4); RawSmb.Put32(cancel, 16, 2); RawSmb.Put64(cancel, 32, RawSmb.U64(pending, 32));
        await d.Send(cancel); Status(await AsyncFinal(transport, pending, 15), 0xc0000120, "last compound notify can be cancelled by its AsyncId");
        await Close(d, Id(response[reopen ? 2 : 0]));
    }
    static byte[] CopyInput(byte[] key, int chunks, uint length = 4096)
    {
        var data = new byte[32 + 24 * chunks]; key.AsSpan(0, 24).CopyTo(data); RawSmb.Put32(data, 24, (uint)chunks);
        for (var i = 0; i < chunks; i++) { RawSmb.Put64(data, 40 + 24 * i, (ulong)i * length); RawSmb.Put32(data, 48 + 24 * i, length); }
        return data;
    }
    static async Task<byte[]> Resume(P2Tests.Direct d, (ulong P, ulong V) id)
    { var b = await d.Send(P5Tests.Ioctl(id, 0x140078, [], 32)); Status(b, Ok, "issue source resume key"); return RawSmb.Buffer(b, (int)RawSmb.U32(b, 96), 24); }
    static async Task CopySecondTree(string shape)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); d.Options.FeaturePolicy = SmbFeaturePolicy.CopyOnly;
        var source = await Open(d, "source", 3); var bytes = Enumerable.Range(0, 4096).Select(i => (byte)(i * 13 + 7)).ToArray(); await Write(d, source, bytes);
        var key = shape == "zero-key" ? new byte[24] : await Resume(d, source);
        var treeResponse = await d.Send(RawSmb.TreeConnect("\\\\localhost\\P0", 0, 1)); Status(treeResponse, Ok, "second tree on same authenticated session"); var tree = RawSmb.U32(treeResponse, 36);
        async Task<byte[]> Other(byte[] b) { RawSmb.Put32(b, 36, tree); return await d.Send(b); }
        var target = Id(await Other(Create("target", 3))); if (shape == "closed-source") await Close(d, source);
        var chunks = shape == "two" ? 2 : 1; var result = await Other(P5Tests.Ioctl(target, 0x1440f2, CopyInput(key, chunks), 12));
        var success = shape is "one" or "two"; Status(result, success ? Ok : Missing, "copy resume key is session-scoped and tied to live source open");
        if (success)
        {
            var output = RawSmb.Buffer(result, (int)RawSmb.U32(result, 96), RawSmb.U32(result, 100)); Check.Equal(12, output.Length, "COPYCHUNK result fixed length");
            Check.Equal((uint)chunks, RawSmb.U32(output, 0), "completed chunk count"); Check.Equal(0u, RawSmb.U32(output, 4), "no partial final chunk"); Check.Equal((uint)(4096 * chunks), RawSmb.U32(output, 8), "total copied bytes");
        }
        await Data(d, await Open(d, "target"), success ? Enumerable.Range(0, chunks).SelectMany(_ => bytes).ToArray() : []);
    }
    // Only backend scheduling is controlled here. All assertions inspect SMB
    // responses, final bytes or public handle lifetime; no manager counters.
    sealed class WireGateStore(IFileStore inner) : IFileStore
    {
        internal AsyncBarrier? ReadGate, WriteGate, FlushGate, QueryGate;
        public ValueTask<FileStoreResult<FileCreateResult>> CreateAsync(string p, FileAccessIntent a, CreateDispositionIntent d, bool dir, bool non, CancellationToken ct = default) => inner.CreateAsync(p, a, d, dir, non, ct);
        public async ValueTask<FileStoreResult<int>> ReadAsync(IFileHandle h, long o, Memory<byte> b, CancellationToken ct = default) { if (ReadGate is { } g) { ReadGate = null; await g.WaitAsync(ct); } return await inner.ReadAsync(h, o, b, ct); }
        public async ValueTask<FileStoreResult<int>> WriteAsync(IFileHandle h, long o, ReadOnlyMemory<byte> b, CancellationToken ct = default) { if (WriteGate is { } g) { WriteGate = null; await g.WaitAsync(ct); } return await inner.WriteAsync(h, o, b, ct); }
        public async ValueTask<FileStoreResult<IReadOnlyList<FileEntryInfo>>> QueryDirectoryAsync(IFileHandle h, string p, CancellationToken ct = default) { if (QueryGate is { } g) { QueryGate = null; await g.WaitAsync(ct); } return await inner.QueryDirectoryAsync(h, p, ct); }
        public ValueTask<NtStatus> SetEndOfFileAsync(IFileHandle h, long n, CancellationToken ct = default) => inner.SetEndOfFileAsync(h, n, ct);
        public ValueTask<NtStatus> RenameAsync(IFileHandle h, string p, bool r, CancellationToken ct = default) => inner.RenameAsync(h, p, r, ct);
        public ValueTask<NtStatus> SetDeleteOnCloseAsync(IFileHandle h, bool b, CancellationToken ct = default) => inner.SetDeleteOnCloseAsync(h, b, ct);
        public async ValueTask<NtStatus> FlushAsync(IFileHandle h, CancellationToken ct = default) { if (FlushGate is { } g) { FlushGate = null; await g.WaitAsync(ct); } return await inner.FlushAsync(h, ct); }
    }
    static async Task GatedIo(string shape)
    {
        using var root = new P7cTests.Root(); var store = new WireGateStore(root.Store()); await using var d = new P2Tests.Direct(store); var id = await Open(d, disposition: 3); await Write(d, id, Payload);
        var barrier = new AsyncBarrier(); Task<byte[]> task;
        if (shape == "copy-close")
        {
            d.Options.FeaturePolicy = SmbFeaturePolicy.CopyOnly; var key = await Resume(d, id); var target = await Open(d, "target", 3); store.ReadGate = barrier;
            task = Chain(d, [P5Tests.Ioctl(target, 0x1440f2, CopyInput(key, 1, (uint)Payload.Length), 12), RawSmb.Close(Inherit, 0, 1, 42)]);
        }
        else if (shape == "read-cancel")
        {
            store.ReadGate = barrier; task = d.Send(RawSmb.Read(id, 1, 0, 0, 1, 42));
        }
        else
        {
            if (shape.StartsWith("flush")) store.FlushGate = barrier; else if (shape.StartsWith("write")) store.WriteGate = barrier; else store.ReadGate = barrier;
            byte[][] packets = shape switch
            {
                "flush-close" => [Flush(id), RawSmb.Close(Inherit, 0, 1, 42)], "flush-flush" => [Flush(id), Flush(Inherit)],
                "write-write" => [RawSmb.Write(id, [11], 0, 0, 1, 42), RawSmb.Write(Inherit, [12], 1, 0, 1, 42)],
                _ => [RawSmb.Read(id, 1, 0, 0, 1, 42), RawSmb.Read(Inherit, 1, 1, 0, 1, 42)]
            }; task = Chain(d, packets);
        }
        try
        {
            await barrier.Entered.WaitAsync(Check.Timeout);
            if (shape == "read-cancel")
            {
                var echo = RawSmb.Header(13, 4, 0, 1, 42); RawSmb.Put16(echo, 64, 4); var next = await d.Send(echo);
                var cancel = RawSmb.Header(12, 4, RawSmb.U64(next, 24) - 1, 1); RawSmb.Put16(cancel, 64, 4); RawSmb.Sign(cancel, d.Session.SigningKey);
                var none = await d.Dispatcher.ProcessMessageAsync(d.Connection, cancel); Check.Equal(0, none.Length, "CANCEL has no separate response");
            }
        }
        finally { barrier.Release(); }
        var response = await task.WaitAsync(Check.Timeout);
        if (shape == "read-cancel")
        {
            var status = RawSmb.U32(response, 8); Check.That(status is Ok or 0xc0000120, "CANCEL may win or lose the delayed READ completion race");
            if (status == Ok) Check.Equal(Payload[0], response[response[66]], "completed READ has correct byte");
            await Data(d, id, Payload); // cancellation never closes the file or changes its bytes
        }
        else
        {
            var parts = Split(response); Check.Equal(2, parts.Count, "both delayed compound commands finish"); foreach (var p in parts) Status(p, Ok, "compound command after backend delay");
            if (shape == "flush-close") Status(await d.Send(RawSmb.Read(id, 1, 0, 0, 1, 42)), Closed, "dependent CLOSE waits for flush completion");
            if (shape == "write-write") await Data(d, id, new byte[] { 11, 12 }.Concat(Payload[2..]).ToArray());
            if (shape == "read-read") for (var i = 0; i < 2; i++) Check.Equal(Payload[i], parts[i][parts[i][66]], "ordered delayed READ bytes");
            if (shape == "copy-close") await Data(d, await Open(d, "target"), Payload);
        }
    }
    static async Task IndependentDrain(bool copy)
    {
        using var root = new P7cTests.Root(); var store = new WireGateStore(root.Store()); await using var d = new P2Tests.Direct(store); var barrier = new AsyncBarrier(); (ulong P, ulong V) id; byte[] request;
        if (copy)
        {
            d.Options.FeaturePolicy = SmbFeaturePolicy.CopyOnly; var source = await Open(d, disposition: 3); await Write(d, source, Payload); var key = await Resume(d, source); id = await Open(d, "target", 3);
            request = P5Tests.Ioctl(id, 0x1440f2, CopyInput(key, 1, (uint)Payload.Length), 12); store.ReadGate = barrier;
        }
        else
        {
            for (var i = 0; i < 5000; i++) File.WriteAllBytes(Path.Combine(root.Path, "file" + i), []);
            id = await Open(d, "", directory: true); request = Enum(id, cls: 3, max: 65536); store.QueryGate = barrier;
        }
        var pending = d.Send(request); Task<byte[]>? close = null;
        try { await barrier.Entered.WaitAsync(Check.Timeout); close = d.Send(RawSmb.Close(id, 0, 1, 42)); Check.That(!close.IsCompleted, "independent CLOSE waits for already admitted physical IOCTL/directory query"); }
        finally { barrier.Release(); }
        Status(await pending.WaitAsync(Check.Timeout), Ok, "admitted operation completes successfully before final close"); Status(await close!.WaitAsync(Check.Timeout), Ok, "CLOSE completes after admitted operation drains");
        Status(await d.Send(Query(id, 5)), Closed, "closed handle cannot be used for later metadata query"); if (copy) await Data(d, await Open(d, "target"), Payload);
    }
    static async Task CacheCompound(string shape)
    {
        await using var f = new CacheFixture(); var d = f.D; var owner = Id(await d.Send(Lease(Create(disposition: 3), shape == "getinfo-middle" ? 7u : 3u))); await Write(d, owner, Payload);
        byte[][] packets = shape == "getinfo-middle" ? [Create(), Query(Inherit, 4), RawSmb.Close(Inherit, 0, 1, 42)] : shape == "rename-last" ? [Lease(Create(), 0, 2), Rename(Inherit, "renamed")] : [Create(), Rename(Inherit, "renamed"), RawSmb.Close(Inherit, 0, 1, 42)];
        var task = Chain(d, packets); while (!f.Transport.Sends.Any(x => RawSmb.U16(x.Message, 12) == 18)) await f.Transport.WaitForSendAsync().WaitAsync(Check.Timeout);
        List<byte[]>? interim = null;
        if (task.IsCompleted)
        {
            interim = Split(await task, d.Connection.Dialect); Check.That(interim.All(x => RawSmb.U32(x, 8) == 0x103), "no dependent compound operation reports success before held cache ACK");
        }
        var notice = f.Transport.Sends.First(x => RawSmb.U16(x.Message, 12) == 18).Message;
        Status(await d.Send(LeaseAck(1, RawSmb.U32(notice, 92))), Ok, "ACK actual advertised downgrade releases compound continuation");
        if (interim == null) { var final = Split(await task.WaitAsync(Check.Timeout), d.Connection.Dialect); foreach (var part in final) Status(part, Ok, "synchronous compound completes after ACK"); }
        else foreach (var pending in interim) Status(await AsyncFinal(f.Transport, pending, RawSmb.U16(pending, 12)), Ok, "each deferred component receives successful terminal response after ACK");
        if (shape == "getinfo-middle") await Data(d, owner, Payload); else { Status(await d.Send(Create()), Missing, "rename continuation removes old name"); await Data(d, await Open(d, "renamed"), Payload); }
    }
}
