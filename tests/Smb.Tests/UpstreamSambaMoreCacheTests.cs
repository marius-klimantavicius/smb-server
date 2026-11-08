using System.Text;
using Smb.Protocol.Enums;
using Smb.Server;
using Smb.Server.State;
using Smb.Testing;

internal static partial class UpstreamSambaMoreTests
{
    static IEnumerable<(string Name, Func<Task> Run)> CacheCases()
    {
        foreach (var held in new uint[] { 1, 3, 5, 7 })
            foreach (var requested in new uint[] { 1, 3, 5, 7 })
                yield return ($"upstream.samba.more.lease.conflict.{held}.{requested}", () => LeaseConflict(held, requested));
        foreach (var access in new uint[] { 0x80, 0x100, 0x100080, 0x20080 })
            yield return ($"upstream.samba.more.lease.stat.{access:x}", () => LeaseStat(access));
        foreach (var shape in new[] { "read", "write", "lock", "rename", "delete", "overwrite", "same-key-write", "duplicate-key-file" })
            yield return ($"upstream.samba.more.lease.operation.{shape}", () => LeaseOperation(shape));
        foreach (var v1 in new[] { true, false })
            foreach (var shape in new[] { "lock-batch", "lock-lease", "lock-no-write-lease", "position", "delete-on-close", "active", "wrong-name", "wrong-key", "missing-lease", "wrong-client", "wrong-guid", "double-reconnect", "readonly" })
            {
                if (v1 && shape == "wrong-guid") continue;
                yield return ($"upstream.samba.more.durable.{(v1 ? 1 : 2)}.{shape}", () => DurableWorkflow(v1, shape));
            }
        foreach (var leased in new[] { false, true })
            yield return ($"upstream.samba.more.cache.timeout.{leased}", () => CacheTimeout(leased));
    }
    sealed class CacheFixture : IAsyncDisposable
    {
        public readonly P7cTests.Root Root = new();
        public readonly P2Tests.Direct D;
        public readonly RecordingTransport Transport = new();
        public readonly Dictionary<(ulong P, ulong V), byte> Oplocks = new();
        public bool CloseOnClassicBreak;
        public bool AcknowledgeClassicToNone;
        public CacheFixture(bool durable = false)
        {
            D = new P2Tests.Direct(Root.Store()); D.Options.FeaturePolicy = durable ? SmbFeaturePolicy.Durable : SmbFeaturePolicy.Caching;
            D.Connection.Dialect = SmbDialect.Smb300; D.Connection.ServerCapabilities |= Smb2Capabilities.Leasing;
            D.Session.TryAttachChannel(new SmbChannel { Connection = D.Connection, SigningKey = D.Session.SigningKey }); Transport.Attach(D.Connection);
        }
        public async ValueTask DisposeAsync()
        {
            foreach (var c in D.State.Connections.Values.ToArray()) await D.Dispatcher.OnConnectionClosedAsync(c, Smb2Dispatcher.CloseReason.Shutdown);
            await D.Dispatcher.CloseRetainedHandlesAsync();
            foreach (var path in Directory.EnumerateFiles(Root.Path, "*", SearchOption.AllDirectories)) File.SetAttributes(path, FileAttributes.Normal);
            Root.Dispose();
        }
    }
    static byte[] Lease(byte[] b, uint state, ulong key = 1, bool v2 = false, ushort epoch = 0)
    {
        b[67] = 255; var data = new byte[v2 ? 52 : 32]; RawSmb.Put64(data, 0, key); RawSmb.Put64(data, 8, ~key); RawSmb.Put32(data, 16, state);
        if (v2) RawSmb.Put16(data, 48, epoch); return P7cTests.Context(b, "RqLs", data);
    }
    static byte[]? Context(byte[] b, string name)
    {
        Status(b, Ok, "CREATE response for context lookup"); var at = (int)RawSmb.U32(b, 144); var end = at + (int)RawSmb.U32(b, 148);
        while (at != 0 && at < end)
        {
            Check.That(at + 16 <= end && end <= b.Length, "bounded response context");
            if (Encoding.ASCII.GetString(b, at + RawSmb.U16(b, at + 4), RawSmb.U16(b, at + 6)) == name)
                return RawSmb.Buffer(b, at + RawSmb.U16(b, at + 10), RawSmb.U32(b, at + 12));
            var next = (int)RawSmb.U32(b, at); if (next == 0) break; Check.That(next >= 16 && (next & 7) == 0, "context progresses"); at += next;
        }
        return null;
    }
    static void LeaseState(byte[] response, uint state, ulong key)
    {
        Status(response, Ok, "leased CREATE"); var ctx = Context(response, "RqLs"); Check.That(ctx != null, "lease response context present");
        Check.Equal(key, RawSmb.U64(ctx!, 0), "lease key echoed"); Check.Equal(~key, RawSmb.U64(ctx!, 8), "second lease key half echoed"); Check.Equal(state, RawSmb.U32(ctx!, 16), "independent expected lease grant");
    }
    static byte[] LeaseAck(ulong key, uint state)
    {
        var b = RawSmb.Header(18, 36, 0, 1, 42); RawSmb.Put16(b, 64, 36); RawSmb.Put64(b, 72, key); RawSmb.Put64(b, 80, ~key); RawSmb.Put32(b, 88, state); return b;
    }
    static async Task<byte[]> Complete(CacheFixture f, byte[] request, Func<byte[], Task>? onBreak = null, Func<byte[], bool>? closedOnBreak = null)
    {
        var start = f.Transport.Sends.Length;
        var response = await f.D.Send(request); if (RawSmb.U32(response, 8) != 0x103) return response;
        var asyncId = RawSmb.U64(response, 32); var seen = new HashSet<RecordedSend>();
        while (true)
        {
            foreach (var send in f.Transport.Sends.Skip(start).Where(s => !seen.Contains(s)))
            {
                seen.Add(send); var b = send.Message;
                if (RawSmb.U16(b, 12) == 18 && RawSmb.U16(b, 64) == 44)
                {
                    if (onBreak != null) await onBreak(b);
                    if ((RawSmb.U32(b, 68) & 1) != 0 && closedOnBreak?.Invoke(b) != true) Status(await f.D.Send(LeaseAck(RawSmb.U64(b, 72), RawSmb.U32(b, 92))), Ok, "ACK exact requested lease downgrade");
                }
                if (RawSmb.U16(b, 12) == 18 && RawSmb.U16(b, 64) == 24)
                {
                    var owner = (RawSmb.U64(b, 72), RawSmb.U64(b, 80));
                    if (f.Oplocks.TryGetValue(owner, out var old) && old is 8 or 9)
                    {
                        if (f.CloseOnClassicBreak) await Close(f.D, owner);
                        else Status(await f.D.Send(P6Tests.Ack(owner, (OplockLevel)(f.AcknowledgeClassicToNone ? 0 : b[66]))), Ok, "classic oplock break ACK");
                    }
                    f.Oplocks[owner] = f.AcknowledgeClassicToNone ? (byte)0 : b[66];
                }
            }
            var final = f.Transport.Sends.LastOrDefault(s => RawSmb.U16(s.Message, 12) == RawSmb.U16(request, 12) && (RawSmb.U32(s.Message, 16) & 2) != 0 && RawSmb.U64(s.Message, 32) == asyncId && RawSmb.U32(s.Message, 8) != 0x103);
            if (final != null) return final.Message;
            await f.Transport.WaitForSendAsync().WaitAsync(Check.Timeout);
        }
    }
    static async Task LeaseConflict(uint held, uint requested)
    {
        await using var f = new CacheFixture(); var d = f.D;
        var a = await d.Send(Lease(Create(disposition: 3), held)); var first = Id(a); LeaseState(a, held, 1);
        var target = held & 3; var granted = requested & 3;
        var b = await Complete(f, Lease(Create(), requested, 2), notification =>
        {
            Check.Equal(held, RawSmb.U32(notification, 88), "lease break CurrentLeaseState"); Check.Equal(target, RawSmb.U32(notification, 92), "lease break NewLeaseState");
            Check.Equal(1ul, RawSmb.U64(notification, 72), "break targets original key"); return Task.CompletedTask;
        });
        var second = Id(b); LeaseState(b, granted, 2);
        Check.Equal(held == target ? 0 : 1, f.Transport.Sends.Count(s => RawSmb.U16(s.Message, 12) == 18), "exact conflict break count");
        var reopened = await d.Send(Lease(Create(), 7)); var third = Id(reopened); LeaseState(reopened, target, 1);
        await Close(d, first); await Close(d, second); await Close(d, third);
    }
    static async Task LeaseStat(uint access)
    {
        await using var f = new CacheFixture(); var d = f.D; var first = await d.Send(Lease(Create(disposition: 3), 7)); var id = Id(first);
        var stat = Id(await d.Send(Create(access: access))); Check.Equal(0, f.Transport.Sends.Length, "stat/control-only open does not break lease");
        var same = await d.Send(Lease(Create(), 0)); LeaseState(same, 7, 1); await Close(d, stat); await Close(d, id); await Close(d, Id(same));
    }
    static async Task LeaseOperation(string shape)
    {
        await using var f = new CacheFixture(); var d = f.D;
        var first = await d.Send(Lease(Create(disposition: 3), shape == "read" ? 5u : 7u)); var id = Id(first); await Write(d, id, Payload);
        if (shape == "duplicate-key-file")
        {
            Status(await d.Send(Lease(Create("other", 3), 7)), Invalid, "same client lease key cannot identify two files");
            Status(await d.Send(Create("other")), Missing, "rejected duplicate-key create did not publish another file");
            await Close(d, await Open(d, "other", 3)); Status(await d.Send(Lease(Create("other"), 7)), Invalid, "duplicate key also rejects a different existing object");
            await Data(d, id, Payload); return;
        }
        if (shape == "same-key-write")
        {
            var peer = Id(await d.Send(Lease(Create(), 7))); await Write(d, peer, [8], 0); Check.Equal(0, f.Transport.Sends.Length, "same lease does not break itself"); return;
        }
        var opened = await Complete(f, Lease(Create(), 3, 2)); var other = Id(opened);
        var start = f.Transport.Sends.Length;
        var operation = shape switch
        {
            "read" => RawSmb.Read(other, 1, 0, 0, 1, 42), "write" => RawSmb.Write(other, [8], 0, 0, 1, 42),
            "lock" => Lock(other, 0, 1), "rename" => Rename(other, "renamed"), "delete" => Set(other, 13, [1]), _ => Create(disposition: 5)
        };
        Status(await Complete(f, operation), Ok, "operation completes after wire lease downgrade");
        if (shape == "read") Check.Equal(0, f.Transport.Sends.Skip(start).Count(s => RawSmb.U16(s.Message, 12) == 18), "READ compatible with shared read cache");
        if (shape == "write") await Data(d, id, new byte[] { 8 }.Concat(Payload[1..]).ToArray());
        if (shape == "rename") Check.Equal((ulong)Payload.Length, RawSmb.U64(Output(await d.Send(Query(other, 5))), 8), "renamed handle retains EOF");
    }
    static byte[] DurableRequest(bool v1, Guid guid, string shape)
    {
        var b = Create(disposition: 3); b[67] = 9;
        if (shape == "delete-on-close") RawSmb.Put32(b, 104, 0x1040);
        if (shape == "readonly") RawSmb.Put32(b, 92, 1);
        var data = new byte[v1 ? 16 : 32]; if (!v1) { RawSmb.Put32(data, 0, 30000); guid.ToByteArray().CopyTo(data, 16); }
        b = P7cTests.Context(b, v1 ? "DHnQ" : "DH2Q", data);
        if (shape.Contains("lease") || shape is "wrong-name" or "wrong-key" or "missing-lease" or "wrong-client") b = Lease(b, shape == "lock-no-write-lease" ? 3u : 7u);
        return b;
    }
    static SmbSession Session(CacheFixture f, ulong sessionId = 2, uint treeId = 43)
    {
        var d = f.D; var c = d.Channel(); c.Dialect = SmbDialect.Smb300; c.ServerCapabilities = d.Connection.ServerCapabilities; c.ClientGuid = d.Connection.ClientGuid.ToArray();
        var s = new SmbSession { SessionId = sessionId, SessionGlobalId = checked((uint)sessionId), Connection = c, State = SessionState.Valid, SigningRequired = true, SigningKey = new byte[16], SessionKey = new byte[16], Identity = d.Session.Identity };
        c.Sessions.TryAdd(sessionId, s); d.State.Connections.TryAdd(c.ConnectionId, c); d.State.SessionGlobalList.TryAdd(sessionId, s);
        s.TryAttachChannel(new SmbChannel { Connection = c, SigningKey = s.SigningKey }); d.Options.Metrics.OnAuthenticationSucceeded();
        s.TreeConnects.TryAdd(treeId, new SmbTreeConnect { Session = s, TreeId = treeId, Share = d.Tree.Share, MaximalAccess = 0x1f01ff }); d.Options.Metrics.OnTreeConnected(); return s;
    }
    static async Task<byte[]> Send(CacheFixture f, SmbSession s, byte[] b)
    {
        RawSmb.Put64(b, 40, s.SessionId);
        if ((RawSmb.U32(b, 16) & 2) == 0) RawSmb.Put32(b, 36, checked((uint)s.TreeConnects.Keys.First())); // async header contains AsyncId here, not TreeId
        return await f.D.Send(b, s.Connection);
    }
    static async Task DurableWorkflow(bool v1, string shape)
    {
        await using var f = new CacheFixture(true); var d = f.D; var guid = Guid.NewGuid(); var req = DurableRequest(v1, guid, shape);
        var response = await d.Send(req); var id = Id(response); Check.That(Context(response, v1 ? "DHnQ" : "DH2Q") != null, "actual durable CREATE grant");
        if (shape == "readonly") Check.That((RawSmb.U32(response, 120) & 1) != 0, "durable CREATE retains requested readonly attribute");
        await Write(d, id, Payload);
        if (shape.StartsWith("lock-")) Status(await d.Send(Lock(id, 0, 1)), Ok, "lock before disconnect");
        if (shape == "position") { var data = new byte[8]; RawSmb.Put64(data, 0, 4096); Status(await d.Send(Set(id, 14, data)), Ok, "set durable file position"); }
        if (shape != "active") await d.Dispatcher.OnConnectionClosedAsync(d.Connection);
        var s = Session(f); if (shape == "wrong-client") s.Connection.ClientGuid = Guid.NewGuid().ToByteArray();
        byte[] Reconnect(bool correct)
        {
            var b = Create(shape == "wrong-name" && !correct ? "wrong" : "file");
            var data = new byte[v1 ? 16 : 36]; RawSmb.Put64(data, 0, id.P); RawSmb.Put64(data, 8, id.V);
            if (!v1) (shape == "wrong-guid" && !correct ? Guid.NewGuid() : guid).ToByteArray().CopyTo(data, 16);
            b = P7cTests.Context(b, v1 ? "DHnC" : "DH2C", data);
            if ((shape.Contains("lease") || shape is "wrong-name" or "wrong-key" or "wrong-client") && (shape != "missing-lease" || correct)) b = Lease(b, shape == "lock-no-write-lease" ? 3u : 7u, shape == "wrong-key" && !correct ? 9ul : 1ul);
            return b;
        }
        var result = await Send(f, s, Reconnect(false));
        var invalid = shape is "active" or "wrong-name" or "wrong-key" or "missing-lease" or "wrong-client" or "wrong-guid" or "lock-no-write-lease";
        Status(result, shape == "wrong-name" && v1 ? Invalid : invalid ? Missing : Ok, "durable reconnect public validation/result");
        if (invalid)
        {
            if (shape == "wrong-client") s.Connection.ClientGuid = d.Connection.ClientGuid.ToArray();
            if (shape is "active" or "lock-no-write-lease") return;
            result = await Send(f, s, Reconnect(true)); Status(result, Ok, "invalid reconnect preserves valid retained claim");
        }
        var recovered = Id(result); Check.Equal(id.P, recovered.P, "persistent FileId retained");
        if (shape.StartsWith("lock-")) Status(await Send(f, s, Lock(recovered, 0, 1, 4)), Ok, "reconnect retains exact lock ownership");
        if (shape == "position") Check.Equal(4096ul, RawSmb.U64(Output(await Send(f, s, Query(recovered, 14))), 0), "file position retained through reconnect");
        var read = await Send(f, s, RawSmb.Read(recovered, (uint)Payload.Length, 0, 0, 1, 42)); Status(read, Ok, "reconnected READ");
        Check.That(RawSmb.Buffer(read, read[66], RawSmb.U32(read, 68)).SequenceEqual(Payload), "reconnected file bytes preserved");
        if (shape == "readonly")
        {
            Check.That((RawSmb.U32(result, 120) & 1) != 0, "readonly metadata survives durable reconnect");
            Status(await Send(f, s, RawSmb.Write(recovered, [1], (ulong)Payload.Length, 0, 1, 42)), Ok, "reconnect preserves already-granted WRITE despite readonly attribute");
        }
        if (shape == "double-reconnect") Status(await Send(f, s, Reconnect(true)), Missing, "retained claim consumed exactly once");
        Status(await Send(f, s, RawSmb.Close(recovered, 0, 1, 42)), Ok, "close recovered open");
        if (shape == "delete-on-close") Status(await Send(f, s, Create()), Missing, "reconnected DELETE_ON_CLOSE survives");
    }
    static async Task CacheTimeout(bool leased)
    {
        await using var f = new CacheFixture(); var d = f.D; var clock = new ManualClock(); d.Options.TimeProvider = clock; d.Options.OplockBreakTimeout = TimeSpan.FromSeconds(1);
        var request = Create(disposition: 3); if (leased) request = Lease(request, 7); else request[67] = 9;
        var response = await d.Send(request); var owner = Id(response);
        var next = Create(); if (leased) next = Lease(next, 7, 2); else next[67] = 9;
        var interim = await d.Send(next); Status(interim, 0x103, "cache-conflicting CREATE is pending before timeout");
        while (!f.Transport.Sends.Any(s => RawSmb.U16(s.Message, 12) == 18)) await f.Transport.WaitForSendAsync().WaitAsync(Check.Timeout);
        clock.Advance(TimeSpan.FromSeconds(2)); var completed = await AsyncFinal(f.Transport, interim); var peer = Id(completed);
        Status(await d.Send(leased ? LeaseAck(1, 0) : P6Tests.Ack(owner, OplockLevel.None)), leased ? 0xc0000001u : 0xc0000184u, "timeout retires the outstanding ACK obligation; classic open is no longer Breaking");
        Status(await d.Send(RawSmb.Read(owner, 0, 0, 0, 1, 42)), Ok, "timeout does not close the ordinary file handle");
        if (leased)
        {
            var probe = await d.Send(Lease(Create(), 0)); LeaseState(probe, 0, 1); await Close(d, Id(probe));
            Status(await Complete(f, RawSmb.Write(owner, Payload, 0, 0, 1, 42)), Ok, "timed-out ordinary handle can still invalidate the new peer cache and write");
            var count = f.Transport.Sends.Length; await Write(d, peer, Payload); Check.Equal(count, f.Transport.Sends.Length, "peer write does not break already revoked original key");
            await Close(d, peer);
            foreach (var state in new uint[] { 1, 7 }) { var rearmed = await d.Send(Lease(Create(), state)); LeaseState(rearmed, state, 1); await Close(d, Id(rearmed)); }
            await Close(d, owner); return;
        }
        await Close(d, peer); await Close(d, owner);
    }
}
