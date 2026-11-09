using Smb.Protocol.Enums;
using Smb.Testing;

internal static partial class UpstreamSambaMoreTests
{
    static IEnumerable<(string Name, Func<Task> Run)> OplockCases()
    {
        foreach (var leaseFirst in new[] { false, true })
            foreach (var state in new uint[] { 1, 3, 5, 7 })
                foreach (var level in new byte[] { 1, 8, 9 })
                    yield return ($"upstream.samba.more.cache.mixed.{leaseFirst}.{state}.{level}", () => MixedCaches(leaseFirst, state, level));
        foreach (var level in new byte[] { 1, 8, 9 })
            foreach (var shape in new[] { "second-read", "second-write", "stat", "stat-overwrite", "share-denial", "owner-write", "stream-write", "lock", "rename", "delete" })
                yield return ($"upstream.samba.more.oplock.{level}.{shape}", () => OplockWorkflow(level, shape));
        foreach (var state in new uint[] { 3, 7 })
            foreach (var shape in new[] { "stat", "same-key", "read-lease", "rwh-lease", "share-none", "write", "rename" })
                yield return ($"upstream.samba.more.durable.retained.{state}.{shape}", () => RetainedConflict(state, shape));
        foreach (var shape in new[] { "close-on-open", "close-on-delete", "ack-none", "two-level-II-write", "stat-owner", "stat-owner-and-stat-peer", "unleased-first", "self-read", "self-lock", "set-eof", "set-allocation", "query-all", "disposition", "overwrite", "supersede", "level-II-ack", "double-break", "stream-two-grants", "set-attributes" })
            yield return ($"upstream.samba.more.oplock.sequence.{shape}", () => OplockSequence(shape));
        foreach (var level in new byte[] { 8, 9 })
            yield return ($"upstream.samba.more.oplock.{level}.stat-overwrite-II", () => OplockWorkflow(level, "stat-overwrite-II"));
    }
    static async Task<byte[]> OpenOplock(CacheFixture f, byte level, string name = "file", uint access = All, uint disposition = 3, uint share = 7)
    {
        var b = Create(name, disposition, access, share); b[67] = level; var response = await Complete(f, b);
        if (RawSmb.U32(response, 8) == Ok) f.Oplocks[Id(response)] = response[66]; return response;
    }
    static async Task MixedCaches(bool leaseFirst, uint state, byte level)
    {
        await using var f = new CacheFixture(); var d = f.D;
        if (leaseFirst)
        {
            var a = await d.Send(Lease(Create(disposition: 3), state)); LeaseState(a, state, 1);
            var b = await OpenOplock(f, level); Status(b, Ok, "classic request after lease");
            Check.Equal((byte)((state & 2) == 0 ? 1 : 0), b[66], "lease/oplock compatibility table grant");
            var c = await d.Send(Lease(Create(), 0)); LeaseState(c, state & 3, 1);
        }
        else
        {
            var a = await OpenOplock(f, level); Check.Equal(level, a[66], "first classic grant");
            var b = await Complete(f, Lease(Create(), state)); LeaseState(b, 1, 1);
            var notifications = f.Transport.Sends.Where(s => RawSmb.U16(s.Message, 12) == 18).ToArray();
            Check.Equal(level == 1 ? 0 : 1, notifications.Length, "classic-to-lease downgrade notification count");
            if (level != 1) Check.Equal((byte)1, notifications[0].Message[66], "exclusive/batch reduced to level II");
        }
    }
    static async Task OplockWorkflow(byte level, string shape)
    {
        await using var f = new CacheFixture(); var d = f.D;
        var a = await OpenOplock(f, level, share: shape == "share-denial" ? 0u : 7u); var id = Id(a); Check.Equal(level, a[66], "initial classic grant");
        if (shape == "owner-write")
        {
            await Write(d, id, Payload); Check.Equal(level == 1 ? 1 : 0, f.Transport.Sends.Count(s => RawSmb.U16(s.Message, 12) == 18), "level-II owner write invalidates read caching only"); return;
        }
        if (shape == "stream-write")
        {
            var stream = await Open(d, "file:stream", 3); await Write(d, stream, Payload);
            Check.Equal(0, f.Transport.Sends.Length, "named stream has independent data cache"); return;
        }
        if (shape == "share-denial")
        {
            Status(await Complete(f, Create(access: 1)), Sharing, "share conflict remains failure after any permitted batch break");
            Check.Equal(level == 9 ? 1 : 0, f.Transport.Sends.Count(s => RawSmb.U16(s.Message, 12) == 18), "exclusive share denial versus batch handle-cache invalidation"); return;
        }
        if (shape == "stat")
        {
            var b = await Complete(f, Create(access: 0x80)); Status(b, Ok, "stat-only open"); Check.Equal(0, f.Transport.Sends.Length, "stat-only open cannot break data caching"); return;
        }
        if (shape is "second-read" or "second-write" || shape.StartsWith("stat-overwrite"))
        {
            var b = await OpenOplock(f, shape.EndsWith("-II") ? (byte)1 : level, access: shape == "second-read" ? 0x81u : shape.StartsWith("stat-overwrite") ? 0x100180u : 3u, disposition: shape.StartsWith("stat-overwrite") ? 5u : 1u);
            Status(b, Ok, "second classic open"); Check.Equal((byte)1, b[66], "contended classic grant level II");
            var breaks = f.Transport.Sends.Where(s => RawSmb.U16(s.Message, 12) == 18).ToArray();
            Check.Equal(level == 1 && !shape.StartsWith("stat-overwrite") ? 0 : 1, breaks.Length, "classic open/overwrite break count"); return;
        }
        // Obtain the mutation FileId under the same lease-free request: this
        // tests the operation's second invalidation after the ordinary open.
        var peerResponse = await OpenOplock(f, 1, disposition: 1); var peer = Id(peerResponse); var start = f.Transport.Sends.Length;
        if (shape == "lock") Check.Equal((byte)1, peerResponse[66], "source lock sequence first requires contended level-II grant");
        var request = shape switch { "lock" => Lock(peer, 0, 1), "rename" => Rename(peer, "renamed"), _ => Set(peer, 13, [1]) };
        Status(await Complete(f, request), Ok, "lock/namespace operation through contended classic handles");
        if (shape == "lock") Check.That(f.Transport.Sends.Skip(start).Any(s => RawSmb.U16(s.Message, 12) == 18 && s.Message[66] == 0), "byte-range lock revokes level-II data caching");
        if (shape == "rename") Status(await d.Send(Create()), Missing, "renamed old path is absent");
        if (shape == "delete") Status(await d.Send(Create()), 0xc0000056, "delete-pending visible despite existing oplocks");
    }
    static async Task RetainedConflict(uint state, string shape)
    {
        await using var f = new CacheFixture(true); var d = f.D; var guid = Guid.NewGuid();
        var request = DurableRequest(false, guid, "lock-lease");
        // DurableRequest puts RqLs last; replace its state using the public
        // request bytes, never the server's grant/recovery records.
        var at = (int)RawSmb.U32(request, 112); while (RawSmb.U32(request, at) != 0) at += (int)RawSmb.U32(request, at);
        RawSmb.Put32(request, at + 24 + 16, state);
        var first = await d.Send(request); var id = Id(first); LeaseState(first, state, 1); await Write(d, id, Payload);
        await d.Dispatcher.OnConnectionClosedAsync(d.Connection); var s = Session(f);
        byte[] peerRequest = shape switch
        {
            "stat" => Create(access: 0x80), "same-key" => Lease(Create(), state),
            "read-lease" => Lease(Create(), 3, 2), "rwh-lease" => Lease(Create(), 7, 2),
            "share-none" => Create(access: 1, share: 0), _ => Create()
        };
        var peer = Id(await Send(f, s, peerRequest));
        if (shape == "write") Status(await Send(f, s, RawSmb.Write(peer, [9], 0, 0, 1, 42)), Ok, "write conflicts with disconnected cache");
        if (shape == "rename") Status(await Send(f, s, Rename(peer, "renamed")), Ok, "rename conflicts with disconnected handle cache");
        var data = new byte[36]; RawSmb.Put64(data, 0, id.P); RawSmb.Put64(data, 8, id.V); guid.ToByteArray().CopyTo(data, 16);
        var reconnect = Lease(P7cTests.Context(Create(), "DH2C", data), state);
        var keep = shape is "stat" or "same-key" || state == 3 && shape is "read-lease" or "rwh-lease";
        var recovered = await Send(f, s, reconnect); Status(recovered, keep ? Ok : Missing, "retained lease keep/purge source workflow");
        if (keep) Status(await Send(f, s, RawSmb.Close(Id(recovered), 0, 1, 42)), Ok, "close retained/recovered open");
    }
    static async Task OplockSequence(string shape)
    {
        await using var f = new CacheFixture(); var d = f.D;
        if (shape == "stream-two-grants")
        {
            var file = await OpenOplock(f, 9, access: 0x120089); var stream = await OpenOplock(f, 9, "file:Stream One:$DATA", 0x120089);
            Check.Equal((byte)9, file[66], "base batch grant"); Check.Equal((byte)9, stream[66], "independent stream batch grant"); Check.Equal(0, f.Transport.Sends.Length, "stream does not break base");
            var again = await OpenOplock(f, 9, access: 0x120089, disposition: 1); Check.Equal((byte)1, again[66], "second base open receives level II");
            var notices = f.Transport.Sends.Where(s => RawSmb.U16(s.Message, 12) == 18).ToArray(); Check.Equal(1, notices.Length, "only base receives a break");
            Check.Equal(Id(file), (RawSmb.U64(notices[0].Message, 72), RawSmb.U64(notices[0].Message, 80)), "break targets base FileId, not named stream"); return;
        }
        if (shape == "unleased-first")
        {
            var first = await Open(d, disposition: 3); var second = await OpenOplock(f, 9, disposition: 1);
            Check.Equal((byte)1, second[66], "batch after ordinary open receives level II");
            Status(await Complete(f, RawSmb.Write(first, Payload, 0, 0, 1, 42)), Ok, "foreign write after ordinary open");
            Check.That(f.Transport.Sends.Any(s => RawSmb.U16(s.Message, 12) == 18 && s.Message[66] == 0), "level II broken to NONE"); return;
        }
        var initial = await OpenOplock(f, 9, access: shape.StartsWith("stat-owner") ? 0x100180u : All, share: shape.StartsWith("stat-owner") || shape is "close-on-delete" or "ack-none" ? 0u : 7u);
        var owner = Id(initial); Check.Equal((byte)9, initial[66], "batch granted before sequence");
        if (shape == "self-read")
        {
            await Write(d, owner, Payload); await Data(d, owner, Payload); Check.Equal(0, f.Transport.Sends.Length, "own READ/WRITE preserves batch"); return;
        }
        if (shape == "self-lock")
        {
            Status(await d.Send(Lock(owner, 0, 4)), Ok, "owner range lock"); Check.Equal(0, f.Transport.Sends.Length, "batch owner's BRL does not break its exclusive data cache"); return;
        }
        if (shape == "set-attributes")
        {
            var stat = Id(await Complete(f, Create(access: 0x180))); var basic = new byte[40]; RawSmb.Put32(basic, 32, 2);
            Status(await d.Send(Set(stat, 4, basic)), Ok, "attribute-only SET does not mutate file data"); Check.Equal(0, f.Transport.Sends.Length, "attribute-only open and SET preserve batch"); return;
        }
        if (shape == "query-all")
        {
            var stat = Id(await Complete(f, Create(access: 0x80))); Output(await d.Send(Query(stat, 18)));
            Check.Equal(0, f.Transport.Sends.Length, "stat open and ALL_INFORMATION do not break batch"); return;
        }
        if (shape == "disposition")
        {
            Status(await d.Send(Set(owner, 13, [1])), Ok, "owner arms delete"); Status(await d.Send(Create()), 0xc0000056, "second open denied while delete pending");
            Check.Equal(0, f.Transport.Sends.Length, "denied pending open causes no break"); return;
        }
        if (shape is "set-eof" or "set-allocation")
        {
            var stat = Id(await Complete(f, Create(access: 0x182))); var data = new byte[8]; RawSmb.Put64(data, 0, 4096);
            Status(await Complete(f, Set(stat, shape == "set-eof" ? (byte)20 : (byte)19, data)), shape == "set-eof" ? Ok : 0xc00000bb, "EOF mutation versus unsupported physical allocation");
            if (shape == "set-eof") Check.That(f.Transport.Sends.Any(s => RawSmb.U16(s.Message, 12) == 18 && s.Message[66] == 0), "EOF requires data invalidation"); return;
        }
        if (shape == "close-on-open")
        {
            f.CloseOnClassicBreak = true; var second = await OpenOplock(f, 9, disposition: 1); Check.Equal((byte)9, second[66], "closing old owner during break lets new owner obtain batch");
            Status(await d.Send(RawSmb.Read(owner, 1, 0, 0, 1, 42)), Closed, "closed old owner unusable"); return;
        }
        if (shape is "close-on-delete" or "ack-none")
        {
            f.CloseOnClassicBreak = shape == "close-on-delete"; f.AcknowledgeClassicToNone = shape == "ack-none";
            var response = await Complete(f, Create(access: 0x10000)); Status(response, shape == "close-on-delete" ? Ok : Sharing, "close versus ACK on batch delete-open conflict");
            Check.Equal(1, f.Transport.Sends.Count(s => RawSmb.U16(s.Message, 12) == 18), "one batch break");
            if (shape == "close-on-delete") { var id = Id(response); Status(await d.Send(Set(id, 13, [1])), Ok, "deletion allowed after old close"); await Close(d, id); Status(await d.Send(Create()), Missing, "name removed"); }
            else { Status(await Complete(f, Create(access: 0x10000)), Sharing, "second delete-open still conflicts"); await Write(d, owner, Payload); Check.Equal(1, f.Transport.Sends.Count(s => RawSmb.U16(s.Message, 12) == 18), "ACK-to-NONE prevents another self break"); }
            return;
        }
        if (shape == "stat-owner-and-stat-peer")
        { Id(await Complete(f, Create(access: 0x80))); Check.Equal(0, f.Transport.Sends.Length, "two stat-only opens preserve batch"); }
        var secondRequest = Create(disposition: shape == "overwrite" ? 4u : shape == "supersede" ? 0u : 1u); secondRequest[67] = 9;
        byte[] secondResponse;
        if (shape is "overwrite" or "supersede")
        {
            // MS-FSA 2.1.5.18/19: destructive CREATE invalidates the old cache;
            // ACK to NONE cannot silently regrant its stale data afterwards.
            await Write(d, owner, Payload);
            var pending = await d.Send(secondRequest); Status(pending, 0x103, "destructive CREATE waits for old batch ACK");
            var notification = f.Transport.Sends.Last(s => RawSmb.U16(s.Message, 12) == 18).Message;
            Check.Equal((byte)0, notification[66], "destructive CREATE breaks old batch to NONE");
            Check.That(File.ReadAllBytes(f.Root.Path + "/file").SequenceEqual(Payload), "truncation withheld before ACK");
            Status(await d.Send(P6Tests.Ack(owner, OplockLevel.None)), Ok, "old cache retired by ACK");
            f.Oplocks[owner] = 0;
            secondResponse = await AsyncFinal(f.Transport, pending); await Data(d, owner, []);
        }
        else secondResponse = await Complete(f, secondRequest);
        var secondId = Id(secondResponse); f.Oplocks[secondId] = secondResponse[66];
        Check.Equal((byte)1, secondResponse[66], "two ordinary opens share level-II grant");
        if (shape.StartsWith("stat-owner"))
        {
            await Close(d, secondId); var count = f.Transport.Sends.Length;
            secondResponse = await OpenOplock(f, 9, disposition: 1); secondId = Id(secondResponse);
            Check.Equal((byte)1, secondResponse[66], "third opener after closing second receives level II");
            Check.Equal(count, f.Transport.Sends.Length, "closing and reopening peer does not break remaining level-II owner");
        }
        var before = f.Transport.Sends.Length; Status(await Complete(f, RawSmb.Write(secondId, Payload, 0, 0, 1, 42)), Ok, "WRITE invalidates both level-II grants");
        var breaks = f.Transport.Sends.Skip(before).Where(s => RawSmb.U16(s.Message, 12) == 18).Select(s => s.Message).ToArray();
        Check.Equal(shape is "overwrite" or "supersede" ? 1 : 2, breaks.Length, "every currently held level-II grant notified exactly once");
        if (shape is "overwrite" or "supersede")
            Check.Equal(secondId, (RawSmb.U64(breaks[0], 72), RawSmb.U64(breaks[0], 80)), "only the new read-cache promise remains after destructive CREATE"); Check.That(breaks.All(b => b[66] == 0), "both targets NONE");
        // Current MS-SMB2 3.3.5.22.1 checks Breaking before level validation.
        // Samba's historical INVALID_OPLOCK_PROTOCOL oracle predates this rule.
        if (shape == "level-II-ack") Status(await d.Send(P6Tests.Ack(owner, OplockLevel.None)), 0xc0000184, "level-II-to-NONE leaves no outstanding break to acknowledge");
        if (shape == "double-break")
        {
            var again = await OpenOplock(f, 9, disposition: 1); Check.Equal((byte)1, again[66], "subsequent contended open gets fresh level II");
            var count = f.Transport.Sends.Length; Status(await Complete(f, RawSmb.Write(secondId, [1], 0, 0, 1, 42)), Ok, "second invalidation");
            Check.Equal(1, f.Transport.Sends.Skip(count).Count(s => RawSmb.U16(s.Message, 12) == 18), "only newly armed owner receives second break");
        }
    }
}
