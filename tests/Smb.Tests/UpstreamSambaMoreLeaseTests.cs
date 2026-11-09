using Smb.Protocol.Enums;
using Smb.Testing;

internal static partial class UpstreamSambaMoreTests
{
    static IEnumerable<(string Name, Func<Task> Run)> LeaseSequenceCases()
    {
        foreach (var v2 in new[] { false, true })
            foreach (var shape in new[] { "open", "overwrite", "handle-overwrite", "read-overwrite", "ack-subset", "invalid-ack", "close-member", "rename" })
                yield return ($"upstream.samba.more.lease.pending.{v2}.{shape}", () => LeasePending(v2, shape));
        foreach (var shape in new[] { "breaking-input-ignored", "parentkey-without-flag", "same-key-epoch" })
            yield return ($"upstream.samba.more.lease.v2.{shape}", () => LeaseV2Fields(shape));
        foreach (var state in new uint[] { 1, 3, 7 })
            yield return ($"upstream.samba.more.lease.directory-unsupported.{state}", () => DirectoryLeaseUnsupported(state));
        foreach (var first in new uint[] { 1, 3 })
            foreach (var second in new uint[] { 1, 3 })
                foreach (var requested in new uint[] { 0, 1, 3, 5, 7 })
                    yield return ($"upstream.samba.more.lease.upgrade-contended.{first}.{second}.{requested}", () => ContendedUpgrade(first, second, requested));
        foreach (var v2 in new[] { false, true })
            yield return ($"upstream.samba.more.lease.two-readers-cross-writes.{v2}", () => LeaseCrossWrites(v2));
        foreach (var state in new uint[] { 2, 4, 6 })
            yield return ($"upstream.samba.more.lease.invalid-state-normalized.{state}", () => InvalidLeaseState(state));
        yield return ("upstream.samba.more.lease.stream-independent-grant", LeaseStreamGrant);
        foreach (var v2 in new[] { false, true })
        {
            yield return ($"upstream.samba.more.lease.escalation.{v2}", () => LeaseEscalation(v2));
            yield return ($"upstream.samba.more.lease.cross-session-complex.{v2}", () => LeaseComplex(v2));
        }
    }
    static async Task LeasePending(bool v2, string shape)
    {
        await using var f = new CacheFixture(); var d = f.D;
        var state = shape == "handle-overwrite" ? 3u : shape == "read-overwrite" ? 1u : 7u;
        var first = await d.Send(Lease(Create(disposition: 3), state, v2: v2)); var owner = Id(first); LeaseState(first, state, 1);
        var epoch = v2 ? RawSmb.U16(Context(first, "RqLs")!, 48) : (ushort)0;
        var request = shape == "rename" ? Rename(owner, "renamed") : Create(disposition: shape.Contains("overwrite") ? 4u : 1u);
        if (shape == "rename")
        {
            var peer = await Complete(f, Lease(Create(), 3, 2, v2)); var peerId = Id(peer); LeaseState(peer, 3, 2);
            Status(await Complete(f, Rename(owner, "renamed")), Ok, "rename releases foreign HANDLE cache");
            var notifications = f.Transport.Sends.Where(s => RawSmb.U16(s.Message, 12) == 18 && RawSmb.U64(s.Message, 72) == 2).ToArray();
            Check.Equal(1, notifications.Length, "one foreign handle-cache rename break"); Check.Equal(1u, RawSmb.U32(notifications[0].Message, 92), "rename retains foreign READ cache"); await Close(d, peerId); return;
        }
        var interim = await d.Send(request); var target = shape.Contains("overwrite") ? 0u : 3u;
        if (state == 1)
        {
            Status(interim, Ok, "READ-only cache downgrade requires no ACK"); var b = await d.Send(Lease(Create(), 0, v2: v2)); LeaseState(b, 0, 1);
            Check.Equal(0u, RawSmb.U32(Context(b, "RqLs")!, 20), "read-only invalidation is already complete");
            Status(await d.Send(LeaseAck(1, 0)), 0xc0000001, "unsolicited read-only lease ACK rejected"); return;
        }
        Status(interim, 0x103, "conflicting CREATE waits for ACK");
        var notification = f.Transport.Sends.Single(s => RawSmb.U16(s.Message, 12) == 18).Message;
        Check.Equal(state, RawSmb.U32(notification, 88), "notification retains granted current state"); Check.Equal(target, RawSmb.U32(notification, 92), "required target state");
        var duplicate = await d.Send(Lease(Create(), 7, v2: v2)); var member = Id(duplicate); LeaseState(duplicate, state, 1);
        Check.Equal(2u, RawSmb.U32(Context(duplicate, "RqLs")!, 20), "same-key CREATE reports BREAK_IN_PROGRESS while ACK withheld");
        if (v2) Check.Equal((ushort)(epoch + 1), RawSmb.U16(notification, 66), "v2 break epoch increments once");
        if (shape == "close-member") await Close(d, member);
        if (shape == "invalid-ack")
        {
            Status(await d.Send(LeaseAck(1, 7)), 0xc00000d0, "ACK cannot retain rights outside requested downgrade");
            Check.That(!f.Transport.Sends.Any(s => RawSmb.U16(s.Message, 12) == 5 && (RawSmb.U32(s.Message, 16) & 2) != 0), "invalid ACK leaves conflicting CREATE pending");
        }
        var accepted = shape == "ack-subset" ? 0u : target;
        Status(await d.Send(LeaseAck(1, accepted)), Ok, "valid downgrade or subset ACK accepted");
        var final = await AsyncFinal(f.Transport, interim); Status(final, Ok, "waiting CREATE final after ACK");
        var current = await d.Send(Lease(Create(), 0, v2: v2)); LeaseState(current, accepted, 1);
        Check.Equal(0u, RawSmb.U32(Context(current, "RqLs")!, 20), "completed downgrade clears BREAK_IN_PROGRESS");
        Status(await d.Send(LeaseAck(1, accepted)), 0xc0000001, "duplicate completed ACK rejected");
    }
    static async Task LeaseV2Fields(string shape)
    {
        await using var f = new CacheFixture(); var d = f.D; var request = Lease(Create(disposition: 3), 7, v2: true, epoch: 0x4711);
        var start = (int)RawSmb.U32(request, 112); var data = start + RawSmb.U16(request, start + 10);
        if (shape == "breaking-input-ignored") RawSmb.Put32(request, data + 20, 2);
        if (shape == "parentkey-without-flag") { RawSmb.Put64(request, data + 32, 1); RawSmb.Put64(request, data + 40, ulong.MaxValue - 1); }
        var response = await d.Send(request); LeaseState(response, 7, 1); var ctx = Context(response, "RqLs")!;
        Check.Equal(52, ctx.Length, "v2 lease context size"); Check.Equal(0u, RawSmb.U32(ctx, 20), "uncontended response ignores input BREAKING flag");
        Check.Equal(0ul, RawSmb.U64(ctx, 32), "unflagged parent key ignored"); Check.Equal(0ul, RawSmb.U64(ctx, 40), "parent key second half zero");
        Check.Equal((ushort)0x4712, RawSmb.U16(ctx, 48), "initial v2 epoch increment");
        if (shape == "same-key-epoch")
        {
            var next = await d.Send(Lease(Create(), 7, v2: true, epoch: 0x33));
            Check.Equal((ushort)0x4712, RawSmb.U16(Context(next, "RqLs")!, 48), "same-key reopen without upgrade cannot reset lease epoch");
        }
    }
    static async Task DirectoryLeaseUnsupported(uint state)
    {
        await using var f = new CacheFixture(); var d = f.D;
        Check.That((d.Connection.ServerCapabilities & Smb2Capabilities.DirectoryLeasing) == 0, "directory leasing not advertised by local profile");
        var response = await d.Send(Lease(Create("dir", 3, directory: true), state, v2: true)); var id = Id(response);
        Check.Equal((byte)0, response[66], "unsupported directory caching receives NONE"); Check.That(Context(response, "RqLs") == null, "no fabricated directory lease grant");
        Check.Equal((byte)1, Output(await d.Send(Query(id, 5)))[21], "ordinary directory handle remains usable");
    }
    static async Task ContendedUpgrade(uint first, uint second, uint requested)
    {
        await using var f = new CacheFixture(); var d = f.D;
        var a = await d.Send(Lease(Create(disposition: 3), first)); LeaseState(a, first, 1);
        var b = await d.Send(Lease(Create(), second, 2)); LeaseState(b, second, 2);
        Check.Equal(0, f.Transport.Sends.Length, "initial R/RH combinations coexist without a break");
        var upgraded = await d.Send(Lease(Create(), requested));
        // Literal source upgrade3 table: a competing READ cache prevents adding
        // WRITE; adding HANDLE to an R lease is compatible and permitted.
        var expected = first == 1 && requested == 3 ? 3u : first;
        LeaseState(upgraded, expected, 1); Check.Equal(0, f.Transport.Sends.Length, "an incompatible upgrade preserves grants without a break");
        var other = await d.Send(Lease(Create(), 0, 2)); LeaseState(other, second, 2);
    }
    static async Task LeaseCrossWrites(bool v2)
    {
        await using var f = new CacheFixture(); var d = f.D; var a = Id(await d.Send(Lease(Create(disposition: 3), 1, v2: v2)));
        var b = Id(await d.Send(Lease(Create(), 1, 2, v2))); Check.Equal(0, f.Transport.Sends.Length, "two READ leases coexist");
        await Write(d, a, [1]);
        var notices = f.Transport.Sends.Where(s => RawSmb.U16(s.Message, 12) == 18).ToArray(); Check.Equal(1, notices.Length, "first cross write produces one break");
        Check.Equal(2ul, RawSmb.U64(notices[0].Message, 72), "foreign key breaks; writer's own READ lease survives");
        var rearmed = await d.Send(Lease(Create(), 1, 2, v2)); LeaseState(rearmed, 1, 2);
        await Write(d, b, [2]); await Write(d, a, [3]);
        notices = f.Transport.Sends.Where(s => RawSmb.U16(s.Message, 12) == 18).ToArray(); Check.Equal(3, notices.Length, "three alternating writes invalidate only current foreign cache");
        Check.That(notices.Select(s => RawSmb.U64(s.Message, 72)).SequenceEqual(new ulong[] { 2, 1, 2 }), "exact break key sequence");
        Check.That(notices.All(s => RawSmb.U32(s.Message, 88) == 1 && RawSmb.U32(s.Message, 92) == 0 && RawSmb.U32(s.Message, 68) == 0), "READ-to-NONE invalidation never requires ACK");
        await Data(d, a, [3]); await Data(d, b, [3]);
    }
    static async Task InvalidLeaseState(uint state)
    {
        await using var f = new CacheFixture(); var response = await f.D.Send(Lease(Create(disposition: 3), state));
        LeaseState(response, 0, 1); Check.Equal(0u, RawSmb.U32(Context(response, "RqLs")!, 20), "invalid state cannot fabricate a breaking lease");
    }
    static async Task LeaseStreamGrant()
    {
        await using var f = new CacheFixture(); var d = f.D; var file = await d.Send(Lease(Create(disposition: 3), 7)); LeaseState(file, 7, 1);
        var stream = await d.Send(Lease(Create("file:stream", 3), 7, 2)); LeaseState(stream, 7, 2);
        Check.Equal(0, f.Transport.Sends.Length, "base and named stream cache domains coexist independently");
        await Write(d, Id(file), [1]); await Write(d, Id(stream), [2]);
        Check.Equal(0, f.Transport.Sends.Length, "writes on one stream do not invalidate independent stream cache");
        await Data(d, Id(file), [1]); await Data(d, Id(stream), [2]);
    }
    static async Task LeaseEscalation(bool v2)
    {
        await using var f = new CacheFixture(); var d = f.D; var initial = await d.Send(Lease(Create(disposition: 3), 7, v2: v2)); Id(initial);
        var first = await d.Send(Create()); Status(first, 0x103, "ordinary open initiates lease break");
        var notice = f.Transport.Sends.Single(s => RawSmb.U16(s.Message, 12) == 18).Message;
        Check.Equal(3u, RawSmb.U32(notice, 92), "first break RWH to RH");
        async Task SameKey(uint expected)
        {
            var b = await Complete(f, Lease(Create(), 7, v2: v2)); var member = Id(b); LeaseState(b, expected, 1);
            if (v2) Check.Equal(RawSmb.U16(f.Transport.Sends.Last(s => RawSmb.U16(s.Message, 12) == 18).Message, 66), RawSmb.U16(Context(b, "RqLs")!, 48), "all same-key breaking responses use the common queued-break epoch");
            Check.Equal(2u, RawSmb.U32(Context(b, "RqLs")!, 20), "same-key open exposes current unacknowledged grant with BREAK_IN_PROGRESS"); await Close(d, member);
        }
        await SameKey(7); var overwrite = await d.Send(Create(disposition: 4)); Status(overwrite, 0x103, "overwrite queues behind existing break");
        Check.Equal(1, f.Transport.Sends.Count(s => RawSmb.U16(s.Message, 12) == 18), "additional conflict does not send overlapping initial breaks");
        await SameKey(7); Status(await d.Send(LeaseAck(1, 3)), Ok, "ack first downgrade to RH");
        while (f.Transport.Sends.Count(s => RawSmb.U16(s.Message, 12) == 18) < 2) await f.Transport.WaitForSendAsync().WaitAsync(Check.Timeout);
        var notices = f.Transport.Sends.Where(s => RawSmb.U16(s.Message, 12) == 18).ToArray();
        Check.Equal(3u, RawSmb.U32(notices[1].Message, 88), "second break begins at acknowledged RH"); Check.Equal(1u, RawSmb.U32(notices[1].Message, 92), "second break RH to R");
        await SameKey(3); Status(await d.Send(LeaseAck(1, 1)), Ok, "ack second downgrade to READ");
        var a = await AsyncFinal(f.Transport, first); var b = await AsyncFinal(f.Transport, overwrite); Status(a, Ok, "queued ordinary open completes"); Status(b, Ok, "queued overwrite completes");
        notices = f.Transport.Sends.Where(s => RawSmb.U16(s.Message, 12) == 18).ToArray(); Check.Equal(3, notices.Length, "three ordered lease downgrades");
        Check.Equal(1u, RawSmb.U32(notices[2].Message, 88), "last break begins at READ"); Check.Equal(0u, RawSmb.U32(notices[2].Message, 92), "last READ-to-NONE break");
        Check.Equal(0u, RawSmb.U32(notices[2].Message, 68), "last downgrade is no-ACK");
        Check.Equal(1u, RawSmb.U32(a, 68), "first CREATE action EXISTED"); Check.Equal(3u, RawSmb.U32(b, 68), "overwrite action TRUNCATED");
        if (v2)
        {
            Check.Equal((ushort)(RawSmb.U16(Context(initial, "RqLs")!, 48) + 1), RawSmb.U16(notice, 66), "first queued-break epoch");
            Check.Equal((ushort)(RawSmb.U16(notice, 66) + 1), RawSmb.U16(notices[1].Message, 66), "MS-SMB2 3.3.4.7 advances epoch for each notification; historical unchanged epoch is product note 249");
            Check.Equal((ushort)(RawSmb.U16(notice, 66) + 2), RawSmb.U16(notices[2].Message, 66), "READ invalidation advances epoch");
        }
    }
    static async Task LeaseComplex(bool v2)
    {
        await using var f = new CacheFixture(); var d = f.D;
        var a = await d.Send(Lease(Create(disposition: 3), 1, v2: v2)); var owner = Id(a); LeaseState(a, 1, 1);
        var s = Session(f); var sender = new RecordingTransport(); sender.Attach(s.Connection);
        async Task<byte[]> Other(byte[] req)
        {
            var start = f.Transport.Sends.Length; var result = await Send(f, s, req); if (RawSmb.U32(result, 8) != 0x103) return result;
            var handled = new HashSet<RecordedSend>();
            while (true)
            {
                foreach (var notification in f.Transport.Sends.Skip(start).Where(n => RawSmb.U16(n.Message, 12) == 18 && handled.Add(n)))
                {
                    var n = notification.Message;
                    if ((RawSmb.U32(n, 68) & 1) != 0) Status(await d.Send(LeaseAck(RawSmb.U64(n, 72), RawSmb.U32(n, 92))), Ok, "cross-session lease downgrade ACK");
                }
                var final = sender.Sends.LastOrDefault(n => RawSmb.U16(n.Message, 12) == RawSmb.U16(req, 12) && RawSmb.U64(n.Message, 32) == RawSmb.U64(result, 32));
                if (final != null) return final.Message;
                // Either connection may carry the next frame (MS-SMB2 3.3.4.7).
                // Cancel and join the losing wait before the next iteration:
                // an orphan wait can consume the next notification/final signal.
                using var wake = new CancellationTokenSource(Check.Timeout);
                var waits = new[] { f.Transport.WaitForSendAsync(wake.Token), sender.WaitForSendAsync(wake.Token) };
                try { await await Task.WhenAny(waits); }
                finally
                {
                    await wake.CancelAsync();
                    try { await Task.WhenAll(waits); } catch (OperationCanceledException) { }
                }
            }
        }
        var upgraded = await Other(Lease(Create(), 7, v2: v2)); LeaseState(upgraded, 7, 1); Status(await Send(f, s, RawSmb.Close(Id(upgraded), 0, 1, 42)), Ok, "close upgrading member keeps common grant");
        var foreign = await Other(Lease(Create(), 1, 2, v2)); var peer = Id(foreign); LeaseState(foreign, 1, 2);
        var breakOne = f.Transport.Sends.Single(n => RawSmb.U16(n.Message, 12) == 18).Message; Check.Equal(7u, RawSmb.U32(breakOne, 88), "common upgraded grant break current state"); Check.Equal(3u, RawSmb.U32(breakOne, 92), "common upgraded grant reduces to RH");
        var retained = await Other(Lease(Create(), 3, v2: v2)); LeaseState(retained, 3, 1); Status(await Send(f, s, RawSmb.Close(Id(retained), 0, 1, 42)), Ok, "close RH peer member");
        var mark = sender.Sends.Length; await Write(d, owner, new byte[4096]);
        var foreignBreak = sender.Sends.Skip(mark).Single(n => RawSmb.U16(n.Message, 12) == 18).Message;
        Check.Equal(2ul, RawSmb.U64(foreignBreak, 72), "owner write breaks key two across session"); Check.Equal(0u, RawSmb.U32(foreignBreak, 92), "key two loses READ");
        Status(await Other(RawSmb.Write(peer, new byte[4096], 0, 0, 1, 42)), Ok, "foreign write after prior invalidation");
        var last = f.Transport.Sends.Last(n => RawSmb.U16(n.Message, 12) == 18).Message; Check.Equal(3u, RawSmb.U32(last, 88), "foreign write breaks retained RH"); Check.Equal(0u, RawSmb.U32(last, 92), "retained lease fully invalidated");
    }
}
