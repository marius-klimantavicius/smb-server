using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Smb.Auth.Ntlm;
using Smb.Protocol.Enums;
using Smb.Testing;

internal static class UpstreamProtocolTests
{
    // Independent wire constants: MS-ERREF 2.3.1; MS-SMB2 2.2.26.1.
    const uint Success = 0, Pending = 0x103, Invalid = 0xc000000d, InvalidHandle = 0xc0000008;
    const uint Denied = 0xc0000022, LockConflict = 0xc0000054, NotGranted = 0xc0000055;
    const uint NotLocked = 0xc000007e, Cancelled = 0xc0000120, FileClosed = 0xc0000128;
    const uint Shared = 0x11, Exclusive = 0x12, Unlock = 4;
    static readonly (ulong P, ulong V) Inherit = (ulong.MaxValue, ulong.MaxValue);

    public static IEnumerable<(string, Func<Task>)> Cases()
    {
        yield return ("upstream.protocol.lock.shared-stack-count", SharedStack);
        yield return ("upstream.protocol.lock.exclusive-shared-unlock-order", ExclusiveSharedStack);
        yield return ("upstream.protocol.lock.failed-upgrade-preserves-shared", FailedUpgrade);
        yield return ("upstream.protocol.lock.exclusive-does-not-stack", ExclusiveDoesNotStack);
        yield return ("upstream.protocol.lock.unlock-other-open", WrongOwnerUnlock);
        yield return ("upstream.protocol.lock.unlock-exact-range", ExactUnlock);
        yield return ("upstream.protocol.lock.unlock-cannot-coalesce", CoalescedUnlock);
        yield return ("upstream.protocol.lock.invalid-unlock-flags-preserve", InvalidUnlockFlags);
        yield return ("upstream.protocol.lock.multiple-unlock-first-missing", UnlockFirstMissing);
        yield return ("upstream.protocol.lock.multiple-unlock-stops-at-gap", UnlockStopsAtGap);
        yield return ("upstream.protocol.lock.acquire-rollback-preserves-prior", AcquireRollback);
        yield return ("upstream.protocol.lock.acquire-internal-conflict-rollback", InternalConflictRollback);
        yield return ("upstream.protocol.lock.unlock-prefix-before-invalid-lock", UnlockPrefix);
        yield return ("upstream.protocol.lock.shared-io-and-release", SharedIo);
        yield return ("upstream.protocol.lock.exclusive-io-boundaries", ExclusiveIo);
        yield return ("upstream.protocol.lock.cancel-message-id-retry", () => CancelRetry(false));
        yield return ("upstream.protocol.lock.cancel-async-id-retry", () => CancelRetry(true));
        yield return ("upstream.protocol.compound.two-related-groups", TwoGroups);
        yield return ("upstream.protocol.compound.failed-group-reset", FailedGroupReset);
        yield return ("upstream.protocol.compound.unrelated-clears-file-id", UnrelatedClearsFileId);
        yield return ("upstream.protocol.compound.unrelated-error-isolation", UnrelatedErrorIsolation);
        yield return ("upstream.protocol.compound.closed-inherited-file", ClosedInheritedFile);
        yield return ("upstream.protocol.compound.should-propagate-file-error", RecommendedErrorPropagation);
        yield return ("upstream.protocol.credit.skipped-ids-survive-grants", SkippedIds);
        yield return ("upstream.protocol.credit.multi-credit-interior-consumed", MultiCreditInterior);
        yield return ("upstream.protocol.credit.overlap-rejection-preserves-holes", CreditOverlap);
        yield return ("upstream.protocol.credit.tcp-negotiated-roundtrip", TcpMultiCredit);
    }

    // Adapted scenarios from Samba lock.c:test_stacking, test_unlock, test_multiple_unlock,
    // test_lock, test_overlap, test_lock_read_write, test_cancel (not its implementation):
    // https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/lock.c
    // Semantics: MS-SMB2 3.3.5.14.1/.2; MS-FSA 2.1.4.10, 2.1.5.8/.9.
    static byte[] Lock((ulong P, ulong V) id, params (ulong Offset, ulong Length, uint Flags)[] elements)
    {
        var b = RawSmb.Header(10, 24 + 24 * elements.Length, 0, 1, 42);
        RawSmb.Put16(b, 64, 48);
        RawSmb.Put16(b, 66, checked((ushort)elements.Length));
        RawSmb.Put64(b, 72, id.P);
        RawSmb.Put64(b, 80, id.V);
        for (var i = 0; i < elements.Length; i++)
        {
            var p = 88 + 24 * i;
            RawSmb.Put64(b, p, elements[i].Offset);
            RawSmb.Put64(b, p + 8, elements[i].Length);
            RawSmb.Put32(b, p + 16, elements[i].Flags);
        }
        return b;
    }

    static void Status(byte[] response, uint expected, string why)
    {
        Check.That(response.Length >= 68, why + ": complete SMB2 response");
        Check.Equal(expected, RawSmb.U32(response, 8), why);
        if (expected == Success && RawSmb.U16(response, 12) == 10)
        {
            Check.Equal((ushort)4, RawSmb.U16(response, 64), "LOCK response StructureSize");
            Check.Equal((ushort)0, RawSmb.U16(response, 66), "LOCK response Reserved");
        }
    }

    static async Task L(P2Tests.Direct d, (ulong P, ulong V) id, uint expected,
        params (ulong Offset, ulong Length, uint Flags)[] elements) =>
        Status(await d.Send(Lock(id, elements)), expected, "LOCK range transition");

    static byte[] Read((ulong P, ulong V) id, uint length = 1, ulong offset = 0) =>
        RawSmb.Read(id, length, offset, 0, 1, 42);
    static byte[] Write((ulong P, ulong V) id, byte[] data, ulong offset = 0) =>
        RawSmb.Write(id, data, offset, 0, 1, 42);
    static byte[] Close((ulong P, ulong V) id) => RawSmb.Close(id, 0, 1, 42);
    static void Data(byte[] response, byte[] expected)
    {
        Status(response, Success, "READ status");
        Check.Equal((ushort)17, RawSmb.U16(response, 64), "READ StructureSize");
        Check.Equal((uint)expected.Length, RawSmb.U32(response, 68), "READ DataLength");
        Check.That(RawSmb.Buffer(response, response[66], RawSmb.U32(response, 68)).SequenceEqual(expected), "independent expected READ bytes");
    }

    static async Task SharedStack()
    {
        await using var d = new P2Tests.Direct();
        var a = await d.Open(); var b = await d.Open();
        await L(d, a, Success, (10, 10, Shared));
        await L(d, a, Success, (10, 10, Shared));
        await L(d, a, Success, (10, 10, Unlock));
        await L(d, b, NotGranted, (10, 10, Exclusive));
        await L(d, a, Success, (10, 10, Unlock));
        await L(d, a, NotLocked, (10, 10, Unlock));
        await L(d, b, Success, (10, 10, Exclusive));
    }

    static async Task ExclusiveSharedStack()
    {
        await using var d = new P2Tests.Direct();
        var a = await d.Open(); var b = await d.Open();
        await L(d, a, Success, (10, 10, Exclusive));
        await L(d, a, Success, (10, 10, Shared));
        await L(d, a, Success, (10, 10, Shared));
        await L(d, b, NotGranted, (10, 10, Shared));
        await L(d, a, Success, (10, 10, Unlock)); // Exact unlock removes exclusive before shared.
        await L(d, b, Success, (10, 10, Shared));
        await L(d, b, Success, (10, 10, Unlock));
        await L(d, a, Success, (10, 10, Unlock));
        await L(d, b, NotGranted, (10, 10, Exclusive));
        await L(d, a, Success, (10, 10, Unlock));
        await L(d, b, Success, (10, 10, Exclusive));
    }

    static async Task FailedUpgrade()
    {
        await using var d = new P2Tests.Direct();
        var a = await d.Open(); var b = await d.Open();
        await L(d, a, Success, (0, 10, Shared));
        await L(d, a, NotGranted, (0, 10, Exclusive));
        await L(d, b, NotGranted, (0, 10, Exclusive));
        await L(d, b, Success, (0, 10, Shared));
        await L(d, b, Success, (0, 10, Unlock));
        await L(d, a, Success, (0, 10, Unlock));
        await L(d, b, Success, (0, 10, Exclusive));
    }

    static async Task ExclusiveDoesNotStack()
    {
        await using var d = new P2Tests.Direct();
        var a = await d.Open(); var b = await d.Open();
        await L(d, a, Success, (0, 10, Exclusive));
        await L(d, a, NotGranted, (0, 10, Exclusive));
        await L(d, b, NotGranted, (0, 10, Shared));
        await L(d, a, Success, (0, 10, Unlock));
        await L(d, a, NotLocked, (0, 10, Unlock));
        await L(d, b, Success, (0, 10, Exclusive));
    }

    static async Task WrongOwnerUnlock()
    {
        await using var d = new P2Tests.Direct();
        var a = await d.Open(); var b = await d.Open();
        await L(d, a, Success, (20, 10, Exclusive));
        await L(d, b, NotLocked, (20, 10, Unlock));
        await L(d, b, NotGranted, (20, 10, Exclusive));
        await L(d, a, Success, (20, 10, Unlock));
        await L(d, b, Success, (20, 10, Exclusive));
    }

    static async Task ExactUnlock()
    {
        await using var d = new P2Tests.Direct();
        var a = await d.Open(); var b = await d.Open();
        await L(d, a, Success, (20, 10, Exclusive));
        foreach (var range in new (ulong Offset, ulong Length)[] { (20, 5), (21, 9), (19, 11) })
            await L(d, a, NotLocked, (range.Offset, range.Length, Unlock));
        await L(d, b, NotGranted, (20, 10, Exclusive));
        await L(d, a, Success, (20, 10, Unlock));
        await L(d, b, Success, (20, 10, Exclusive));
    }

    static async Task CoalescedUnlock()
    {
        await using var d = new P2Tests.Direct();
        var a = await d.Open(); var b = await d.Open();
        await L(d, a, Success, (0, 10, Exclusive), (10, 10, Exclusive));
        await L(d, a, NotLocked, (0, 20, Unlock));
        await L(d, b, NotGranted, (0, 1, Exclusive));
        await L(d, b, NotGranted, (19, 1, Exclusive));
        await L(d, a, Success, (0, 10, Unlock), (10, 10, Unlock));
        await L(d, b, Success, (0, 20, Exclusive));
    }

    static async Task InvalidUnlockFlags()
    {
        await using var d = new P2Tests.Direct();
        var a = await d.Open(); var b = await d.Open();
        await L(d, a, Success, (0, 10, Exclusive));
        await L(d, a, Invalid, (0, 10, 5)); // UNLOCK | SHARED_LOCK
        await L(d, a, Invalid, (0, 10, 6)); // UNLOCK | EXCLUSIVE_LOCK
        await L(d, b, NotGranted, (0, 10, Shared));
        await L(d, a, Success, (0, 10, Unlock));
        await L(d, b, Success, (0, 10, Exclusive));
    }

    static async Task UnlockFirstMissing()
    {
        await using var d = new P2Tests.Direct();
        var a = await d.Open(); var b = await d.Open();
        await L(d, a, Success, (10, 10, Exclusive));
        await L(d, a, NotLocked, (0, 10, Unlock), (10, 10, Unlock));
        await L(d, b, NotGranted, (10, 10, Exclusive));
        await L(d, a, Success, (10, 10, Unlock));
        await L(d, b, Success, (10, 10, Exclusive));
    }

    static async Task UnlockStopsAtGap()
    {
        await using var d = new P2Tests.Direct();
        var a = await d.Open(); var b = await d.Open();
        await L(d, a, Success, (0, 10, Exclusive), (20, 10, Exclusive));
        await L(d, a, NotLocked, (0, 10, Unlock), (10, 10, Unlock), (20, 10, Unlock));
        await L(d, b, Success, (0, 10, Exclusive));
        await L(d, b, NotGranted, (20, 10, Exclusive));
        await L(d, a, NotLocked, (0, 10, Unlock));
        await L(d, a, Success, (20, 10, Unlock));
        await L(d, b, Success, (20, 10, Exclusive));
    }

    static async Task AcquireRollback()
    {
        await using var d = new P2Tests.Direct();
        var a = await d.Open(); var b = await d.Open(); var c = await d.Open();
        await L(d, a, Success, (0, 10, Shared));
        await L(d, b, Success, (20, 10, Exclusive));
        await L(d, a, NotGranted, (0, 10, Shared), (10, 10, Exclusive), (20, 10, Exclusive));
        await L(d, c, NotGranted, (0, 10, Exclusive)); // Pre-request shared lock survives rollback.
        await L(d, c, Success, (10, 10, Exclusive)); // Newly acquired prefix was rolled back.
        await L(d, a, Success, (0, 10, Unlock));
        await L(d, c, Success, (0, 10, Exclusive)); // No duplicate shared prefix survived.
        await L(d, c, NotGranted, (20, 10, Exclusive)); // Foreign blocker survives.
    }

    static async Task InternalConflictRollback()
    {
        await using var d = new P2Tests.Direct();
        var a = await d.Open(); var b = await d.Open();
        await L(d, a, NotGranted, (0, 10, Exclusive), (5, 10, Exclusive));
        await L(d, a, NotLocked, (0, 10, Unlock));
        await L(d, b, Success, (0, 15, Exclusive));
    }

    static async Task UnlockPrefix()
    {
        await using var d = new P2Tests.Direct();
        var a = await d.Open(); var b = await d.Open();
        await L(d, a, Success, (0, 10, Exclusive), (20, 10, Exclusive));
        await L(d, a, Invalid, (0, 10, Unlock), (10, 10, Exclusive), (20, 10, Unlock));
        await L(d, b, Success, (0, 10, Exclusive), (10, 10, Exclusive));
        await L(d, b, NotGranted, (20, 10, Exclusive));
        await L(d, a, Success, (20, 10, Unlock));
    }

    static async Task SharedIo()
    {
        await using var d = new P2Tests.Direct();
        d.Store.Seed("a", [1, 2, 3, 4]);
        var a = await d.Open(); var b = await d.Open();
        await L(d, a, Success, (0, 2, Shared), (2, 2, Shared));
        Status(await d.Send(Write(a, [8], 2)), LockConflict, "even shared-lock owner cannot write");
        Status(await d.Send(Write(b, [9], 2)), LockConflict, "other open cannot write shared range");
        Check.Equal(0, d.Store.Control.Count("Write"), "rejected writes do not enter backend");
        Data(await d.Send(Read(a, 4)), [1, 2, 3, 4]);
        Data(await d.Send(Read(b, 4)), [1, 2, 3, 4]);
        await L(d, a, Success, (2, 2, Unlock));
        Status(await d.Send(Write(b, [9, 8], 2)), Success, "unlocked half writable");
        Status(await d.Send(Write(b, [7, 7], 1)), LockConflict, "crossing retained shared lock denied atomically");
        Data(await d.Send(Read(b, 4)), [1, 2, 9, 8]);
    }

    static async Task ExclusiveIo()
    {
        await using var d = new P2Tests.Direct();
        d.Store.Seed("a", [1, 2, 3, 4, 5, 6]);
        var a = await d.Open(); var b = await d.Open();
        await L(d, a, Success, (2, 2, Exclusive));
        Status(await d.Send(Write(a, [8, 9], 2)), Success, "exclusive owner writes its range");
        Data(await d.Send(Read(a, 2, 2)), [8, 9]);
        var reads = d.Store.Control.Count("Read"); var writes = d.Store.Control.Count("Write");
        Status(await d.Send(Read(b, 2, 1)), LockConflict, "partial read overlap denied");
        Status(await d.Send(Write(b, [7, 7], 3)), LockConflict, "partial write overlap denied");
        Check.Equal(reads, d.Store.Control.Count("Read"), "blocked read never enters backend");
        Check.Equal(writes, d.Store.Control.Count("Write"), "blocked write never enters backend");
        Data(await d.Send(Read(b, 2)), [1, 2]);
        Status(await d.Send(Write(b, [7, 7], 4)), Success, "adjacent range writable");
        await L(d, a, Success, (2, 2, Unlock));
        Data(await d.Send(Read(b, 6)), [1, 2, 8, 9, 7, 7]);
    }

    static async Task CancelRetry(bool asyncId)
    {
        await using var d = new P2Tests.Direct();
        var transport = new RecordingTransport(); transport.Attach(d.Connection);
        var a = await d.Open(); var b = await d.Open(); var c = await d.Open();
        await L(d, a, Success, (10, 10, Exclusive));
        Status(await d.Send(Lock(b, (10, 10, 2))), Pending, "blocked LOCK returns interim");
        var pending = d.Connection.PendingRequests.Values.Single();
        await L(d, b, NotLocked, (10, 10, Unlock)); // A waiter is not an acquired lock.
        Check.That(!pending.Finished.IsCompleted, "failed unlock cannot complete or cancel a pending LOCK");
        var cancel = RawSmb.Header(12, 4, pending.MessageId, 1, 42);
        RawSmb.Put16(cancel, 64, 4);
        if (asyncId) { RawSmb.Put32(cancel, 16, 2); RawSmb.Put64(cancel, 32, pending.AsyncId); }
        RawSmb.Sign(cancel, d.Session.SigningKey);
        var reply = await d.Dispatcher.ProcessMessageAsync(d.Connection, cancel);
        Check.Equal(0, reply.Length, "CANCEL has no reply of its own");
        await pending.Finished.WaitAsync(Check.Timeout);
        var final = transport.Sends.Single().Message;
        Status(final, Cancelled, "cancelled LOCK final status");
        Check.Equal(pending.MessageId, RawSmb.U64(final, 24), "cancel final MessageId");
        Check.Equal(pending.AsyncId, RawSmb.U64(final, 32), "cancel final AsyncId");
        Check.Equal((ushort)0, RawSmb.U16(final, 14), "final grants no credits");
        Check.That(d.Connection.PendingRequests.IsEmpty && d.Connection.AsyncRequests.IsEmpty, "cancel retires both pending identities");
        await L(d, c, NotGranted, (10, 10, Exclusive)); // Cancellation cannot release the blocker.
        await L(d, a, Success, (10, 10, Unlock));
        await L(d, b, Success, (10, 10, Exclusive)); // Fresh request on cancelled open succeeds.
        await L(d, c, NotGranted, (10, 10, Exclusive));
        await L(d, b, Success, (10, 10, Unlock));
        await L(d, c, Success, (10, 10, Exclusive));
        Check.Equal(1, transport.Sends.Length, "cancelled waiter never emits a second final on later unlock");
    }

    // Samba compound.c:test_compound_related2/6, test_compound_invalid2/3;
    // https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/compound.c
    // Microsoft Compound.cs:BVT_Compound_UnRelatedRequests / Compound_RelatedRequests:
    // https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/Compound/Compound.cs
    static async Task<byte[][]> Compound(P3Tests.Direct d, params (byte[] Packet, bool Related)[] steps)
    {
        var request = d.Join(steps.Select(s => s.Packet).ToArray());
        var p = 0;
        for (var i = 0; i < steps.Length; i++)
        {
            var next = RawSmb.U32(request, p + 20);
            var length = next == 0 ? request.Length - p : checked((int)next);
            var part = request.AsSpan(p, length).ToArray();
            RawSmb.Put32(part, 16, (RawSmb.U32(part, 16) & ~4u) | (steps[i].Related ? 4u : 0u));
            RawSmb.Put64(part, 40, steps[i].Related ? ulong.MaxValue : 1);
            RawSmb.Put32(part, 36, steps[i].Related ? uint.MaxValue : 42);
            RawSmb.Sign(part, d.D.Session.SigningKey);
            part.CopyTo(request, p);
            p += length;
        }
        var response = await d.D.Dispatcher.ProcessMessageAsync(d.C, request);
        d.C.ResponseSent(response);
        var parts = new List<byte[]>(); p = 0; var requestOffset = 0;
        while (true)
        {
            Check.That(parts.Count < steps.Length && response.Length - p >= 64, "bounded compound response count/header");
            var next = RawSmb.U32(response, p + 20);
            Check.That(next == 0 || (next >= 64 && next % 8 == 0 && next <= response.Length - p), "compound NextCommand bounds/alignment");
            var length = next == 0 ? response.Length - p : checked((int)next);
            var part = response.AsSpan(p, length).ToArray();
            Check.Equal(RawSmb.U16(request, requestOffset + 12), RawSmb.U16(part, 12), "compound response command order");
            Check.Equal(RawSmb.U64(request, requestOffset + 24), RawSmb.U64(part, 24), "compound response MessageId order");
            Check.That((RawSmb.U32(part, 16) & 1) != 0, "compound server response flag");
            var signature = part.AsSpan(48, 16).ToArray(); part.AsSpan(48, 16).Clear();
            Check.That(HMACSHA256.HashData(d.D.Session.SigningKey, part).AsSpan(0, 16).SequenceEqual(signature), "independent compound response signature");
            signature.CopyTo(part, 48); parts.Add(part);
            if (next == 0) break;
            requestOffset += checked((int)RawSmb.U32(request, requestOffset + 20));
            p += length;
        }
        Check.Equal(steps.Length, parts.Count, "one response per compound command");
        return parts.ToArray();
    }

    static async Task TwoGroups()
    {
        await using var d = new P3Tests.Direct();
        var r = await Compound(d,
            (d.D.Create("left"), false), (Write(Inherit, [1, 2]), true), (Close(Inherit), true),
            (d.D.Create("right"), false), (Write(Inherit, [3, 4, 5]), true), (Read(Inherit, 3), true), (Close(Inherit), true));
        foreach (var b in r) Status(b, Success, "independent related groups succeed");
        Data(r[5], [3, 4, 5]);
        Check.That(d.D.Store.Contents("left").SequenceEqual(new byte[] { 1, 2 }), "first group content isolated");
        Check.That(d.D.Store.Contents("right").SequenceEqual(new byte[] { 3, 4, 5 }), "second group selects its own generated FileId");
        Check.Equal(0, d.D.Store.ActiveHandles, "both groups close their own open");
    }

    static async Task FailedGroupReset()
    {
        await using var d = new P3Tests.Direct();
        d.D.Store.Control.Enqueue("Create", new OperationStep(Status: (NtStatus)Denied));
        var r = await Compound(d,
            (d.D.Create("failed"), false), (Write(Inherit, [9]), true), (Close(Inherit), true),
            (d.D.Create("survivor"), false), (Write(Inherit, [4, 2]), true), (Read(Inherit, 2), true), (Close(Inherit), true));
        foreach (var b in r.Take(3)) Status(b, Denied, "failed related group propagates CREATE error");
        foreach (var b in r.Skip(3)) Status(b, Success, "unrelated group clears prior dependency failure");
        Data(r[5], [4, 2]);
        Check.Equal(1, d.D.Store.Control.Count("Write"), "only independent group's write reaches backend");
        Check.Equal(0, d.D.Store.ActiveHandles, "successful group closes despite earlier error");
    }

    static async Task UnrelatedClearsFileId()
    {
        await using var d = new P3Tests.Direct();
        var echo = d.Echo(0); // Carry valid SessionId and TreeId but no FileId.
        var r = await Compound(d, (d.D.Create(), false), (Write(Inherit, [7]), true),
            (echo, false), (Close(Inherit), true));
        Status(r[0], Success, "first group CREATE"); Status(r[1], Success, "first group WRITE");
        Status(r[2], Success, "unrelated ECHO"); Status(r[3], InvalidHandle, "new group cannot inherit old group's FileId");
        Check.Equal(1, d.D.Store.ActiveHandles, "missing dependency cannot close unrelated live open");
        var id = (RawSmb.U64(r[0], 128), RawSmb.U64(r[0], 136));
        Data(await d.Send(Read(id)), [7]);
        Status(await d.Send(Close(id)), Success, "original open remains usable");
    }

    static async Task UnrelatedErrorIsolation()
    {
        await using var d = new P3Tests.Direct(); d.D.Store.Seed("a", [6, 5]);
        var create = d.D.Create(); RawSmb.Put32(create, 88, 1); // Read-only open, ordinary CREATE semantics.
        var opened = await d.Send(create); Status(opened, Success, "read-only fixture open");
        var id = (RawSmb.U64(opened, 128), RawSmb.U64(opened, 136));
        var r = await Compound(d, (Write(id, [9]), false), (Read(id, 2), false), (Close(id), false));
        Status(r[0], Denied, "unrelated write denied by access mask"); Data(r[1], [6, 5]);
        Status(r[2], Success, "unrelated close unaffected by earlier denied write");
        Check.Equal(0, d.D.Store.Control.Count("Write"), "denied unrelated write cannot mutate");
    }

    static async Task ClosedInheritedFile()
    {
        await using var d = new P3Tests.Direct();
        var r = await Compound(d, (d.D.Create(), false), (Close(Inherit), true),
            (Close(Inherit), true), (Read(Inherit), true));
        Status(r[0], Success, "CREATE before repeated close"); Status(r[1], Success, "first close succeeds");
        Status(r[2], FileClosed, "second close reports closed inherited FileId");
        Status(r[3], FileClosed, "closed dependency persists");
        Check.Equal(1, d.D.Store.Handles.Single().DisposeCalls, "repeated inherited close disposes once");
        Check.Equal(0, d.D.Store.Control.Count("Read"), "no backend access after close");
    }

    static async Task RecommendedErrorPropagation()
    {
        // MS-SMB2 3.3.5.2.7.2 says SHOULD propagate a prior FileId operation error:
        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/46dd4182-62d3-4e30-9fe5-e2ec124edca1
        // Samba test_compound_related6 instead expects later READ/CLOSE success.
        // This case checks the recommendation, not a mandatory defect or Windows product-policy claim.
        await using var d = new P3Tests.Direct(); d.D.Store.Seed("a", [6, 5]);
        var create = d.D.Create(); RawSmb.Put32(create, 88, 1);
        var r = await Compound(d, (create, false), (Read(Inherit, 2), true), (Write(Inherit, [9]), true),
            (Read(Inherit, 2), true), (Close(Inherit), true));
        Status(r[0], Success, "read-only compound CREATE"); Data(r[1], [6, 5]);
        foreach (var b in r.Skip(2)) Status(b, Denied, "SHOULD policy: propagate denied FileId operation");
        Check.Equal(1, d.D.Store.Control.Count("Read"), "recommended policy suppresses dependent backend read");
        Check.Equal(0, d.D.Store.Control.Count("Write"), "denied write has no backend mutation");
        var id = (RawSmb.U64(r[0], 128), RawSmb.U64(r[0], 136));
        Data(await d.Send(Read(id, 2)), [6, 5]);
        Status(await d.Send(Close(id)), Success, "separate request can close dependency-suppressed open");
    }

    // Samba credits.c:test_crediting_skipped_mid (bounded sequence, no server-specific grant target):
    // https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/credits.c
    // MS-SMB2 3.3.5.2.3 removes every charged sequence number, not skipped lower numbers.
    // Rejection status below is the existing direct-harness INVALID_PARAMETER policy;
    // the specification SHOULD terminate invalid-ID connections, rather than mandate that status.
    static async Task SkippedIds()
    {
        await using var d = new P3Tests.Direct(); var id = await d.Open();
        for (ulong mid = 4; mid < 68; mid++)
        {
            var b = d.Echo(0); RawSmb.Put16(b, 14, 1);
            Status(await d.Send(b, mid), Success, "higher IDs remain usable while lower IDs skipped");
        }
        Status(await d.Send(Write(id, [0x41]), 2), Success, "first skipped ID remains unconsumed across grants");
        Status(await d.Send(Write(id, [0x42], 1), 3), Success, "second skipped ID remains unconsumed");
        Status(await d.Send(Write(id, [0xff]), 2), Invalid, "used hole cannot be reused for mutation");
        Check.Equal(2, d.D.Store.Control.Count("Write"), "duplicate skipped ID never dispatches second mutation");
        Data(await d.Send(Read(id, 2), 68), [0x41, 0x42]);
    }

    static void MultiCreditState(P3Tests.Direct d)
    {
        // Deterministic pre-dispatch SMB2.1 state; the TCP case below tests actual LARGE_MTU negotiation.
        d.C.Dialect = SmbDialect.Smb210; d.C.SupportsMultiCredit = true;
        d.C.MaxReadSize = d.C.MaxWriteSize = d.C.MaxTransactSize = 1048576;
    }
    static byte[] Charged(byte[] request, ushort charge) { RawSmb.Put16(request, 6, charge); return request; }
    static byte[] Payload(int length) => Enumerable.Range(0, length).Select(i => (byte)((i * 37 + (i >> 8) + 11) & 255)).ToArray();

    static async Task MultiCreditInterior()
    {
        await using var d = new P3Tests.Direct(); var id = await d.Open(); MultiCreditState(d);
        var bytes = Payload(131073);
        var written = await d.Send(Charged(Write(id, bytes), 3), 4);
        Status(written, Success, "three-credit WRITE succeeds");
        Check.Equal((uint)bytes.Length, RawSmb.U32(written, 68), "large WRITE Count");
        Status(await d.Send(Charged(Write(id, [0xff]), 1), 5), Invalid, "interior sequence number was consumed by charge");
        Status(await d.Send(Charged(Write(id, [0xff]), 1), 6), Invalid, "last charged sequence number was consumed");
        Check.Equal(1, d.D.Store.Control.Count("Write"), "charged interior duplicates never mutate");
        Data(await d.Send(Charged(Read(id, (uint)bytes.Length), 3), 7), bytes);
    }

    static async Task CreditOverlap()
    {
        await using var d = new P3Tests.Direct(); var id = await d.Open(); MultiCreditState(d);
        Status(await d.Send(Charged(d.Echo(0), 1), 5), Success, "consume middle sequence number first");
        Status(await d.Send(Charged(Write(id, Payload(131073)), 3), 4), Invalid, "multi-credit range overlapping consumed ID rejected");
        Check.Equal(0, d.D.Store.Control.Count("Write"), "overlapping range rejected before backend");
        Status(await d.Send(Charged(Write(id, [0x41]), 1), 4), Success, "failed range did not consume unused prefix ID");
        Status(await d.Send(Charged(Write(id, [0x42], 1), 1), 6), Success, "failed range did not consume unused suffix ID");
        Data(await d.Send(Charged(Read(id, 2), 1), 7), [0x41, 0x42]);
    }

    // Microsoft MultiCredit.cs:BVT_MultiCredit_OneRequestWithMultiCredit, strengthened with exact bytes:
    // https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/Basic/MultiCredit.cs
    static async Task TcpMultiCredit()
    {
        await using var host = new HostFixture(); await host.StartAsync();
        using var peer = new LargeMtuPeer(); await peer.Connect(host.Server.Endpoint);
        var opened = await peer.Exchange(RawSmb.Create("multicredit", false, 0, peer.Session, peer.Tree), 0, 89);
        var id = (RawSmb.U64(opened, 128), RawSmb.U64(opened, 136)); var bytes = Payload(131073);
        var written = await peer.Exchange(RawSmb.Write(id, bytes, 0, 0, peer.Session, peer.Tree), 0, 17, 3);
        Check.Equal((uint)bytes.Length, RawSmb.U32(written, 68), "negotiated multi-credit WRITE Count");
        Data(await peer.Exchange(RawSmb.Read(id, (uint)bytes.Length, 0, 0, peer.Session, peer.Tree), 0, 17, 3), bytes);
        // A short patch crosses both a data-buffer boundary and the 64 KiB boundary.
        var patch = new byte[] { 91, 92, 93, 94 };
        await peer.Exchange(RawSmb.Write(id, patch, 65534, 0, peer.Session, peer.Tree), 0, 17);
        patch.CopyTo(bytes, 65534);
        Data(await peer.Exchange(RawSmb.Read(id, (uint)bytes.Length, 0, 0, peer.Session, peer.Tree), 0, 17, 3), bytes);
        await peer.Exchange(RawSmb.Close(id, 0, peer.Session, peer.Tree), 0, 60);
        Check.Equal(0, host.Store.ActiveHandles, "multi-credit TCP workflow closes backend handle");
    }

    // Small test-local TCP peer because WireClient's NEGOTIATE does not advertise LARGE_MTU.
    // Reuses only the established excluded NTLM client; all SMB layouts/statuses/signatures are raw.
    sealed class LargeMtuPeer : IDisposable
    {
        readonly TcpClient client = new TcpClient();
        ulong next;
        long available;
        byte[]? key;
        public ulong Session { get; private set; }
        public uint Tree { get; private set; }
        public async Task Connect(IPEndPoint endpoint)
        {
            using var timeout = new CancellationTokenSource(Check.Timeout);
            await client.ConnectAsync(endpoint.Address, endpoint.Port, timeout.Token);
            var negotiate = RawSmb.Negotiate(); RawSmb.Put16(negotiate, 100, 0x210); RawSmb.Put32(negotiate, 72, 4);
            available = 1;
            var response = await Exchange(negotiate, 0, 65);
            Check.Equal((ushort)0x210, RawSmb.U16(response, 68), "SMB2.1 selected");
            Check.That((RawSmb.U16(response, 66) & 2) != 0, "negotiation retains required signing");
            Check.That((RawSmb.U32(response, 88) & 4) != 0, "server negotiated LARGE_MTU");
            Check.That(RawSmb.U32(response, 96) >= 131073 && RawSmb.U32(response, 100) >= 131073, "negotiated read/write limits support test payload");
            var ntlm = new NtlmClient(HostFixture.Domain, HostFixture.User, HostFixture.Password);
            response = await Exchange(RawSmb.SessionSetup(ntlm.BuildNegotiate(), 0), 0xc0000016, 9);
            Session = RawSmb.U64(response, 40);
            var challenge = RawSmb.Buffer(response, RawSmb.U16(response, 68), RawSmb.U16(response, 70));
            await Exchange(RawSmb.SessionSetup(ntlm.BuildAuthenticate(challenge), 0, Session), 0, 9);
            key = ntlm.ExportedSessionKey;
            response = await Exchange(RawSmb.TreeConnect("\\\\localhost\\P0", 0, Session), 0, 16);
            Tree = RawSmb.U32(response, 36);
        }
        public async Task<byte[]> Exchange(byte[] request, uint status, ushort size, ushort charge = 1)
        {
            Check.That(available >= charge, "client sends only actually granted credits");
            var mid = next; next += charge; available -= charge;
            RawSmb.Put64(request, 24, mid);
            if (RawSmb.U16(request, 12) != 0) RawSmb.Put16(request, 6, charge);
            if (key != null) RawSmb.Sign(request, key);
            using var timeout = new CancellationTokenSource(Check.Timeout);
            var frame = new byte[4 + request.Length];
            frame[1] = (byte)(request.Length >> 16); frame[2] = (byte)(request.Length >> 8); frame[3] = (byte)request.Length;
            request.CopyTo(frame, 4); var stream = client.GetStream();
            await stream.WriteAsync(frame, timeout.Token);
            var prefix = new byte[4]; await stream.ReadExactlyAsync(prefix, timeout.Token);
            Check.Equal((byte)0, prefix[0], "direct TCP response type");
            var length = (prefix[1] << 16) | (prefix[2] << 8) | prefix[3];
            Check.That(length >= 64 && length <= 1048576, "bounded multi-credit TCP frame");
            var response = new byte[length]; await stream.ReadExactlyAsync(response, timeout.Token);
            RawSmb.Response(response, RawSmb.U16(request, 12), mid, status, size);
            available += RawSmb.U16(response, 14);
            if (key != null)
            {
                Check.That((RawSmb.U32(response, 16) & 8) != 0, "authenticated response signed");
                var signature = response.AsSpan(48, 16).ToArray(); response.AsSpan(48, 16).Clear();
                Check.That(HMACSHA256.HashData(key, response).AsSpan(0, 16).SequenceEqual(signature), "independent TCP HMAC signature");
                signature.CopyTo(response, 48);
            }
            return response;
        }
        public void Dispose() => client.Dispose();
    }
}
