using System.Text;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Protocol.Enums;
using Smb.Server;
using Smb.Server.Notification;
using Smb.Server.State;
using Smb.Testing;

// Scenario adaptations, not imported implementations. Expected names and NTSTATUS
// values below are literals independent of the backend and protocol serializers.
internal static class UpstreamStateTests
{
    const uint Success = 0, Pending = 0x103, NoSuchFile = 0xc000000f,
        NoMoreFiles = 0x80000006, Cancelled = 0xc0000120, NotifyCleanup = 0x10b,
        NotFound = 0xc0000034, FileClosed = 0xc0000128, DuplicateObjectId = 0xc000022a;

    public static IEnumerable<(string Name, Func<Task> Run)> Cases()
    {
        yield return ("upstream.state.enum.star", () => Wildcard("*",
            ["Fine", "File", "Bile", "Fille", "Nine"], [".", "..", "Fine", "File", "Bile", "Fille", "Nine"]));
        yield return ("upstream.state.enum.star-dot-star", () => Wildcard("*.*",
            ["Fine", "File.txt", "Bile", "Fille.log", "Nine"], [".", "..", "Fine", "File.txt", "Bile", "Fille.log", "Nine"]));
        yield return ("upstream.state.enum.question", () => Wildcard("Fi?e",
            ["Fine", "File", "Bile", "Fille", "Nine"], ["Fine", "File"]));
        yield return ("upstream.state.enum.suffix", () => Wildcard("*ile",
            ["Fine", "File", "Bile", "Fille", "Nine"], ["File", "Bile"]));
        yield return ("upstream.state.enum.dos-star", () => Wildcard("<txt",
            ["Fine.txt", "FileGrip.txt", "Bile.txt", "Tile.txt", "Nine.jpg"], ["Fine.txt", "FileGrip.txt", "Bile.txt", "Tile.txt"]));
        yield return ("upstream.state.enum.dos-question", () => Wildcard("Fi>e",
            ["Fine", "File", "Bile", "Fille", "Nine"], ["Fine", "File"]));
        yield return ("upstream.state.enum.dos-dot", () => Wildcard("grcBlankFile?\"",
            ["grcBlankFile1", "grcBlankFile2", "grcBlankFile3", "grc.BadFile_1.txt", "grc.BadFile_2.txt"],
            ["grcBlankFile1", "grcBlankFile2", "grcBlankFile3"]));
        yield return ("upstream.state.enum.no-match-restart", NoMatchRestart);
        yield return ("upstream.state.enum.independent-cursors", IndependentCursors);
        yield return ("upstream.state.enum.partial-restart", PartialRestart);
        yield return ("upstream.state.enum.modified-restart", ModifiedRestart);
        yield return ("upstream.state.enum.empty-close-reopen", CloseReopenCursor);
        yield return ("upstream.state.notify.cancel-rearm", CancelRearm);
        yield return ("upstream.state.notify.cancel-middle", CancelMiddle);
        yield return ("upstream.state.notify.independent-delivery", IndependentDelivery);
        yield return ("upstream.state.notify.close-one-open", CloseOneSubscription);
        yield return ("upstream.state.notify.cancel-close-reopen", CancelCloseReopen);
        yield return ("upstream.state.notify.independent-policies", IndependentPolicies);
        yield return ("upstream.state.lease.subset-sidegrade", LeaseSubsetSidegrade);
        yield return ("upstream.state.lease.close-one-member", LeaseCloseMember);
        yield return ("upstream.state.lease.reuse-after-last-close", LeaseReuse);
        yield return ("upstream.state.lease.no-self-break", LeaseNoSelfBreak);
        yield return ("upstream.state.lease.epoch-stale-upgrade", LeaseEpoch);
        yield return ("upstream.state.durable.bad-guid-then-valid", DurableGuidRetry);
        yield return ("upstream.state.durable.bad-lease-then-valid", DurableLeaseRetry);
        yield return ("upstream.state.durable.v1-second-disconnect", () => DurableCycles(true));
        yield return ("upstream.state.durable.v2-second-disconnect", () => DurableCycles(false));
        yield return ("upstream.state.durable.independent-records", DurableIndependent);
        yield return ("upstream.state.replay.repeated-and-duplicate", ReplayRepeated);
        yield return ("upstream.state.replay.unrelated-open-io", ReplayUnrelated);
    }

    // Microsoft WindowsProtocolTestSuites 29ddb4238a5443b7499e82934c90cc898861c5e7:
    // FSA/TestSuite/QueryDirectory/QueryDirectory_FileNameInExpression_FileNamesInformation.cs,
    // BVT_QueryDirectoryBySearchPattern_FileNamesInformation_* (seven wildcard cases).
    // https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/QueryDirectory/QueryDirectory_FileNameInExpression_FileNamesInformation.cs
    // MS-FSA 2.1.4.4 controls matching on both OSes. DOS_DOT is tested at end of
    // extensionless names: Windows normalizes trailing periods in upstream's names.
    static async Task Wildcard(string pattern, string[] names, string[] expected)
    {
        using var root = new Root(); root.Files(names);
        await using var f = new Fixture(root.Store());
        var id = await OpenDirectory(f);
        var actual = await Scan(f, id, pattern);
        NameSet(expected, actual, "independent wildcard set for " + pattern);
        Status(await f.Send(Enumeration(id, "")), NoMoreFiles, "exhaustion remains stable");
        await StoreWildcard(root.Store(), pattern, expected);
        await StoreWildcard(new Smb.FileSystem.Versioning.VersioningFileStore(root.Store()), pattern, expected);
    }

    static async Task StoreWildcard(IFileStore store, string pattern, string[] expected)
    {
        var opened = await store.CreateAsync("scan", FileAccessIntent.Read, CreateDispositionIntent.Open, true, false);
        Check.That(opened.IsSuccess, "backend wildcard directory opens");
        using var handle = opened.Value.Handle;
        var listing = await store.QueryDirectoryAsync(handle, pattern);
        Check.That(listing.IsSuccess, "backend wildcard listing succeeds");
        var entries = listing.Value ?? throw new InvalidOperationException("successful backend listing has entries");
        NameSet(expected, entries.Select(e => e.Name), "backend wildcard set for " + pattern);
        var bounded = await store.QueryDirectoryAsync(handle, pattern, 64);
        Check.That(bounded.IsSuccess && !bounded.Value.Truncated, "bounded wildcard listing completes");
        NameSet(expected, bounded.Value.Entries.Select(e => e.Name), "bounded wildcard set for " + pattern);
        var openedCursor = await ((IDirectoryCursorStore)store).OpenDirectoryCursorAsync(handle, pattern);
        Check.That(openedCursor.IsSuccess, "backend wildcard cursor opens");
        using var cursor = openedCursor.Value ?? throw new InvalidOperationException("successful backend cursor is non-null");
        var names = new List<string>();
        for (var page = 0; page < 64; page++)
        {
            var batch = await cursor.ReadAsync(1);
            Check.That(batch.IsSuccess && batch.Value.Entries.Count <= 1, "backend cursor stays bounded");
            names.AddRange(batch.Value.Entries.Select(e => e.Name));
            if (!batch.Value.Truncated) { NameSet(expected, names, "backend cursor wildcard set for " + pattern); return; }
        }
        throw new InvalidOperationException("backend wildcard cursor failed to reach EOF");
    }

    // Samba 2816d12d5346c4e6258d8263f68eb653fd44fd5e, dir.c:
    // test_one_file / test_modify_search (single entries, continuation, mutation/restart).
    // https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/dir.c#L481
    // https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/dir.c#L989
    static async Task NoMatchRestart()
    {
        using var root = new Root(); root.Files(["other"]);
        await using var f = new Fixture(root.Store()); var id = await OpenDirectory(f);
        Status(await f.Send(Enumeration(id, "wanted")), NoSuchFile, "first search has no match");
        Status(await f.Send(Enumeration(id, "")), NoMoreFiles, "empty continuation after no match is EOF");
        root.Files(["wanted"]);
        Status(await f.Send(Enumeration(id, "")), NoMoreFiles, "new entry cannot reset exhausted scan implicitly");
        NameSet(["wanted"], await Scan(f, id, "wanted", 1), "explicit restart after no match discovers new entry");
    }

    static async Task IndependentCursors()
    {
        using var root = new Root(); root.Files(["one.a", "two.a", "one.b", "two.b", "three.b"]);
        await using var f = new Fixture(root.Store());
        var a = await OpenDirectory(f); var b = await OpenDirectory(f);
        var firstA = await Single(f, a, "*.a"); var firstB = await Single(f, b, "*.b");
        var restA = await Scan(f, a, "", 0); var restB = await Scan(f, b, "", 0);
        NameSet(["one.a", "two.a"], new[] { firstA }.Concat(restA), "first open retains its cursor and pattern");
        NameSet(["one.b", "two.b", "three.b"], new[] { firstB }.Concat(restB), "second open retains its cursor and pattern");
        NameSet(["one.a", "two.a"], await Scan(f, a, "*.a", 16), "reopen resets only selected open");
        Status(await f.Send(Enumeration(b, "")), NoMoreFiles, "other open remains exhausted");
    }

    static async Task PartialRestart()
    {
        using var root = new Root(); root.Files(["r1", "r2", "r3", "r4"]);
        await using var f = new Fixture(root.Store()); var id = await OpenDirectory(f);
        await Single(f, id, "r*"); await Single(f, id, "");
        NameSet(["r1", "r2", "r3", "r4"], await Scan(f, id, "r*", 1), "restart discards partial cursor and returns each name once");
    }

    static async Task ModifiedRestart()
    {
        using var root = new Root(); root.Files(["m1", "m2", "m3"]);
        await using var f = new Fixture(root.Store()); var id = await OpenDirectory(f);
        await Single(f, id, "m*");
        File.Delete(System.IO.Path.Combine(root.ScanPath, "m2")); root.Files(["m4"]);
        // No snapshot assumption about the old cursor: inspect only a restarted scan.
        NameSet(["m1", "m3", "m4"], await Scan(f, id, "m*", 1), "restart sees stable post-mutation namespace");
    }

    static async Task CloseReopenCursor()
    {
        using var root = new Root();
        await using var f = new Fixture(root.Store()); var old = await OpenDirectory(f);
        var dot = await Single(f, old, "*"); Check.That(dot is "." or "..", "empty nested directory contains only dot entries");
        await Close(f, old);
        Status(await f.Send(Enumeration(old, "*", 1)), FileClosed, "closed cursor cannot be restarted");
        var fresh = await OpenDirectory(f);
        NameSet([".", ".."], await Scan(f, fresh, "*"), "new open of empty directory starts with both dot entries");
    }

    static byte[] Enumeration((ulong P, ulong V) id, string pattern, byte flags = 0)
    {
        var request = RawSmb.Enumerate(id, 0, 1, 42, pattern, flags);
        RawSmb.Put32(request, 92, 96); // Small pages; no dependency on host ordering.
        if (pattern.Length == 0) RawSmb.Put16(request, 88, 0);
        return request;
    }
    static async Task<List<string>> Scan(Fixture f, (ulong P, ulong V) id, string pattern, byte flags = 0)
    {
        var result = new List<string>();
        for (var page = 0; page < 64; page++)
        {
            var response = await f.Send(Enumeration(id, page == 0 ? pattern : "", page == 0 ? flags : (byte)0));
            if (RawSmb.U32(response, 8) == NoMoreFiles) return result;
            Status(response, Success, "directory page"); var names = DirectoryNames(response);
            Check.That(names.Length > 0, "successful directory page makes progress"); result.AddRange(names);
        }
        throw new InvalidOperationException("directory scan failed to reach EOF within 64 pages");
    }
    static async Task<string> Single(Fixture f, (ulong P, ulong V) id, string pattern)
    {
        var response = await f.Send(Enumeration(id, pattern, 2)); Status(response, Success, "single-entry query");
        var names = DirectoryNames(response); Check.Equal(1, names.Length, "RETURN_SINGLE_ENTRY returns exactly one name"); return names[0];
    }
    static string[] DirectoryNames(byte[] response) => RawSmb.Names(RawSmb.Buffer(response, RawSmb.U16(response, 66), RawSmb.U32(response, 68))).ToArray();
    static void NameSet(IEnumerable<string> expected, IEnumerable<string> actual, string why)
    {
        var names = actual.ToArray();
        Check.Equal(names.Length, names.Distinct(StringComparer.Ordinal).Count(), why + ": no duplicate names across pages");
        Check.Equal(string.Join("|", expected.Order(StringComparer.Ordinal)), string.Join("|", names.Order(StringComparer.Ordinal)), why);
    }

    // SMBLibrary 582635541d2ec0c84eac5f66cbebd41e2d35c7ae,
    // SMBLibrary.Tests/NTFileStore/NTFileStoreTests.cs: TestCancel.
    // https://github.com/TalAloni/SMBLibrary/blob/582635541d2ec0c84eac5f66cbebd41e2d35c7ae/SMBLibrary.Tests/NTFileStore/NTFileStoreTests.cs#L26
    // Samba 2816d12d5346c4e6258d8263f68eb653fd44fd5e notify.c:
    // torture_smb2_notify_double / torture_smb2_notify_close / torture_smb2_notify_tree.
    // https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/notify.c#L1737
    // https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/notify.c#L1347
    // Events are injected into individual subscriptions, with no OS-watcher timing assumption.
    static async Task CancelRearm()
    {
        await using var f = new Fixture(); var id = await OpenDirectory(f, "");
        var first = await Arm(f, id); await Cancel(f, first);
        var second = await Arm(f, id); await Cancel(f, second, true);
        var third = await Arm(f, id);
        f.Watcher.Subscriptions.Single().Emit(new FileNotifyEvent(FileNotifyAction.Added, "after-two-cancels"));
        NotifyName(await Final(f, third, Success), "after-two-cancels");
        Check.Equal(1, f.Watcher.Subscriptions.Length, "cancel/rearm retains one continuous subscription");
        await Close(f, id); Check.Equal(0, f.Watcher.ActiveCount, "close after rearm disposes watcher");
        Check.That(f.D.Connection.PendingRequests.IsEmpty && f.D.Connection.AsyncRequests.IsEmpty, "all notify identities retired");
    }
    static async Task CancelMiddle()
    {
        await using var f = new Fixture(); var id = await OpenDirectory(f, "");
        var first = await Arm(f, id); var middle = await Arm(f, id); var last = await Arm(f, id);
        await Cancel(f, middle, true);
        f.Watcher.Subscriptions.Single().Emit(new FileNotifyEvent(FileNotifyAction.Added, "first"));
        NotifyName(await Final(f, first, Success), "first"); Check.That(!last.Finished.IsCompleted, "cancelled waiter cannot consume next FIFO event");
        f.Watcher.Subscriptions.Single().Emit(new FileNotifyEvent(FileNotifyAction.Added, "last"));
        NotifyName(await Final(f, last, Success), "last");
        Check.Equal(3, f.Transport.Sends.Length, "exactly one final per request including cancelled middle");
    }
    static async Task IndependentDelivery()
    {
        await using var f = new Fixture(); var a = await OpenDirectory(f, ""); var b = await OpenDirectory(f, "");
        var pa = await Arm(f, a); var pb = await Arm(f, b);
        Check.Equal(2, f.Watcher.ActiveCount, "two opens have two subscriptions");
        f.Watcher.Subscriptions[0].Emit(new FileNotifyEvent(FileNotifyAction.Added, "a-only"));
        NotifyName(await Final(f, pa, Success), "a-only"); Check.That(!pb.Finished.IsCompleted, "other open cannot consume first subscription's event");
        f.Watcher.Subscriptions[1].Emit(new FileNotifyEvent(FileNotifyAction.Removed, "b-only"));
        NotifyName(await Final(f, pb, Success), "b-only", 2);
    }
    static async Task CloseOneSubscription()
    {
        await using var f = new Fixture(); var a = await OpenDirectory(f, ""); var b = await OpenDirectory(f, "");
        var pa = await Arm(f, a); var pb = await Arm(f, b); await Close(f, a);
        await Final(f, pa, NotifyCleanup); Check.Equal(1, f.Watcher.ActiveCount, "close disposes only selected open's watcher");
        Check.That(!pb.Finished.IsCompleted, "second open survives first open close");
        f.Watcher.Subscriptions[1].Emit(new FileNotifyEvent(FileNotifyAction.Added, "survivor"));
        NotifyName(await Final(f, pb, Success), "survivor"); await Close(f, b);
        Check.That(f.Watcher.Subscriptions.All(s => s.DisposeCalls == 1), "each watcher is disposed exactly once");
    }
    static async Task CancelCloseReopen()
    {
        await using var f = new Fixture(); var old = await OpenDirectory(f, "");
        var pending = await Arm(f, old); await Cancel(f, pending); var stale = f.Watcher.Subscriptions.Single(); await Close(f, old);
        var fresh = await OpenDirectory(f, ""); var next = await Arm(f, fresh);
        stale.Emit(new FileNotifyEvent(FileNotifyAction.Added, "stale")); Check.That(!next.Finished.IsCompleted, "closed watcher cannot complete newly opened handle");
        f.Watcher.Subscriptions[1].Emit(new FileNotifyEvent(FileNotifyAction.Added, "fresh")); NotifyName(await Final(f, next, Success), "fresh");
        Check.Equal(2, f.Transport.Sends.Length, "cancel then reopen each completes once");
    }
    static async Task IndependentPolicies()
    {
        await using var f = new Fixture(); var a = await OpenDirectory(f, ""); var b = await OpenDirectory(f, "");
        var pa = await Arm(f, a, 1, false); var pb = await Arm(f, b, 2, true);
        var sa = f.Watcher.Subscriptions[0]; var sb = f.Watcher.Subscriptions[1];
        Check.Equal(1u, (uint)sa.Filter, "first open file-name filter"); Check.That(!sa.Subtree, "first open watches one level");
        Check.Equal(2u, (uint)sb.Filter, "second open directory-name filter"); Check.That(sb.Subtree, "second open watches subtree");
        await Cancel(f, pa); var rearmed = await Arm(f, a, 0x10, true);
        Check.Equal(2, f.Watcher.Subscriptions.Length, "rearm does not replace either subscription");
        Check.Equal(1u, (uint)sa.Filter, "first open's initial policy persists after cancellation");
        Check.That(!pb.Finished.IsCompleted, "rearming another open leaves second pending");
        sa.Emit(new FileNotifyEvent(FileNotifyAction.Added, "file")); sb.Emit(new FileNotifyEvent(FileNotifyAction.Added, "subdir"));
        NotifyName(await Final(f, rearmed, Success), "file"); NotifyName(await Final(f, pb, Success), "subdir");
    }
    static async Task<PendingAsyncRequest> Arm(Fixture f, (ulong P, ulong V) id, uint filter = 1, bool subtree = false)
    {
        var request = RawSmb.Header(15, 32, 0, 1, 42); RawSmb.Put16(request, 64, 32); RawSmb.Put16(request, 66, subtree ? (ushort)1 : (ushort)0);
        RawSmb.Put32(request, 68, 4096); RawSmb.Put64(request, 72, id.P); RawSmb.Put64(request, 80, id.V); RawSmb.Put32(request, 88, filter);
        var response = await f.Send(request); Status(response, Pending, "notification is armed");
        var mid = RawSmb.U64(response, 24); return f.D.Connection.PendingRequests.Values.Single(p => p.MessageId == mid);
    }
    static async Task Cancel(Fixture f, PendingAsyncRequest pending, bool asyncId = false)
    {
        var request = RawSmb.Header(12, 4, pending.MessageId, 1, 42); RawSmb.Put16(request, 64, 4);
        if (asyncId) { RawSmb.Put32(request, 16, 2); RawSmb.Put64(request, 32, pending.AsyncId); }
        RawSmb.Sign(request, f.D.Session.SigningKey);
        await f.D.Dispatcher.ProcessMessageAsync(f.D.Connection, request).AsTask().WaitAsync(Check.Timeout);
        await Final(f, pending, Cancelled);
    }
    static async Task<byte[]> Final(Fixture f, PendingAsyncRequest pending, uint status)
    {
        await pending.Finished.WaitAsync(Check.Timeout);
        Check.Equal(status, (uint)pending.FinalStatus, "independent final notify status");
        var response = f.Transport.Sends.Single(s => RawSmb.U64(s.Message, 24) == pending.MessageId).Message;
        Status(response, status, "notify wire status"); return response;
    }
    static void NotifyName(byte[] response, string expected, uint action = 1)
    {
        Check.Equal((ushort)9, RawSmb.U16(response, 64), "CHANGE_NOTIFY response StructureSize");
        var data = RawSmb.Buffer(response, RawSmb.U16(response, 66), RawSmb.U32(response, 68));
        Check.That(data.Length >= 12, "FILE_NOTIFY_INFORMATION header"); Check.Equal(0u, RawSmb.U32(data, 0), "exactly one notify record");
        Check.Equal(action, RawSmb.U32(data, 4), "independent notification action");
        var length = RawSmb.U32(data, 8); Check.Equal((uint)Encoding.Unicode.GetByteCount(expected), length, "notification name byte count");
        Check.Equal(expected, Encoding.Unicode.GetString(data, 12, checked((int)length)), "notification name");
    }

    // Samba 2816d12d5346c4e6258d8263f68eb653fd44fd5e lease.c:
    // test_lease_upgrade / test_lease_upgrade2 / test_lease_nobreakself /
    // test_lease_v2_epoch2. MS-SMB2 3.3.5.9.8/.11 and 3.3.4.17 adjudicate.
    // https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/lease.c#L208
    // https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/lease.c#L650
    // https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/lease.c#L2156
    static async Task LeaseSubsetSidegrade()
    {
        using var root = new Root(); root.File("a", "original"); await using var f = new Fixture(root.Store(), SmbFeaturePolicy.Caching);
        var first = await f.Send(Lease(Open("a"), 11, 5)); LeaseState(first, 11, 5);
        var sidegrade = await f.Send(Lease(Open("a"), 11, 3)); LeaseState(sidegrade, 11, 5);
        var subset = await f.Send(Lease(Open("a"), 11, 1)); LeaseState(subset, 11, 5);
        var promoted = await f.Send(Lease(Open("a"), 11, 7)); LeaseState(promoted, 11, 7);
        Check.Equal(4, f.D.Session.Opens.Count, "same lease key creates four distinct opens");
        Check.Equal(0, f.Transport.Sends.Length, "same-key sidegrades and subsets cannot break themselves");
    }
    static async Task LeaseCloseMember()
    {
        using var root = new Root(); root.File("a", "original"); await using var f = new Fixture(root.Store(), SmbFeaturePolicy.Caching);
        var a = await f.Send(Lease(Open("a"), 12, 7)); var b = await f.Send(Lease(Open("a"), 12, 7)); LeaseState(a, 12, 7); LeaseState(b, 12, 7);
        await Close(f, Id(a));
        var c = await f.Send(Lease(Open("a"), 12, 1)); LeaseState(c, 12, 7);
        await Close(f, Id(c));
        Status(await f.Send(RawSmb.Write(Id(b), [0x71], 0, 0, 1, 42)), Success, "remaining same-key member still writes");
        Check.Equal(7u, (uint)f.D.Session.Opens[Id(b)].LeaseState, "closing other members preserves shared rights");
        Check.Equal(0, f.Transport.Sends.Length, "member close does not generate self break");
    }
    static async Task LeaseReuse()
    {
        using var root = new Root(); root.File("a", "original"); root.File("b", "different"); await using var f = new Fixture(root.Store(), SmbFeaturePolicy.Caching);
        var a = await f.Send(Lease(Open("a"), 13, 7)); var b = await f.Send(Lease(Open("a"), 13, 7)); LeaseState(a, 13, 7); LeaseState(b, 13, 7);
        await Close(f, Id(a)); await Close(f, Id(b));
        var reused = await f.Send(Lease(Open("b"), 13, 7)); LeaseState(reused, 13, 7);
        Status(await f.Send(RawSmb.Write(Id(reused), [0x72], 0, 0, 1, 42)), Success, "last close releases key for different object");
        Check.Equal("original", NativeHost.ReadAllText(System.IO.Path.Combine(root.Path, "a")), "reused key never redirects old object");
    }
    static async Task LeaseNoSelfBreak()
    {
        using var root = new Root(); root.File("a", "original"); await using var f = new Fixture(root.Store(), SmbFeaturePolicy.Caching);
        var first = await f.Send(Lease(Open("a"), 14, 1)); var second = await f.Send(Lease(Open("a"), 15, 1)); LeaseState(first, 14, 1); LeaseState(second, 15, 1);
        Status(await f.Send(RawSmb.Write(Id(first), [0x73], 0, 0, 1, 42)), Success, "read-only lease invalidation needs no ACK");
        var breaks = f.Transport.Sends.Where(s => RawSmb.U16(s.Message, 64) == 44).Select(s => s.Message).ToArray();
        Check.Equal(1, breaks.Length, "only foreign lease key is broken"); Check.Equal(15ul, RawSmb.U64(breaks[0], 72), "break addresses other lease");
        Check.Equal(1u, RawSmb.U32(breaks[0], 88), "break's previous state is READ"); Check.Equal(0u, RawSmb.U32(breaks[0], 92), "break target is NONE");
        Check.Equal(0u, RawSmb.U32(breaks[0], 68), "read-only lease break does not require ACK");
        Check.Equal(1u, (uint)f.D.Session.Opens[Id(first)].LeaseState, "writer's own lease survives");
        Check.Equal(0u, (uint)f.D.Session.Opens[Id(second)].LeaseState, "foreign read cache invalidated");
    }
    static async Task LeaseEpoch()
    {
        using var root = new Root(); root.File("a", "original"); await using var f = new Fixture(root.Store(), SmbFeaturePolicy.Caching);
        var first = await f.Send(Lease(Open("a"), 16, 1, true, 0xfffe)); LeaseState(first, 16, 1);
        Check.Equal((ushort)0xffff, RawSmb.U16(ContextData(first, "RqLs"), 48), "initial v2 epoch increments");
        var second = await f.Send(Lease(Open("a"), 16, 5, true, 2)); LeaseState(second, 16, 5);
        Check.Equal((ushort)0, RawSmb.U16(ContextData(second, "RqLs"), 48), "promotion wraps retained epoch instead of using incoming epoch");
        await Close(f, Id(first));
        var third = await f.Send(Lease(Open("a"), 16, 7, true, 0x4711)); LeaseState(third, 16, 7);
        Check.Equal((ushort)1, RawSmb.U16(ContextData(third, "RqLs"), 48), "later promotion continues common epoch after member close");
    }

    // Samba durable_open.c test_durable_open_reopen2 / _reopen2_lease:
    // https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/durable_open.c#L731
    // Microsoft DurableHandleV2.cs BVT_DurableHandleV2_Reconnect_WithBatchOplock /
    // BVT_DurableHandleV2_Reconnect_WithLeaseV1:
    // https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/DurableHandle/DurableHandleV2.cs#L440
    // Real grants, transport-loss retention and fresh authenticated sessions; no seeded
    // durable state, reflection, persistent-handle/CA fallback, or production encoders.
    static async Task DurableGuidRetry()
    {
        using var root = new Root(); root.File("a", "recoverable"); await using var f = new Fixture(root.Store(), SmbFeaturePolicy.Durable);
        var guid = Guid.NewGuid(); var response = await f.Send(Durable(Open("a"), guid)); GrantedDurable(response, false);
        var old = Id(response); var retained = f.D.Session.Opens[old]; await f.Lose(f.D.Session); var session = f.NewSession();
        Status(await f.Send(Reconnect("a", old, Guid.NewGuid()), session), NotFound, "wrong CreateGuid is rejected");
        var restored = await f.Send(Reconnect("a", old, guid), session); Status(restored, Success, "failed claim leaves valid reconnect available");
        Check.That(ReferenceEquals(retained, session.Opens[Id(restored)]), "retry restores original open");
        Status(await f.Send(RawSmb.Read(old, 1, 0, 0, 1, 42), session), FileClosed, "old FileId cannot address restored open");
        await AssertRead(f, session, Id(restored), "recoverable");
    }
    static async Task DurableLeaseRetry()
    {
        using var root = new Root(); root.File("a", "leased-data"); await using var f = new Fixture(root.Store(), SmbFeaturePolicy.Durable);
        var guid = Guid.NewGuid(); var response = await f.Send(Lease(Durable(Open("a"), guid), 17, 7)); GrantedDurable(response, false); LeaseState(response, 17, 7);
        var old = Id(response); await f.Lose(f.D.Session); var session = f.NewSession();
        Status(await f.Send(Reconnect("a", old, guid), session), NotFound, "missing lease context cannot consume retained record");
        Status(await f.Send(Lease(Reconnect("a", old, guid), 18, 7), session), NotFound, "wrong lease key cannot consume retained record");
        var restored = await f.Send(Lease(Reconnect("a", old, guid), 17, 7), session); LeaseState(restored, 17, 7);
        await AssertRead(f, session, Id(restored), "leased-data");
    }
    static async Task DurableCycles(bool v1)
    {
        using var root = new Root(); root.File("a", "two-cycles"); await using var f = new Fixture(root.Store(), SmbFeaturePolicy.Durable);
        var guid = Guid.NewGuid(); var response = await f.Send(Durable(Open("a"), guid, v1)); GrantedDurable(response, v1);
        var id = Id(response); var retained = f.D.Session.Opens[id]; await f.Lose(f.D.Session);
        f.Clock.Advance(TimeSpan.FromSeconds(1)); var second = f.NewSession();
        var reconnect = await f.Send(Reconnect("a", id, guid, v1), second); Status(reconnect, Success, "first reconnect"); id = Id(reconnect);
        await AssertRead(f, second, id, "two-cycles"); await f.Lose(second);
        // Beyond the first disconnect's two-second deadline, but inside the second's.
        f.Clock.Advance(TimeSpan.FromMilliseconds(1500)); f.D.Dispatcher.ScavengeDurableHandles(); var third = f.NewSession();
        reconnect = await f.Send(Reconnect("a", id, guid, v1), third); Status(reconnect, Success, "new disconnect establishes new retention deadline");
        Check.That(ReferenceEquals(retained, third.Opens[Id(reconnect)]), "two cycles preserve one backend open");
        await AssertRead(f, third, Id(reconnect), "two-cycles");
    }
    static async Task DurableIndependent()
    {
        using var root = new Root(); root.File("a", "first-data"); root.File("b", "second-data"); await using var f = new Fixture(root.Store(), SmbFeaturePolicy.Durable);
        var ga = Guid.NewGuid(); var gb = Guid.NewGuid(); var a = await f.Send(Durable(Open("a"), ga)); var b = await f.Send(Durable(Open("b"), gb));
        GrantedDurable(a, false); GrantedDurable(b, false); await f.Lose(f.D.Session); var session = f.NewSession();
        Status(await f.Send(Reconnect("a", Id(a), gb), session), NotFound, "another retained record's GUID cannot steal first open");
        var rb = await f.Send(Reconnect("b", Id(b), gb), session); Status(rb, Success, "second retained record remains available");
        var ra = await f.Send(Reconnect("a", Id(a), ga), session); Status(ra, Success, "failed mixed claim does not consume first record");
        Check.Equal(2, session.Opens.Count, "both independent records published once");
        await AssertRead(f, session, Id(rb), "second-data"); await AssertRead(f, session, Id(ra), "first-data");
    }

    // Samba replay.c test_replay_dhv2_oplock1 / test_replay_twice_durable:
    // https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/replay.c#L354
    // https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/replay.c#L5783
    // Microsoft's mature Replay/ReplayIsReplayEligible.cs scopes invalidation to Open:
    // https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/Replay/ReplayIsReplayEligible.cs#L787
    static async Task ReplayRepeated()
    {
        using var root = new Root(); root.File("a", "preserved"); await using var f = new Fixture(root.Store(), SmbFeaturePolicy.Durable);
        var guid = Guid.NewGuid(); var first = await f.Send(Durable(Open("a"), guid)); GrantedDurable(first, false);
        var id = Id(first);
        for (var i = 0; i < 3; i++)
        {
            var replay = await f.Send(Replay(Durable(Open("a"), guid))); CheckReplay(replay, id);
        }
        Status(await f.Send(Durable(Open("a"), guid)), DuplicateObjectId, "non-replay duplicate GUID rejected after successful replays");
        CheckReplay(await f.Send(Replay(Durable(Open("a"), guid))), id);
        Check.Equal(1, f.D.Session.Opens.Count, "duplicate rejection cannot erase replay owner or acquire another open");
        await AssertRead(f, f.D.Session, id, "preserved");
    }
    static async Task ReplayUnrelated()
    {
        using var root = new Root(); root.File("a", "preserved"); root.File("b", "unrelated"); await using var f = new Fixture(root.Store(), SmbFeaturePolicy.Durable);
        var guid = Guid.NewGuid(); var first = await f.Send(Durable(Open("a"), guid)); GrantedDurable(first, false); var id = Id(first);
        var other = await f.Send(Open("b")); Status(other, Success, "unrelated open");
        Status(await f.Send(RawSmb.Write(Id(other), [0x75], 0, 0, 1, 42)), Success, "unrelated write"); await Close(f, Id(other));
        CheckReplay(await f.Send(Replay(Durable(Open("a"), guid))), id);
        Check.Equal(1, f.D.Session.Opens.Count, "I/O and close on another open leave this replay owner intact");
        await AssertRead(f, f.D.Session, id, "preserved");
    }
    static void CheckReplay(byte[] response, (ulong P, ulong V) expected)
    {
        Status(response, Success, "eligible CREATE replay"); Check.Equal(expected, Id(response), "replay retains same FileId");
        Check.Equal(1u, RawSmb.U32(response, 68), "replay of existing-file open retains FILE_OPENED action");
        Check.Equal((byte)9, response[66], "replay retains Batch oplock"); GrantedDurable(response, false);
        Check.Equal(9ul, RawSmb.U64(response, 112), "replay preserves known file length");
    }

    static byte[] Open(string path)
    {
        var request = RawSmb.Create(path, false, 0, 1, 42); RawSmb.Put32(request, 100, 1); return request;
    }
    static byte[] Lease(byte[] request, ulong key, uint state, bool v2 = false, ushort epoch = 0)
    {
        request[67] = 255; var data = new byte[v2 ? 52 : 32]; RawSmb.Put64(data, 0, key); RawSmb.Put64(data, 8, 0x12345678);
        RawSmb.Put32(data, 16, state); if (v2) RawSmb.Put16(data, 48, epoch); return AddContext(request, "RqLs", data);
    }
    static byte[] Durable(byte[] request, Guid guid, bool v1 = false)
    {
        request[67] = 9; var data = new byte[v1 ? 16 : 32];
        if (!v1) { RawSmb.Put32(data, 0, 2000); guid.ToByteArray().CopyTo(data, 16); }
        return AddContext(request, v1 ? "DHnQ" : "DH2Q", data);
    }
    static byte[] Reconnect(string path, (ulong P, ulong V) id, Guid guid, bool v1 = false)
    {
        var data = new byte[v1 ? 16 : 36]; RawSmb.Put64(data, 0, id.P); RawSmb.Put64(data, 8, id.V);
        if (!v1) guid.ToByteArray().CopyTo(data, 16);
        return AddContext(Open(path), v1 ? "DHnC" : "DH2C", data);
    }
    static byte[] Replay(byte[] request) { RawSmb.Put32(request, 16, RawSmb.U32(request, 16) | 0x20000000); return request; }
    static byte[] AddContext(byte[] request, string name, byte[] data)
    {
        var offset = (request.Length + 7) & ~7; var previous = (int)RawSmb.U32(request, 112);
        if (previous != 0)
        {
            while (RawSmb.U32(request, previous) != 0) previous += checked((int)RawSmb.U32(request, previous));
            RawSmb.Put32(request, previous, checked((uint)(offset - previous)));
        }
        Array.Resize(ref request, offset + ((24 + data.Length + 7) & ~7));
        RawSmb.Put16(request, offset + 4, 16); RawSmb.Put16(request, offset + 6, 4); RawSmb.Put16(request, offset + 10, 24); RawSmb.Put32(request, offset + 12, (uint)data.Length);
        Encoding.ASCII.GetBytes(name).CopyTo(request, offset + 16); data.CopyTo(request, offset + 24);
        if (previous == 0) RawSmb.Put32(request, 112, (uint)offset);
        RawSmb.Put32(request, 116, (uint)request.Length - RawSmb.U32(request, 112)); return request;
    }
    static byte[] ContextData(byte[] response, string name)
    {
        var start = checked((int)RawSmb.U32(response, 144)); var length = checked((int)RawSmb.U32(response, 148));
        Check.That(start >= 152 && length >= 16 && start + length <= response.Length, "CREATE response contexts bounded");
        var end = start + length;
        for (var at = start; at < end;)
        {
            Check.That(at + 16 <= end, "CREATE context header bounded");
            var nameOffset = RawSmb.U16(response, at + 4); var nameLength = RawSmb.U16(response, at + 6);
            var dataOffset = RawSmb.U16(response, at + 10); var dataLength = checked((int)RawSmb.U32(response, at + 12));
            Check.That(at + nameOffset + nameLength <= end && at + dataOffset + dataLength <= end, "CREATE context buffers bounded");
            if (Encoding.ASCII.GetString(response, at + nameOffset, nameLength) == name) return response.AsSpan(at + dataOffset, dataLength).ToArray();
            var next = checked((int)RawSmb.U32(response, at)); if (next == 0) break;
            Check.That(next >= 16 && (next & 7) == 0, "CREATE context chain progresses"); at += next;
        }
        throw new InvalidOperationException("Missing expected CREATE response context " + name);
    }
    static void LeaseState(byte[] response, ulong key, uint state)
    {
        Status(response, Success, "lease CREATE"); Check.Equal((byte)255, response[66], "lease oplock marker"); var data = ContextData(response, "RqLs");
        Check.That(data.Length is 32 or 52, "lease response v1/v2 layout"); Check.Equal(key, RawSmb.U64(data, 0), "lease key low");
        Check.Equal(0x12345678ul, RawSmb.U64(data, 8), "lease key high"); Check.Equal(state, RawSmb.U32(data, 16), "independent granted lease state");
        Check.Equal(0u, RawSmb.U32(data, 20), "lease is not breaking"); Check.Equal(0ul, RawSmb.U64(data, 24), "reserved lease duration");
    }
    static void GrantedDurable(byte[] response, bool v1)
    {
        Status(response, Success, "eligible durable grant"); var data = ContextData(response, v1 ? "DHnQ" : "DH2Q");
        Check.Equal(8, data.Length, "durable response context data size");
        if (!v1) { Check.Equal(2000u, RawSmb.U32(data, 0), "requested retention timeout"); Check.Equal(0u, RawSmb.U32(data, 4), "ordinary nonpersistent handle"); }
    }
    static async Task AssertRead(Fixture f, SmbSession session, (ulong P, ulong V) id, string expected)
    {
        var response = await f.Send(RawSmb.Read(id, (uint)Encoding.UTF8.GetByteCount(expected), 0, 0, 1, 42), session);
        Status(response, Success, "restored/retained handle reads independently known content");
        Check.Equal(expected, Encoding.UTF8.GetString(RawSmb.Buffer(response, response[66], RawSmb.U32(response, 68))), "known file content");
    }
    static async Task<(ulong P, ulong V)> OpenDirectory(Fixture f, string path = "scan")
    {
        var response = await f.Send(RawSmb.Create(path, true, 0, 1, 42)); Status(response, Success, "open directory"); return Id(response);
    }
    static async Task Close(Fixture f, (ulong P, ulong V) id) => Status(await f.Send(RawSmb.Close(id, 0, 1, 42)), Success, "CLOSE");
    static (ulong P, ulong V) Id(byte[] response) => (RawSmb.U64(response, 128), RawSmb.U64(response, 136));
    static void Status(byte[] response, uint expected, string why) => Check.Equal(expected, RawSmb.U32(response, 8), why);

    sealed class Root : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "smb-upstream-state-" + Guid.NewGuid().ToString("N"));
        public string ScanPath => System.IO.Path.Combine(Path, "scan");
        public Root() => Directory.CreateDirectory(ScanPath);
        public void File(string name, string content) => System.IO.File.WriteAllText(System.IO.Path.Combine(Path, name), content);
        public void Files(string[] names) { foreach (var name in names) System.IO.File.WriteAllText(System.IO.Path.Combine(ScanPath, name), ""); }
        public LocalFileStore Store() => new(Path, false, null, exclusiveServerAccess: true);
        public void Dispose() => Directory.Delete(Path, true);
    }
    sealed class Fixture : IAsyncDisposable
    {
        public readonly P2Tests.Direct D;
        public readonly FakeWatcher Watcher = new();
        public readonly RecordingTransport Transport = new();
        public readonly ManualClock Clock = new();
        ulong sessionId = 1;
        public Fixture(IFileStore? store = null, SmbFeaturePolicy? profile = null)
        {
            D = new P2Tests.Direct(store); D.Options.DirectoryWatcher = Watcher;
            D.Session.Identity = new Smb.Auth.SecurityIdentity { DomainName = "UPSTREAM", UserName = "state-tests" };
            D.Options.TimeProvider = Clock; D.Options.DurableHandleTimeout = TimeSpan.FromSeconds(2);
            if (profile != null)
            {
                D.Options.FeaturePolicy = profile; D.Connection.Dialect = SmbDialect.Smb300;
                D.Connection.ServerCapabilities |= Smb2Capabilities.Leasing;
                Check.That(D.Session.TryAttachChannel(new SmbChannel { Connection = D.Connection, SigningKey = D.Session.SigningKey }), "fixture attaches original channel");
            }
            Transport.Attach(D.Connection);
        }
        public async Task Lose(SmbSession session) => await D.Dispatcher.OnConnectionClosedAsync(session.Connection).AsTask().WaitAsync(Check.Timeout);
        public SmbSession NewSession()
        {
            var connection = D.Channel(); connection.Dialect = SmbDialect.Smb300; connection.ServerCapabilities |= Smb2Capabilities.Leasing;
            connection.ClientGuid = D.Connection.ClientGuid.ToArray();
            var session = new SmbSession { SessionId = ++sessionId, SessionGlobalId = sessionId, Connection = connection, State = SessionState.Valid,
                SigningRequired = true, SigningKey = new byte[16], SessionKey = new byte[16], Identity = D.Session.Identity };
            Check.That(session.TryAttachChannel(new SmbChannel { Connection = connection, SigningKey = session.SigningKey }), "fixture attaches replacement channel");
            D.State.Connections.TryAdd(connection.ConnectionId, connection); D.State.SessionGlobalList.TryAdd(session.SessionGlobalId, session);
            session.TreeConnects.TryAdd(42, new SmbTreeConnect { TreeId = 42, Session = session, Share = D.Tree.Share, MaximalAccess = D.Tree.MaximalAccess });
            D.Options.Metrics.OnAuthenticationSucceeded(); D.Options.Metrics.OnTreeConnected(); return session;
        }
        public Task<byte[]> Send(byte[] request) => D.Send(request).WaitAsync(Check.Timeout);
        public Task<byte[]> Send(byte[] request, SmbSession session)
        {
            RawSmb.Put64(request, 40, session.SessionId); RawSmb.Put32(request, 36, 42); return D.Send(request, session.Connection).WaitAsync(Check.Timeout);
        }
        public async ValueTask DisposeAsync()
        {
            foreach (var connection in D.State.Connections.Values.ToArray())
                await D.Dispatcher.OnConnectionClosedAsync(connection, Smb2Dispatcher.CloseReason.Shutdown).AsTask().WaitAsync(Check.Timeout);
            await D.Dispatcher.CloseRetainedHandlesAsync().AsTask().WaitAsync(Check.Timeout);
        }
    }
}
