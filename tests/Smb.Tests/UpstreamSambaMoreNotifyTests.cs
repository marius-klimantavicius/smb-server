using Smb.Server.State;
using Smb.Testing;

internal static partial class UpstreamSambaMoreTests
{
    static IEnumerable<(string Name, Func<Task> Run)> CreditNotifyCases()
    {
        foreach (var two in new[] { false, true })
            yield return ($"upstream.samba.more.credit.notify-limit.{two}", () => NotifyLimit(two));
        foreach (var initial in new[] { false, true })
            foreach (var secondSession in new[] { false, true })
                yield return ($"upstream.samba.more.notify.delete-directory.{initial}.{secondSession}", () => NotifyDeleteDirectory(initial, secondSession));
        foreach (var mask in new uint[] { 0x100, 0xfff })
            foreach (var sameDescriptor in new[] { false, true })
                yield return ($"upstream.samba.more.notify.security-update.{mask:x}.{sameDescriptor}", () => NotifySecurity(mask, sameDescriptor));
        yield return ("upstream.samba.more.notify.attribute-only-handle-denied", NotifyNoListAccess);
        yield return ("upstream.samba.more.notify.mask-policy-through-cancel", NotifyMaskPolicy);
        yield return ("upstream.samba.more.credit.notify-bound-channel-limit", BoundNotifyLimit);
    }
    static async Task NotifyLimit(bool two)
    {
        await using var f = new CacheFixture(); var d = f.D; d.Options.MaxOutstandingRequests = 3; d.Options.DirectoryWatcher = new FakeWatcher();
        var primary = await Open(d, "", directory: true); var lanes = new List<(SmbSession S, (ulong P, ulong V) Id, RecordingTransport T)> { (d.Session, primary, f.Transport) };
        if (two)
        {
            var s = Session(f); var t = new RecordingTransport(); t.Attach(s.Connection);
            var dir = Id(await Send(f, s, Create("", directory: true))); lanes.Add((s, dir, t));
        }
        async Task<byte[]> Submit(SmbSession s, byte[] b)
        {
            if (s == d.Session) return await d.Send(b);
            return await Send(f, s, b);
        }
        var admitted = new List<((SmbSession S, (ulong P, ulong V) Id, RecordingTransport T) Lane, List<byte[]> Pending)>();
        foreach (var lane in lanes)
        {
            var pending = new List<byte[]>();
            for (var i = 0; i < 3; i++)
            {
                var response = await Submit(lane.S, Notify(lane.Id)); Status(response, 0x103, "per-connection notify admission below configured bound");
                Check.That(pending.All(b => RawSmb.U64(b, 32) != RawSmb.U64(response, 32)), "distinct async identities for independent pending requests"); pending.Add(response);
            }
            admitted.Add((lane, pending));
        }
        foreach (var entry in admitted)
        {
            var lane = entry.Lane; var pending = entry.Pending;
            Status(await Submit(lane.S, Notify(lane.Id)), 0xc000009a, "notify resource limit rejects exactly the excess request");
            var cancel = RawSmb.Header(12, 4, 0, lane.S.SessionId); RawSmb.Put16(cancel, 64, 4); RawSmb.Put32(cancel, 16, 2); RawSmb.Put64(cancel, 32, RawSmb.U64(pending[1], 32));
            await Submit(lane.S, cancel); Status(await AsyncFinal(lane.T, pending[1], 15), 0xc0000120, "CANCEL returns one terminal status to middle notify");
            var retry = await Submit(lane.S, Notify(lane.Id)); Status(retry, 0x103, "completed cancellation releases one resource slot");
            Status(await Submit(lane.S, Notify(lane.Id)), 0xc000009a, "retry did not release additional slots");
            Status(await Submit(lane.S, RawSmb.Close(lane.Id, 0, 1, 42)), Ok, "close directory retires outstanding notify requests");
            foreach (var b in new[] { pending[0], pending[2], retry }) Status(await AsyncFinal(lane.T, b, 15), 0x10b, "outstanding CHANGE_NOTIFY receives NOTIFY_CLEANUP on close");
        }
    }
    static async Task NotifyNoListAccess()
    {
        await using var f = new CacheFixture(); f.D.Options.DirectoryWatcher = new FakeWatcher();
        var directory = await Open(f.D, "dir", 3, access: 0x80, directory: true);
        Status(await f.D.Send(Notify(directory, recursive: true)), Denied, "READ_ATTRIBUTES without LIST_DIRECTORY cannot arm CHANGE_NOTIFY");
        Output(await f.D.Send(Query(directory, 4))); // failed notify does not close a valid metadata handle
    }
    static async Task NotifyDeleteDirectory(bool initial, bool secondSession)
    {
        await using var f = new CacheFixture(); var d = f.D; d.Options.DirectoryWatcher = new FakeWatcher(); var directory = await Open(d, "dir", 2, directory: true);
        var pending = await d.Send(Notify(directory)); Status(pending, 0x103, "directory notify pending before deletion");
        var s = secondSession ? Session(f) : d.Session;
        async Task<byte[]> Submit(byte[] b) => secondSession ? await Send(f, s, b) : await d.Send(b);
        var request = Create("dir", access: 0x10000, directory: true); if (initial) RawSmb.Put32(request, 104, 0x1001);
        var deleter = Id(await Submit(request)); if (!initial) Status(await Submit(Set(deleter, 13, [1])), Ok, "second open sets directory delete disposition");
        Status(await Submit(RawSmb.Close(deleter, 0, 1, 42)), Ok, "close directory delete owner");
        Status(await AsyncFinal(f.Transport, pending, 15), 0xc0000056, "deletion pending terminates outstanding directory notification");
        Status(await d.Send(Create("dir", directory: true)), 0xc0000056, "watched handle keeps deleted directory pending");
        await Close(d, directory); Status(await d.Send(Create("dir", directory: true)), Missing, "final watched handle close removes directory");
    }
    static async Task NotifySecurity(uint mask, bool sameDescriptor)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var transport = new RecordingTransport(); transport.Attach(d.Connection);
        var directory = await Open(d, "dir", 2, directory: true); var file = await Open(d, "dir\\sec_notify.txt", 2, access: 0x1f01ff);
        var descriptor = Output(await d.Send(SecurityQuery(file, 5)));
        if (!sameDescriptor) descriptor = DaclWithFallback(0, false);
        var pending = await d.Send(Notify(directory, filter: mask, recursive: true)); Status(pending, 0x103, "native security notify armed before DACL SET");
        Status(await d.Send(SecuritySet(file, descriptor)), Ok, "security update applies with ordinary WRITE_DAC handle"); await Close(d, file);
        var final = await AsyncFinal(transport, pending, 15); Status(final, Ok, "security SET produces source-compatible native notification");
        var events = RawSmb.Buffer(final, RawSmb.U16(final, 66), RawSmb.U32(final, 68)); Check.Equal(0u, RawSmb.U32(events, 0), "exactly one security-change event");
        Check.Equal(3u, RawSmb.U32(events, 4), "security event is MODIFIED"); Check.Equal("sec_notify.txt", System.Text.Encoding.Unicode.GetString(events, 12, (int)RawSmb.U32(events, 8)), "security event relative name");
    }
    static async Task NotifyMaskPolicy()
    {
        await using var f = new CacheFixture(); var d = f.D; var watcher = new FakeWatcher(); d.Options.DirectoryWatcher = watcher;
        var directory = await Open(d, "", directory: true);
        async Task Cancel(byte[] pending)
        {
            var b = RawSmb.Header(12, 4, 0, 1); RawSmb.Put16(b, 64, 4); RawSmb.Put32(b, 16, 2); RawSmb.Put64(b, 32, RawSmb.U64(pending, 32));
            await d.Send(b); Status(await AsyncFinal(f.Transport, pending, 15), 0xc0000120, "cancel a recursive/nonrecursive request without changing open's first filter");
        }
        await Cancel(await d.Send(Notify(directory, filter: 4, recursive: true))); await Cancel(await d.Send(Notify(directory, filter: 4)));
        var a = await d.Send(Notify(directory, filter: 4, recursive: true)); Status(a, 0x103, "attribute waiter after cancellation");
        watcher.Subscriptions.Single().Emit(new Smb.Server.Notification.FileNotifyEvent(Smb.Server.Notification.FileNotifyAction.Modified, "tname1"));
        Status(await AsyncFinal(f.Transport, a, 15), Ok, "original attributes subscription still delivers after cancel");
        var first = await d.Send(Notify(directory, filter: 0x47, recursive: true)); var second = await d.Send(Notify(directory, filter: 0x47));
        watcher.Subscriptions.Single().Emit(new Smb.Server.Notification.FileNotifyEvent(Smb.Server.Notification.FileNotifyAction.Modified, "subname2-r"));
        var one = await AsyncFinal(f.Transport, first, 15); Status(one, Ok, "first changed-mask request receives next original-filter event");
        watcher.Subscriptions.Single().Emit(new Smb.Server.Notification.FileNotifyEvent(Smb.Server.Notification.FileNotifyAction.Modified, "subname3-r"));
        var two = await AsyncFinal(f.Transport, second, 15); Status(two, Ok, "second changed-mask request receives subsequent event FIFO");
        foreach (var row in new[] { (one,"subname2-r"),(two,"subname3-r") })
        { var data = RawSmb.Buffer(row.Item1, RawSmb.U16(row.Item1, 66), RawSmb.U32(row.Item1, 68)); Check.Equal(row.Item2, System.Text.Encoding.Unicode.GetString(data, 12, (int)RawSmb.U32(data, 8)), "exact relative event delivered to its waiter"); }
    }
    static async Task BoundNotifyLimit()
    {
        await using var f = new CacheFixture(); var d = f.D; d.Options.DirectoryWatcher = new FakeWatcher(); d.Options.MaxOutstandingRequests = 3; d.Options.EnableMultichannel = true; d.Options.FeaturePolicy = Smb.Server.SmbFeaturePolicy.MultichannelWithCaching;
        var channel = d.Channel(); channel.Dialect = d.Connection.Dialect; channel.ClientGuid = d.Connection.ClientGuid.ToArray(); channel.ServerCapabilities = d.Connection.ServerCapabilities;
        channel.Sessions.TryAdd(1, d.Session); d.State.Connections.TryAdd(channel.ConnectionId, channel); d.Session.TryAttachChannel(new SmbChannel { Connection = channel, SigningKey = d.Session.SigningKey }); var secondary = new RecordingTransport(); secondary.Attach(channel);
        var dirs = new[] { await Open(d, "", directory: true), Id(await d.Send(Create("", directory: true), channel)) }; var channels = new[] { d.Connection, channel }; var senders = new[] { f.Transport, secondary }; var pending = new List<byte[]>[2];
        for (var lane = 0; lane < 2; lane++)
        {
            pending[lane] = [];
            for (var i = 0; i < 3; i++) { var response = await d.Send(Notify(dirs[lane]), channels[lane]); Status(response, 0x103, "each established bound channel admits its configured pending budget"); pending[lane].Add(response); }
        }
        for (var lane = 0; lane < 2; lane++)
        {
            Status(await d.Send(Notify(dirs[lane]), channels[lane]), 0xc000009a, "bound channel excess request rejected without consuming other channel budget");
            var cancel = RawSmb.Header(12, 4, 0, 1); RawSmb.Put16(cancel, 64, 4); RawSmb.Put32(cancel, 16, 2); RawSmb.Put64(cancel, 32, RawSmb.U64(pending[lane][1], 32)); await d.Send(cancel, channels[lane]);
            Status(await AsyncFinal(senders[lane], pending[lane][1], 15), 0xc0000120, "channel-local middle cancellation"); Status(await d.Send(Notify(dirs[lane]), channels[lane]), 0x103, "one channel-local slot released");
            Status(await d.Send(RawSmb.Close(dirs[lane], 0, 1, 42), channels[lane]), Ok, "close directory cleans own channel pending subscriptions");
        }
    }
}
