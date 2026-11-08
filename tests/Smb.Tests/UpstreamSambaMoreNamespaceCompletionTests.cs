using System.Text;
using Smb.Testing;

internal static partial class UpstreamSambaMoreTests
{
    static IEnumerable<(string Name, Func<Task> Run)> NamespaceCompletionCases()
    {
        foreach (var delete in new[] { false, true }) foreach (var share in new uint[] { 0, 7 })
            yield return ($"upstream.samba.more.rename.parent-reservation.{delete}.{share}", () => ParentRename(delete, share));
        yield return ("upstream.samba.more.rename.msword-source", MswordRename);
        yield return ("upstream.samba.more.rename.three-handles-full-close", ThreeHandleClose);
        foreach (var directory in new[] { false, true }) foreach (var rename in new[] { false, true })
            yield return ($"upstream.samba.more.notify.native-remove-rename.{directory}.{rename}", () => NativeNamespaceEvent(directory, rename));
        yield return ("upstream.samba.more.notify.second-tree-roundtrip", NativeSecondTreeNotify);
        yield return ("upstream.samba.more.stream.noninheriting-parent-create", StreamUnderDescriptor);
    }
    static async Task ParentRename(bool delete, uint share)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); await Close(d, await Open(d, "dir", 3, directory: true));
        var parent = await Open(d, "dir", access: delete ? 0x1701bfu : 0x1601bfu, share: share, directory: true); var id = await Open(d, "dir\\file", 2, access: 0x17019f, share: 0); await Write(d, id, Payload);
        var expected = !delete && share == 7 ? Ok : Sharing; Status(await d.Send(Rename(id, "dir\\renamed")), expected, "source parent-directory access/share reservation policy");
        await Data(d, id, Payload); await Close(d, id); await Close(d, parent); await Data(d, await Open(d, expected == Ok ? "dir\\renamed" : "dir\\file"), Payload);
    }
    static async Task MswordRename()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); await Close(d, await Open(d, "dir", 3, directory: true));
        var request = Create("dir\\file.txt", 2, access: 0x17019f, share: 0); RawSmb.Put32(request, 104, 0x60); var file = Id(await d.Send(request)); await Write(d, file, Payload);
        request = Create("dir", access: 0x100080, share: 0, directory: true); RawSmb.Put32(request, 104, 0x800021); var parent = Id(await d.Send(request));
        Status(await d.Send(Rename(file, "dir\\newname.txt")), Ok, "stat-only parent share NONE permits source Word child rename");
        var info = Output(await d.Send(Query(file, 18))); Check.That(Encoding.Unicode.GetString(info, 100, (int)RawSmb.U32(info, 96)).EndsWith("newname.txt", StringComparison.Ordinal), "renamed handle reports new filename");
        await Data(d, file, Payload); await Close(d, file); await Close(d, parent);
    }
    static async Task ThreeHandleClose()
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); await using var a = await h.ConnectAsync(); await using var b = await h.ConnectAsync();
        var first = Id(await a.ExchangeAsync(Route(Create(disposition: 2, access: 0x81), a))); var second = Id(await b.ExchangeAsync(Route(Create(access: 0x81), b)));
        var renamer = Id(await a.ExchangeAsync(Route(Create(access: 0x10080), a))); await a.ExchangeAsync(Route(Rename(renamer, "renamed"), a)); await a.CloseAsync(renamer);
        foreach (var lane in new[] { (Client:a,Id:first),(Client:b,Id:second) })
        {
            var close = RawSmb.Close(lane.Id, 0, 1, 42); RawSmb.Put16(close, 66, 1); var response = await lane.Client.ExchangeAsync(Route(close, lane.Client));
            Check.Equal((ushort)1, RawSmb.U16(response, 66), "FULL_INFORMATION flag returned for both pre-rename opens"); Check.Equal(0x20u, RawSmb.U32(response, 120), "both original sessions report actual ARCHIVE after cross-session rename"); Check.Equal(0ul, RawSmb.U64(response, 112), "empty original object EOF survives rename");
        }
        await a.ExchangeAsync(Route(Create(), a), Missing); await a.CloseAsync(await a.CreateAsync("renamed"));
    }
    static (uint Action, string Name)[] NotifyEvents(byte[] response)
    {
        var data = Output(response); var events = new List<(uint, string)>(); var at = 0;
        while (true)
        {
            Check.That(at + 12 <= data.Length, "notify record header bounded"); var length = RawSmb.U32(data, at + 8); Check.That((length & 1) == 0 && length <= data.Length - at - 12, "notify UTF-16 name bounded");
            events.Add((RawSmb.U32(data, at + 4), Encoding.Unicode.GetString(data, at + 12, (int)length))); var next = RawSmb.U32(data, at); if (next == 0) break; Check.That(next >= 12 + length && next <= data.Length - at, "notify next offset progresses"); at += (int)next;
        }
        return events.ToArray();
    }
    static async Task NativeNamespaceEvent(bool directory, bool rename)
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); await using var watcher = await h.ConnectAsync(); await using var writer = await h.ConnectAsync();
        var opened = Id(await writer.ExchangeAsync(Route(Create("tname1", 2, directory: directory), writer))); var root = await watcher.CreateAsync("", true);
        await watcher.ExchangeAsync(Route(Notify(root, filter: directory ? 2u : 1u), watcher), 0x103);
        if (rename) await writer.ExchangeAsync(Route(Rename(opened, "tname2"), writer));
        else { await writer.ExchangeAsync(Route(Set(opened, 13, [1]), writer)); await writer.CloseAsync(opened); }
        var events = NotifyEvents(await watcher.ReceiveAsync());
        if (rename) Check.That(events.SequenceEqual(new[] { (4u,"tname1"),(5u,"tname2") }), "native rename reports ordered old/new relative names");
        else Check.That(events.SequenceEqual(new[] { (2u,"tname1") }), "native last-close deletion reports exact removed relative name");
        await watcher.CloseAsync(root);
    }
    static async Task NativeSecondTreeNotify()
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); await using var c = await h.ConnectAsync(); var root = await c.CreateAsync("", true);
        var response = await c.ExchangeAsync(RawSmb.TreeConnect("\\\\localhost\\P0", c.NextMessageId(), c.Session)); var second = RawSmb.U32(response, 36);
        foreach (var tree in new[] { c.Tree, second, c.Tree })
        {
            foreach (var remove in new[] { false, true })
            {
                await c.ExchangeAsync(Route(Notify(root, filter: 2), c), 0x103);
                byte[]? notice = null;
                async Task<byte[]> Roundtrip(byte[] packet)
                {
                    await c.SendAsync(packet);
                    while (true)
                    {
                        var reply = await c.ReceiveAsync(); if (RawSmb.U16(reply, 12) == 15) { Check.That(notice == null, "one final for pending directory change"); notice = reply; continue; }
                        Check.Equal(RawSmb.U64(packet, 24), RawSmb.U64(reply, 24), "same-channel metadata reply routed by MessageId"); Status(reply, Ok, "same-channel namespace command"); return reply;
                    }
                }
                var request = Route(Create("subdir-name", remove ? 1u : 2u, directory: true), c); RawSmb.Put32(request, 36, tree);
                var id = Id(await Roundtrip(request));
                if (remove) { request = Route(Set(id, 13, [1]), c); RawSmb.Put32(request, 36, tree); await Roundtrip(request); }
                request = RawSmb.Close(id, c.NextMessageId(), c.Session, tree); await Roundtrip(request);
                var events = NotifyEvents(notice ?? await c.ReceiveAsync()); Check.That(events.SequenceEqual(new[] { (remove ? 2u : 1u,"subdir-name") }), "second tree mutations preserve original notify subscription and exact name");
            }
            if (tree == second) await c.ExchangeAsync(RawSmb.TreeDisconnect(c.NextMessageId(), c.Session, second));
        }
        await c.CloseAsync(root);
    }
    static async Task StreamUnderDescriptor()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var parent = await Open(d, "parent", 3, access: 0x1f01ff, directory: true);
        var descriptor = Dacl(0, false); RawSmb.Put32(descriptor, 32, 0x1f01ff); Status(await d.Send(SecuritySet(parent, descriptor)), Ok, "set noninheriting basic parent descriptor"); await Close(d, parent);
        var stream = await Open(d, "parent\\implicit:stream", 3); await Write(d, stream, Payload); await Data(d, stream, Payload); await Data(d, await Open(d, "parent\\implicit"), []);
    }
}
