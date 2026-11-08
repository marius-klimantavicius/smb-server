using Smb.Auth.Ntlm;
using Smb.Protocol.Enums;
using Smb.Testing;

internal static partial class UpstreamSambaMoreTests
{
    static IEnumerable<(string Name, Func<Task> Run)> LifecycleCases()
    {
        foreach (var mode in new[] { "logoff", "previous", "invalid-reauth", "disconnect" }) yield return ($"upstream.samba.more.notify.auth-lifetime.{mode}", () => NotifyAuthLifetime(mode));
        yield return ("upstream.samba.more.notify.regular-file-invalid", NotifyRegularFile);
        foreach (var level in new byte[] { 8, 9 }) foreach (var peer in new[] { false, true })
            yield return ($"upstream.samba.more.oplock.parent-directory-rename.{level}.{peer}", () => ClassicParentRename(level, peer));
        yield return ("upstream.samba.more.oplock.exclusive-disposition-table", ClassicDispositions);
        yield return ("upstream.samba.more.oplock.share-failure-then-own-write", BatchShareWrite);
        foreach (var same in new[] { false, true }) yield return ($"upstream.samba.more.oplock.no-cache-peer-brl.{same}", () => NoCachePeerLock(same));
    }
    static async Task NotifyAuthLifetime(string mode)
    {
        await using var f = new CacheFixture(true); f.D.Options.DirectoryWatcher = new FakeWatcher(); var client = Guid.NewGuid(); var p = new NegotiatedPeer(f); await p.Login(client);
        var transport = new RecordingTransport(); transport.Attach(p.Connection);
        Id(await p.Exchange(Create("", directory: true))); var id = Id(await p.Exchange(Create("", directory: true))); var pending = await p.Exchange(Notify(id)); Status(pending, 0x103, "authenticated notify pending on second directory handle");
        if (mode == "logoff")
        { var b = RawSmb.Header(2, 4, 0, 1); RawSmb.Put16(b, 64, 4); Status(await p.Exchange(b), Ok, "signed LOGOFF closes both directory handles"); }
        else if (mode == "previous")
        { var replacement = new NegotiatedPeer(f); await replacement.Login(client, p.Session); }
        else if (mode == "invalid-reauth")
        { await p.FailedReauthentication(); }
        else
        {
            await f.D.Dispatcher.OnConnectionClosedAsync(p.Connection);
            Check.Equal(0, transport.Sends.Count(x => RawSmb.U16(x.Message, 12) == 15), "lost transport has no terminal SMB notify packet; LOCAL_DISCONNECT is a client-local status"); return;
        }
        Status(await AsyncFinal(transport, pending, 15), 0x10b, "session teardown retires admitted notify with NOTIFY_CLEANUP");
        Status(await p.Exchange(Query(id, 14)), 0xc0000203, "old session cannot use old directory after authentication lifetime ends");
    }
    static async Task NotifyRegularFile()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var id = await Open(d, disposition: 3); await Write(d, id, Payload);
        foreach (var recursive in new[] { false, true }) Status(await d.Send(Notify(id, recursive: recursive)), Invalid, "CHANGE_NOTIFY requires a directory, independent of WATCH_TREE"); await Data(d, id, Payload);
    }
    static async Task ClassicParentRename(byte level, bool peer)
    {
        await using var f = new CacheFixture(); var d = f.D; var directory = await Open(d, "dir", 3, directory: true);
        var created = await OpenOplock(f, level, "dir\\file", share: peer ? 7u : 0u); var id = Id(created); Check.Equal(level, created[66], "source cache grant before parent rename");
        if (peer) { var second = await OpenOplock(f, level, "dir\\file", disposition: 1); Check.Equal((byte)1, second[66], "second child open downgrades classic cache"); }
        var before = f.Transport.Sends.Length; Status(await Complete(f, Rename(directory, "renamed")), Denied, "source open-descendant directory rename policy");
        Check.Equal(before, f.Transport.Sends.Length, "denied parent rename does not change child caching");
        var all = Output(await d.Send(Query(id, 18))); Check.That(System.Text.Encoding.Unicode.GetString(all, 100, (int)RawSmb.U32(all, 96)).Contains("dir", StringComparison.Ordinal), "failed directory rename retains child's old path");
    }
    static async Task ClassicDispositions()
    {
        foreach (var disposition in new uint[] { 3, 4, 5, 0 })
        {
            await using var f = new CacheFixture(); var d = f.D; var first = await OpenOplock(f, 8); var owner = Id(first); await Write(d, owner, Payload);
            var second = await OpenOplock(f, 8, disposition: disposition); Id(second); Check.Equal((byte)1, second[66], "source contended exclusive disposition grants level II");
            var notice = f.Transport.Sends.Single(x => RawSmb.U16(x.Message, 12) == 18).Message; Check.Equal(disposition == 3 ? (byte)1 : (byte)0, notice[66], "OPEN_IF versus destructive overwrite/supersede downgrade target");
            await Data(d, owner, disposition == 3 ? Payload : []);
        }
    }
    static async Task BatchShareWrite()
    {
        await using var f = new CacheFixture(); var d = f.D; var response = await OpenOplock(f, 9, share: 0); var id = Id(response);
        Status(await Complete(f, Create()), Sharing, "share failure still breaks batch to level II"); var notice = f.Transport.Sends.Single(x => RawSmb.U16(x.Message, 12) == 18).Message; Check.Equal((byte)1, notice[66], "first source downgrade to level II");
        var before = f.Transport.Sends.Length; Status(await Complete(f, RawSmb.Write(id, Payload, 0, 0, 1, 42)), Ok, "owner write after rejected foreign open");
        var breaks = f.Transport.Sends.Skip(before).Where(x => RawSmb.U16(x.Message, 12) == 18).ToArray(); Check.Equal(1, breaks.Length, "exactly one later level-II self invalidation"); Check.Equal((byte)0, breaks[0].Message[66], "second target NONE");
    }
    static async Task NoCachePeerLock(bool same)
    {
        await using var f = new CacheFixture(); var d = f.D; var response = await OpenOplock(f, 9, access: 0x12019f, share: 3); var owner = Id(response);
        if (same) Id(await Complete(f, Create(access: 0x12019f, share: 3)));
        else { var session = Session(f); var transport = new RecordingTransport(); transport.Attach(session.Connection); Id(await OtherComplete(f, session, transport, Create(access: 0x12019f, share: 3))); }
        var first = f.Transport.Sends.Single(x => RawSmb.U16(x.Message, 12) == 18).Message; Check.Equal((byte)1, first[66], "ordinary noncached peer causes batch-to-II transition");
        var before = f.Transport.Sends.Length; Status(await Complete(f, Lock(owner, 0, 1, 2)), Ok, "owner BRL invalidates its remaining classic READ cache");
        Check.Equal(1, f.Transport.Sends.Skip(before).Count(x => RawSmb.U16(x.Message, 12) == 18), "noncached peer receives no spurious notification"); before = f.Transport.Sends.Length;
        Status(await Complete(f, Lock(owner, 8, 1, 2)), Ok, "second disjoint BRL succeeds"); Check.Equal(before, f.Transport.Sends.Length, "already invalidated owner receives no second cache break");
    }
}
