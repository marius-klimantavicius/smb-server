using Smb.Protocol.Enums;
using Smb.Server;
using Smb.Server.State;
using Smb.Testing;

internal static partial class UpstreamSambaMoreTests
{
    static IEnumerable<(string Name, Func<Task> Run)> ReplayCases()
    {
        foreach (var holder in new[] { "batch", "lease" })
            foreach (var contender in new[] { "none", "batch", "lease" })
                foreach (var channels in new[] { 1, 2, 4 })
                    yield return ($"upstream.samba.more.replay.pending.{holder}.{contender}.{channels}", () => PendingReplay(holder, contender, channels, "compatible"));
        foreach (var release in new[] { "close", "ack" })
            yield return ($"upstream.samba.more.replay.sharing-violation.{release}", () => PendingReplay("lease", "none", 1, release));
        foreach (var holder in new[] { "batch", "lease" })
            foreach (var contender in new[] { "none", "batch", "lease" })
                yield return ($"upstream.samba.more.replay.unsent-final.{holder}.{contender}", () => PendingReplay(holder, contender, 4, "unsent-final"));
    }
    static byte[] ReplayCreate(string kind, Guid guid, ulong key, uint share = 7)
    {
        var b = Create(disposition: 3, share: share); b[67] = kind == "batch" ? (byte)9 : (byte)0;
        var data = new byte[32]; RawSmb.Put32(data, 0, 30000); guid.ToByteArray().CopyTo(data, 16);
        b = P7cTests.Context(b, "DH2Q", data); return kind == "lease" ? Lease(b, 7, key, true) : b;
    }
    static async Task<byte[]> AsyncFinal(RecordingTransport t, byte[] interim, ushort command = 5)
    {
        var id = RawSmb.U64(interim, 32);
        while (true)
        {
            var send = t.Sends.LastOrDefault(s => RawSmb.U16(s.Message, 12) == command && (RawSmb.U32(s.Message, 16) & 2) != 0 && RawSmb.U64(s.Message, 32) == id && RawSmb.U32(s.Message, 8) != 0x103);
            if (send != null) return send.Message;
            await t.WaitForSendAsync().WaitAsync(Check.Timeout);
        }
    }
    static async Task PendingReplay(string holder, string contender, int channelCount, string mode)
    {
        await using var f = new CacheFixture(true); var d = f.D;
        if (channelCount > 1) { d.Options.EnableMultichannel = true; d.Options.FeaturePolicy = SmbFeaturePolicy.DurableWithMultichannel; }
        var ownerResponse = await d.Send(ReplayCreate(holder, Guid.NewGuid(), 1, mode is "close" or "ack" ? 0u : 7u)); var owner = Id(ownerResponse);
        var s = Session(f); s.Connection.ClientGuid = Guid.NewGuid().ToByteArray(); var connections = new List<SmbConnection> { s.Connection };
        for (var i = 1; i < channelCount; i++)
        {
            var c = d.Channel(); c.Dialect = SmbDialect.Smb300; c.ServerCapabilities = s.Connection.ServerCapabilities; c.ClientGuid = s.Connection.ClientGuid.ToArray(); c.Sessions.TryAdd(s.SessionId, s);
            d.State.Connections.TryAdd(c.ConnectionId, c); s.TryAttachChannel(new SmbChannel { Connection = c, SigningKey = s.SigningKey }); connections.Add(c);
        }
        var sender = new RecordingTransport(); sender.Attach(s.Connection); var guid = Guid.NewGuid();
        async Task<byte[]> Submit(SmbConnection c, bool replay)
        {
            var b = ReplayCreate(contender, guid, 2, mode is "close" or "ack" ? 0u : 7u); RawSmb.Put64(b, 40, 2); RawSmb.Put32(b, 36, 43);
            if (replay) RawSmb.Put32(b, 16, 0x20000000); return await d.Send(b, c);
        }
        var first = await Submit(s.Connection, false); Status(first, 0x103, "original durable CREATE parks behind cache break");
        foreach (var c in connections) Status(await Submit(c, true), 0xc0000467, "same CreateGuid replay while original is pending: FILE_NOT_AVAILABLE");
        Status(await Submit(connections[^1], true), 0xc0000467, "rejected replay does not consume or replace the pending claim");
        var notification = f.Transport.Sends.Single(send => RawSmb.U16(send.Message, 12) == 18).Message;
        Check.Equal(holder == "lease" ? (ushort)44 : (ushort)24, RawSmb.U16(notification, 64), "holder's break type");
        if (holder == "lease") Check.Equal(mode is "close" or "ack" ? 5u : 3u, RawSmb.U32(notification, 92), "share violation breaks HANDLE; compatible open breaks WRITE caching");
        else Check.Equal((byte)1, notification[66], "batch breaks to level II");
        var gate = mode == "unsent-final" ? new AsyncBarrier() : null;
        if (gate != null) sender.Control.Enqueue("Send", new OperationStep(Barrier: gate));
        try
        {
            if (mode != "ack") await Close(d, owner);
            else if (holder == "lease") Status(await d.Send(LeaseAck(1, RawSmb.U32(notification, 92))), Ok, "release pending CREATE with lease ACK");
            else Status(await d.Send(P6Tests.Ack(owner, OplockLevel.LevelII)), Ok, "release pending CREATE with oplock ACK");
            if (gate != null)
            {
                await gate.Entered.WaitAsync(Check.Timeout);
                Status(await Submit(connections[^1], true), 0xc0000467, "prepared but unsent CREATE remains unavailable to replay");
                gate.Release();
            }
            var completed = await AsyncFinal(sender, first); var expected = mode == "ack" ? Sharing : Ok;
            Status(completed, expected, "original CREATE after release");
            if (expected != Ok) { Status(await Submit(connections[^1], true), Sharing, "failed original leaves sharing conflict for a subsequent request"); return; }
            var id = Id(completed); var replayed = await Submit(connections[^1], true); Status(replayed, Ok, "completed CREATE replay");
            Check.Equal(id, Id(replayed), "completed DH2Q CREATE replay preserves FileId across channels even if caching grant was declined");
            Check.Equal(contender != "none", Context(completed, "DH2Q") != null, "durable grant eligibility follows actual contender cache state");
            if (contender != "none") Check.That(completed.AsSpan(66, 78).SequenceEqual(replayed.AsSpan(66, 78)), "replay retains action/metadata/oplock/FileId");
            Status(await Send(f, s, RawSmb.Close(id, 0, 1, 42)), Ok, "close original replayed open");
        }
        finally { gate?.Release(); }
    }
}
