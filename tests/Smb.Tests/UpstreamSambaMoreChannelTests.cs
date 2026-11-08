using Smb.Protocol.Enums;
using Smb.Server;
using Smb.Server.State;
using Smb.Testing;

internal static partial class UpstreamSambaMoreTests
{
    static IEnumerable<(string Name, Func<Task> Run)> ChannelCacheCases()
    {
        foreach (var lease in new[] { false, true })
            foreach (var mode in new[] { "ack-other-channel", "primary-disconnect", "sender-failure", "foreign-client-ack" })
                yield return ($"upstream.samba.more.multichannel.cache.{lease}.{mode}", () => ChannelCache(lease, mode));
    }
    static async Task ChannelCache(bool leased, string mode)
    {
        await using var f = new CacheFixture(); var d = f.D;
        d.Options.EnableMultichannel = true; d.Options.FeaturePolicy = SmbFeaturePolicy.MultichannelWithCaching;
        var channel = d.Channel(); channel.Dialect = SmbDialect.Smb300; channel.ServerCapabilities = d.Connection.ServerCapabilities; channel.ClientGuid = d.Connection.ClientGuid.ToArray();
        channel.Sessions.TryAdd(1, d.Session); d.State.Connections.TryAdd(channel.ConnectionId, channel); d.Session.TryAttachChannel(new SmbChannel { Connection = channel, SigningKey = d.Session.SigningKey });
        var secondary = new RecordingTransport(); secondary.Attach(channel);
        var request = Create(disposition: 3); if (leased) request = Lease(request, 7); else request[67] = 9;
        var response = await d.Send(request); var owner = Id(response); Check.Equal(leased ? (byte)255 : (byte)9, response[66], "real multi-channel cache grant");
        await Write(d, owner, Payload);
        if (mode == "primary-disconnect")
        {
            await d.Dispatcher.OnConnectionClosedAsync(d.Connection);
            var alive = await d.Send(RawSmb.Read(owner, 1, 0, 0, 1, 42), channel); Status(alive, Ok, "open remains available on bound surviving channel");
        }
        if (mode == "sender-failure") f.Transport.Control.Enqueue("Send", new OperationStep(Error: new IOException("controlled lost primary break transport")));
        var peer = Session(f); peer.Connection.ClientGuid = Guid.NewGuid().ToByteArray(); var peerSender = new RecordingTransport(); peerSender.Attach(peer.Connection);
        var interim = await Send(f, peer, Create()); Status(interim, 0x103, "other client CREATE waits for cross-channel break");
        using var wait = new CancellationTokenSource(Check.Timeout);
        while (!f.Transport.Sends.Concat(secondary.Sends).Any(s => RawSmb.U16(s.Message, 12) == 18))
        {
            await Task.WhenAny(f.Transport.WaitForSendAsync(wait.Token), secondary.WaitForSendAsync(wait.Token)).WaitAsync(Check.Timeout);
        }
        await wait.CancelAsync();
        var notifications = f.Transport.Sends.Concat(secondary.Sends).Where(s => RawSmb.U16(s.Message, 12) == 18).ToArray();
        Check.That(notifications.Length >= 1, "break delivered on a live bound channel"); var notice = notifications[0].Message;
        if (mode == "primary-disconnect") Check.Equal(1, secondary.Sends.Count(s => RawSmb.U16(s.Message, 12) == 18), "surviving sender receives break after primary loss");
        var ack = leased ? LeaseAck(1, RawSmb.U32(notice, 92)) : P6Tests.Ack(owner, (OplockLevel)notice[66]);
        if (mode == "foreign-client-ack")
        {
            var rejected = await Send(f, peer, ack.ToArray()); Status(rejected, leased ? Missing : Closed, "another client/session cannot acknowledge held rights");
            Check.That(!peerSender.Sends.Any(s => RawSmb.U16(s.Message, 12) == 5), "foreign ACK cannot complete the waiting CREATE");
        }
        Status(await d.Send(ack, channel), Ok, "ACK on a bound channel is valid regardless of notification transport");
        var final = await AsyncFinal(peerSender, interim); var peerId = Id(final);
        var read = await Send(f, peer, RawSmb.Read(peerId, (uint)Payload.Length, 0, 0, 1, 42)); Status(read, Ok, "peer receives usable file after channel-safe downgrade");
        Check.That(RawSmb.Buffer(read, read[66], RawSmb.U32(read, 68)).SequenceEqual(Payload), "cache handoff preserves bytes");
        Status(await Send(f, peer, RawSmb.Close(peerId, 0, 1, 42)), Ok, "peer CLOSE");
        Status(await d.Send(RawSmb.Close(owner, 0, 1, 42), channel), Ok, "surviving channel CLOSE of original FileId");
    }
}
