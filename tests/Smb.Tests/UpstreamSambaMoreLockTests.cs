using Smb.Protocol.Enums;
using Smb.Server;
using Smb.Server.State;
using Smb.Testing;

internal static partial class UpstreamSambaMoreTests
{
    static IEnumerable<(string Name, Func<Task> Run)> LockReplayCases()
    {
        foreach (var durable in new[] { false, true })
        {
            foreach (var shape in new[] { "same", "changed-payload", "next", "bucket-zero", "bucket-65", "failure-not-cached", "unlock" })
                yield return ($"upstream.samba.more.lock.sequence.{durable}.{shape}", () => WireLockSequence(durable, shape));
            yield return ($"upstream.samba.more.lock.sequence-wrap.{durable}", () => LockSequenceWrap(durable));
        }
    }
    static async Task WireLockSequence(bool durable, string shape)
    {
        await using var f = new CacheFixture(durable); var d = f.D;
        if (!durable)
        {
            d.Options.FeaturePolicy = SmbFeaturePolicy.MultichannelWithCaching; d.Options.EnableMultichannel = true; d.Connection.ServerCapabilities |= Smb2Capabilities.MultiChannel;
        }
        var request = durable ? DurableRequest(true, Guid.Empty, "lock-batch") : Create(disposition: 3); request[67] = 9;
        var response = await d.Send(request); var owner = Id(response); Check.Equal((byte)9, response[66], "real batch CREATE for LOCK sequence eligibility"); f.Oplocks[owner] = 9;
        if (durable) Check.That(Context(response, "DHnQ") != null, "real v1 durable grant rather than private eligibility flags");
        var channel = d.Connection;
        if (!durable)
        {
            channel = d.Channel(); channel.Dialect = SmbDialect.Smb300; channel.ServerCapabilities = d.Connection.ServerCapabilities; channel.ClientGuid = d.Connection.ClientGuid.ToArray();
            channel.Sessions.TryAdd(1, d.Session); d.State.Connections.TryAdd(channel.ConnectionId, channel); d.Session.TryAttachChannel(new SmbChannel { Connection = channel, SigningKey = d.Session.SigningKey });
        }
        var peer = Id(await Complete(f, Create(access: 3)));
        async Task<byte[]> Sequenced(uint sequence, uint flags, ulong offset = 0, bool replay = false)
        {
            var b = Lock(owner, offset, 4, flags); RawSmb.Put32(b, 68, sequence); if (replay) RawSmb.Put32(b, 16, 0x20000000);
            return await d.Send(b, channel);
        }
        if (shape == "failure-not-cached")
        {
            Status(await d.Send(Lock(peer, 0, 4)), Ok, "peer blocks range before failed replayable acquisition");
            Status(await Sequenced(0x11, 18), 0xc0000055, "failed LOCK is not a successful cached sequence");
            Status(await d.Send(Lock(peer, 0, 4, 4)), Ok, "release blocker before same-sequence retry");
        }
        if (shape is "next" or "bucket-zero" or "bucket-65")
        {
            var firstSequence = shape == "bucket-zero" ? 1u : shape == "bucket-65" ? 1041u : 0x11u;
            Status(await Sequenced(firstSequence, 17), Ok, "first legal shared acquisition");
            Status(await Sequenced(shape == "next" ? 0x12u : firstSequence, 17, replay: true), Ok, "changed sequence or invalid bucket processes ordinary shared acquisition");
            Status(await Sequenced(shape == "next" ? 0x13u : firstSequence, 4), Ok, "unlock removes one shared grant");
            Status(await d.Send(Lock(peer, 0, 4)), 0xc0000055, "second shared grant still blocks exclusive peer");
            Status(await Sequenced(shape == "next" ? 0x14u : firstSequence, 4), Ok, "second unlock removes the remaining shared grant");
            Status(await d.Send(Lock(peer, 0, 4)), Ok, "range becomes available after exact multiplicity release"); return;
        }
        Status(await Sequenced(0x11, 18), Ok, "first replayable exclusive acquisition");
        if (shape == "unlock")
        {
            Status(await Sequenced(0x12, 4), Ok, "first unlock"); Status(await d.Send(Lock(peer, 0, 4)), Ok, "peer can acquire released range");
            Status(await Sequenced(0x12, 4, replay: true), Ok, "same successful unlock sequence returns cached success");
            Status(await d.Send(RawSmb.Write(owner, [1], 0, 0, 1, 42)), 0xc0000054, "replayed unlock cannot remove peer ownership"); return;
        }
        Status(await Sequenced(0x11, 18, shape == "changed-payload" ? 8ul : 0ul, true), Ok, "same LockSequence returns cached success independent of repeated packet payload");
        Status(await d.Send(Lock(peer, 0, 4)), 0xc0000055, "original exclusive grant remains");
        if (shape == "changed-payload") { Status(await d.Send(Lock(peer, 8, 4)), Ok, "replayed changed range was never newly acquired"); Status(await d.Send(Lock(peer, 8, 4, 4)), Ok, "release probe range"); }
        Status(await Sequenced(0x12, 4), Ok, "single owner unlock releases exactly one grant"); Status(await d.Send(Lock(peer, 0, 4)), Ok, "no duplicate exclusive grant remains");
    }
    static async Task LockSequenceWrap(bool durable)
    {
        await using var f = new CacheFixture(durable); var d = f.D;
        if (!durable) { d.Options.FeaturePolicy = SmbFeaturePolicy.MultichannelWithCaching; d.Options.EnableMultichannel = true; d.Connection.ServerCapabilities |= Smb2Capabilities.MultiChannel; }
        var request = durable ? DurableRequest(true, Guid.NewGuid(), "lock-batch") : Create(disposition: 3); var response = await d.Send(request); var owner = Id(response); f.Oplocks[owner] = response[66];
        var peer = Id(await Complete(f, Create()));
        foreach (var index in new uint[] { 1, 64 })
        {
            async Task<byte[]> SendLock(uint nibble, uint flags, bool replay = false)
            { var b = Lock(owner, 0, 4, flags); RawSmb.Put32(b, 68, index * 16 + nibble); if (replay) RawSmb.Put32(b, 16, 0x20000000); return await d.Send(b); }
            Status(await SendLock(15, 18), Ok, "highest sequence nibble acquires exact range"); Status(await SendLock(15, 18, true), Ok, "same last nibble is replay, not duplicate acquisition");
            Status(await SendLock(0, 4), Ok, "nibble wraps from fifteen to zero and processes unlock"); Status(await SendLock(0, 4, true), Ok, "wrapped successful unlock is cached");
            Status(await d.Send(Lock(peer, 0, 4)), Ok, "first and last valid buckets leave no duplicate lock after wrap"); Status(await d.Send(Lock(peer, 0, 4, 4)), Ok, "release independent peer probe");
        }
    }
}
