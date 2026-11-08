using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Smb.Auth.Ntlm;
using Smb.Crypto;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server;
using Smb.Server.Multichannel;
using Smb.Server.State;
using Smb.Testing;

// Independent public-wire partitions for MS-SMB2 3.3.5.15, 3.3.4.1.1 and
// 3.2.5.1.3. Auth/CMAC primitives are existing fixture helpers, not new crypto oracles.
internal static class UpstreamFinalProtocolTests
{
    const uint Ok = 0, Invalid = 0xc000000d, Closed = 0xc0000128, Unsupported = 0xc00000bb,
        More = 0xc0000016, Logon = 0xc000006d, Deleted = 0xc0000203;
    static readonly (ulong P, ulong V) Sentinel = (ulong.MaxValue, ulong.MaxValue);
    public static IEnumerable<(string Name, Func<Task> Run)> Cases()
    {
        yield return ("upstream.final-protocol.ioctl.compound-missing-open", CompoundMissingOpen);
        yield return ("upstream.final-protocol.ioctl.file-flags-and-open", FileControls);
        foreach (var code in new uint[] { 0x60194, 0x601b0, 0x1401fc, 0x140204, 0x110018 })
            yield return ($"upstream.final-protocol.ioctl.server-sentinel.{code:x}", () => ServerSentinel(code));
        yield return ("upstream.final-protocol.ioctl.network-profile-and-buffer", NetworkProfile);
        foreach (var dialect in new ushort[] { 0x202, 0x210, 0x300, 0x302, 0x311 })
            yield return ($"upstream.final-protocol.auth.failed-reauth-tcp.{dialect:x}", () => FailedReauth(dialect, false));
        foreach (var dialect in new ushort[] { 0x300, 0x302 })
            yield return ($"upstream.final-protocol.auth.failed-reauth-bound-tcp.{dialect:x}", () => FailedReauth(dialect, true));
        yield return ("upstream.final-protocol.auth.invalid-signature-preserves-session", InvalidSignature);
        yield return ("upstream.final-protocol.auth.initial-failure-has-no-key", InitialFailure);
    }
    static void Status(byte[] b, uint expected, string why) => Check.Equal(expected, RawSmb.U32(b, 8), why);
    static void Signature(byte[] b, byte[] key, ushort dialect)
    {
        Check.That((RawSmb.U32(b, 16) & 8) != 0, $"terminal/challenge signature present for status 0x{RawSmb.U32(b, 8):x8}");
        var copy = b.ToArray(); copy.AsSpan(48, 16).Clear();
        var expected = dialect < 0x300 ? HMACSHA256.HashData(key, copy)[..16] : AesCmac.Compute(key, copy);
        Check.That(expected.SequenceEqual(b.AsSpan(48, 16).ToArray()), "response verifies with original established session/channel key");
    }
    static async Task CompoundMissingOpen()
    {
        await using var h = new HostFixture(); await h.StartAsync(); await using var p = new Peer(); await p.Login(h, 0x202);
        // Sequential, granted message IDs, separately signed components and no injected credit ledger.
        var first = P5Tests.Ioctl(Sentinel, 0x900c0, [], 64); p.Route(first); RawSmb.Put32(first, 20, (uint)first.Length); p.Sign(first);
        var last = RawSmb.Close(Sentinel, p.Next(), ulong.MaxValue, uint.MaxValue); RawSmb.Put32(last, 16, 4); p.Sign(last);
        await p.Send(first.Concat(last).ToArray()); var response = await p.Receive();
        var offset = (int)RawSmb.U32(response, 20); Check.That(offset >= 64 && offset < response.Length, "two compound responses");
        var a = response[..offset]; var b = response[offset..];
        Status(a, Closed, "ordinary sentinel IOCTL without open is FILE_CLOSED");
        Status(b, Closed, "dependent CLOSE propagates missing-open status");
        Check.Equal((ushort)11, RawSmb.U16(a, 12), "first command IOCTL"); Check.Equal((ushort)6, RawSmb.U16(b, 12), "second command CLOSE");
        Check.Equal(0u, RawSmb.U32(b, 20), "exact compound vector end"); Signature(a, p.SessionKey, 0x202); Signature(b, p.SessionKey, 0x202);
    }
    static async Task FileControls()
    {
        await using var d = new P2Tests.Direct(); var live = await d.Open();
        foreach (var id in new[] { Sentinel, (0UL, 0UL), (9UL, 19UL) })
            Status(await d.Send(P5Tests.Ioctl(id, 0x900c0, [], 1)), Closed, "ordinary control must locate open before unsupported-control handling");
        foreach (var id in new[] { Sentinel, live }) foreach (var flags in new uint[] { 0, 2, 3 })
        {
            var b = P5Tests.Ioctl(id, 0x900c0, [], 1); RawSmb.Put32(b, 112, flags);
            Status(await d.Send(b), Unsupported, "non-FSCTL flags rejected before missing-open lookup");
        }
        var malformed = P5Tests.Ioctl(Sentinel, 0x900c0, [], 1); RawSmb.Put16(malformed, 64, 56);
        Status(await d.Send(malformed), Invalid, "malformed fixed structure is not an ordinary missing-open request");
        Status(await d.Send(RawSmb.Close(live, 0, 1, 42)), Ok, "rejected controls preserve usable open");
        Check.Equal(0, d.Store.Control.Count("Write"), "rejected controls do not mutate backend");
    }
    sealed class NicProvider : INetworkInterfaceProvider
    {
        public IReadOnlyList<NetworkInterfaceInfo> GetInterfaces() => [new NetworkInterfaceInfo(7, 0, 1000000000, IPAddress.Loopback)];
    }
    static async Task ServerSentinel(uint code)
    {
        await using var d = new P2Tests.Direct(); d.Connection.Dialect = SmbDialect.Smb300;
        d.Options.FeaturePolicy = SmbFeaturePolicy.MultichannelOnly; d.Options.EnableMultichannel = true; d.Options.NetworkInterfaceProvider = new NicProvider();
        var live = await d.Open();
        d.Session.TreeConnects.TryAdd(44, new SmbTreeConnect { TreeId = 44, Session = d.Session, Share = d.Tree.Share, MaximalAccess = 0 }); d.Options.Metrics.OnTreeConnected();
        foreach (var tree in new uint[] { 42, 44 }) foreach (var max in new uint[] { 1, 65535 })
            foreach (var id in new[] { (0UL, 0UL), (ulong.MaxValue, 0UL), (0UL, ulong.MaxValue), live })
            {
                var b = P5Tests.Ioctl(id, code, [], max); RawSmb.Put32(b, 36, tree);
                Status(await d.Send(b), Invalid, $"server control {code:x} rejects non-sentinel before buffer, input parser, open/tree ownership and profile work");
            }
        Check.Equal(0, d.Store.Control.Count("Write"), "invalid server controls do not mutate backend");
        Status(await d.Send(RawSmb.Close(live, 0, 1, 42)), Ok, "invalid server control cannot consume file open");
    }
    static async Task NetworkProfile()
    {
        await using var d = new P2Tests.Direct(); d.Connection.Dialect = SmbDialect.Smb300; d.Options.NetworkInterfaceProvider = new NicProvider();
        Status(await d.Send(P5Tests.Ioctl(Sentinel, 0x1401fc, [], 65535)), Unsupported, "restricted profile remains restricted");
        Status(await d.Send(P5Tests.Ioctl((0, 0), 0x1401fc, [], 1)), Invalid, "invalid server FileId precedes profile rejection");
        d.Options.FeaturePolicy = SmbFeaturePolicy.MultichannelOnly; d.Options.EnableMultichannel = true;
        foreach (var max in new uint[] { 1, 65535 })
        {
            var response = await d.Send(P5Tests.Ioctl(Sentinel, 0x1401fc, [], max));
            Status(response, max == 1 ? 0xc0000023u : Ok, "valid sentinel retains output size policy");
            if (max > 1) Check.That(RawSmb.U32(response, 100) <= max && RawSmb.U32(response, 100) > 0, "network response is nonempty and bounded");
        }
    }
    static byte[] Notify((ulong P, ulong V) id)
    {
        var b = RawSmb.Header(15, 32, 0); RawSmb.Put16(b, 64, 32); RawSmb.Put32(b, 68, 4096);
        RawSmb.Put64(b, 72, id.P); RawSmb.Put64(b, 80, id.V); RawSmb.Put32(b, 88, 1); return b;
    }
    static async Task FailedReauth(ushort dialect, bool bound)
    {
        await using var h = new HostFixture();
        if (bound) { h.Server.State.Options.FeaturePolicy = SmbFeaturePolicy.MultichannelOnly; h.Server.State.Options.EnableMultichannel = true; }
        await h.StartAsync(); await using var primary = new Peer(); await primary.Login(h, dialect);
        await using var other = new Peer(); await other.Login(h, dialect); var otherFile = await other.Open("other-session");
        await using var channel = new Peer(); if (bound) await channel.Bind(h, primary);
        var p = bound ? channel : primary;
        if (bound) Check.That(!p.ChannelKey.SequenceEqual(p.SessionKey), "binding establishes distinct channel key");
        var id = await p.Open("", true); var pending = await p.Exchange(Notify(id), 0x103);
        var ntlm = new NtlmClient(HostFixture.Domain, "unknown-user", "incorrect-password");
        var challenge = await p.Exchange(RawSmb.SessionSetup(ntlm.BuildNegotiate(), 0, p.Session), More, sessionSetup: true);
        Signature(challenge, p.SessionKey, dialect);
        var request = RawSmb.SessionSetup(ntlm.BuildAuthenticate(RawSmb.Buffer(challenge, RawSmb.U16(challenge, 68), RawSmb.U16(challenge, 70))), 0, p.Session);
        // Notify cleanup may precede SESSION_SETUP in the transport. Match both responses by MessageId.
        p.Route(request, true); p.Sign(request); await p.Send(request);
        byte[]? failure = null, cleanup = null;
        for (var n = 0; n < 2; n++)
        {
            var b = await p.Receive();
            if (RawSmb.U64(b, 24) == RawSmb.U64(request, 24)) failure = b;
            else if (RawSmb.U64(b, 24) == RawSmb.U64(pending, 24)) cleanup = b;
            else throw new InvalidOperationException("unrelated terminal response during reauthentication");
        }
        Check.That(failure != null && cleanup != null, "one terminal authentication and one notify cleanup response");
        Status(failure!, Logon, "validly signed failed authentication reports LOGON_FAILURE"); Signature(failure!, p.SessionKey, dialect);
        Status(cleanup!, 0x10b, "failed session retires pending notify with NOTIFY_CLEANUP"); Signature(cleanup!, p.ChannelKey, dialect);
        Check.Equal(RawSmb.U64(pending, 32), RawSmb.U64(cleanup!, 32), "notify AsyncId preserved");
        await p.Exchange(RawSmb.Close(id, 0, p.Session, p.Tree), Deleted);
        if (bound) await primary.Exchange(RawSmb.Close(id, 0, primary.Session, primary.Tree), Deleted);
        var write = await other.Exchange(RawSmb.Write(otherFile, [7, 11, 19], 0, 0, other.Session, other.Tree)); Signature(write, other.ChannelKey, dialect);
        var read = await other.Exchange(RawSmb.Read(otherFile, 3, 0, 0, other.Session, other.Tree));
        Check.That(RawSmb.Buffer(read, read[66], RawSmb.U32(read, 68)).SequenceEqual(new byte[] { 7, 11, 19 }), "unrelated session retains exact usable file data");
        Check.Equal(0, h.Watcher.ActiveCount, "failed session leaves no active watch");
        Check.Equal(1, h.Store.ActiveHandles, "only unrelated session handle survives failed reauthentication");
    }
    static async Task InvalidSignature()
    {
        await using var h = new HostFixture(); await h.StartAsync(); await using var p = new Peer(); await p.Login(h, 0x300);
        var id = await p.Open("still-live"); var request = RawSmb.SessionSetup(new NtlmClient(HostFixture.Domain, "unknown-user", "bad").BuildNegotiate(), 0, p.Session);
        p.Route(request, true); p.Sign(request); request[48] ^= 1; await p.Send(request);
        var denied = await p.Receive(); Status(denied, 0xc0000022, "invalid request signature rejected before auth"); Signature(denied, p.SessionKey, 0x300);
        await p.Exchange(RawSmb.Close(id, 0, p.Session, p.Tree));
    }
    static async Task InitialFailure()
    {
        await using var h = new HostFixture(); await h.StartAsync(); await using var p = new Peer(); await p.Negotiate(h, 0x300);
        var ntlm = new NtlmClient(HostFixture.Domain, "unknown-user", "bad");
        var challenge = await p.Exchange(RawSmb.SessionSetup(ntlm.BuildNegotiate(), 0), More, sessionSetup: true);
        Check.Equal(0u, RawSmb.U32(challenge, 16) & 8, "initial challenge has no established signing key");
        p.Session = RawSmb.U64(challenge, 40);
        var failure = await p.Exchange(RawSmb.SessionSetup(ntlm.BuildAuthenticate(RawSmb.Buffer(challenge, RawSmb.U16(challenge, 68), RawSmb.U16(challenge, 70))), 0, p.Session), Logon, sessionSetup: true);
        Check.Equal(0u, RawSmb.U32(failure, 16) & 8, "initial failed authentication cannot invent a signing key");
        Check.That(failure.AsSpan(48, 16).SequenceEqual(new byte[16]), "initial failure signature zero");
    }
    sealed class Peer : IAsyncDisposable
    {
        readonly TcpClient client = new(); readonly PreauthIntegrityHash preauth = new(); ulong mid;
        public ulong Session; public uint Tree; public ushort Dialect; public byte[] SessionKey = [], ChannelKey = [];
        public ulong Next() => mid++;
        public void Route(byte[] b, bool sessionSetup = false)
        { RawSmb.Put64(b, 24, Next()); RawSmb.Put64(b, 40, Session); if (!sessionSetup) RawSmb.Put32(b, 36, Tree); }
        public void Sign(byte[] b)
        {
            if (ChannelKey.Length == 0) return;
            RawSmb.Put32(b, 16, RawSmb.U32(b, 16) | 8); b.AsSpan(48, 16).Clear();
            (Dialect < 0x300 ? HMACSHA256.HashData(ChannelKey, b)[..16] : AesCmac.Compute(ChannelKey, b)).CopyTo(b, 48);
        }
        public async Task Send(byte[] b)
        {
            using var timeout = new CancellationTokenSource(Check.Timeout); var frame = new byte[4 + b.Length];
            frame[1] = (byte)(b.Length >> 16); frame[2] = (byte)(b.Length >> 8); frame[3] = (byte)b.Length; b.CopyTo(frame, 4);
            await client.GetStream().WriteAsync(frame, timeout.Token);
        }
        public async Task<byte[]> Receive()
        {
            using var timeout = new CancellationTokenSource(Check.Timeout); var prefix = new byte[4]; await client.GetStream().ReadExactlyAsync(prefix, timeout.Token);
            Check.Equal((byte)0, prefix[0], "direct TCP framing"); var length = prefix[1] << 16 | prefix[2] << 8 | prefix[3];
            Check.That(length is >= 64 and <= 1048576, "bounded TCP response"); var b = new byte[length]; await client.GetStream().ReadExactlyAsync(b, timeout.Token); return b;
        }
        public async Task<byte[]> Exchange(byte[] b, uint status = Ok, bool sessionSetup = false)
        {
            Route(b, sessionSetup); Sign(b); await Send(b); var response = await Receive();
            Check.Equal(RawSmb.U64(b, 24), RawSmb.U64(response, 24), "response MessageId");
            Check.Equal(RawSmb.U16(b, 12), RawSmb.U16(response, 12), "response command"); Status(response, status, "TCP response status"); return response;
        }
        public async Task Negotiate(HostFixture h, ushort dialect)
        {
            using var timeout = new CancellationTokenSource(Check.Timeout); await client.ConnectAsync(h.Server.Endpoint, timeout.Token); Dialect = dialect;
            var b = RawSmb.Negotiate(); RawSmb.Put16(b, 100, dialect); RawSmb.Put32(b, 72, 8);
            if (dialect == 0x311)
            {
                Array.Resize(ref b, 132); RawSmb.Put32(b, 92, 104); RawSmb.Put16(b, 96, 2);
                RawSmb.Put16(b, 104, 1); RawSmb.Put16(b, 106, 6); RawSmb.Put16(b, 112, 1); RawSmb.Put16(b, 116, 1);
                RawSmb.Put16(b, 120, 8); RawSmb.Put16(b, 122, 4); RawSmb.Put16(b, 128, 1); RawSmb.Put16(b, 130, 1);
            }
            var response = await Exchange(b); Check.Equal(dialect, RawSmb.U16(response, 68), "actual negotiated dialect");
            Check.That((RawSmb.U16(response, 66) & 2) != 0, "required signing retained");
            if (dialect == 0x311) { preauth.Append(b); preauth.Append(response); }
        }
        byte[] Key(NtlmClient ntlm) => Dialect < 0x300 ? ntlm.ExportedSessionKey :
            Smb3KeyDerivation.Derive((SmbDialect)Dialect, SmbCipherId.None, ntlm.ExportedSessionKey, ntlm.ExportedSessionKey, preauth.Value).SigningKey;
        public async Task Login(HostFixture h, ushort dialect)
        {
            await Negotiate(h, dialect); var ntlm = new NtlmClient(HostFixture.Domain, HostFixture.User, HostFixture.Password);
            var b = RawSmb.SessionSetup(ntlm.BuildNegotiate(), 0); var challenge = await Exchange(b, More, true); Session = RawSmb.U64(challenge, 40);
            if (dialect == 0x311) { preauth.Append(b); preauth.Append(challenge); }
            b = RawSmb.SessionSetup(ntlm.BuildAuthenticate(RawSmb.Buffer(challenge, RawSmb.U16(challenge, 68), RawSmb.U16(challenge, 70))), 0, Session);
            var success = await Exchange(b, sessionSetup: true); if (dialect == 0x311) preauth.Append(b);
            SessionKey = ChannelKey = Key(ntlm); Signature(success, SessionKey, dialect);
            var tree = await Exchange(RawSmb.TreeConnect("\\\\localhost\\P0", 0, Session)); Tree = RawSmb.U32(tree, 36); Signature(tree, ChannelKey, dialect);
        }
        public async Task Bind(HostFixture h, Peer primary)
        {
            await Negotiate(h, primary.Dialect); Session = primary.Session; Tree = primary.Tree; SessionKey = primary.SessionKey; ChannelKey = SessionKey;
            var ntlm = new NtlmClient(HostFixture.Domain, HostFixture.User, HostFixture.Password);
            var b = RawSmb.SessionSetup(ntlm.BuildNegotiate(), 0, Session); b[66] = 1; var challenge = await Exchange(b, More, true); Signature(challenge, SessionKey, Dialect);
            b = RawSmb.SessionSetup(ntlm.BuildAuthenticate(RawSmb.Buffer(challenge, RawSmb.U16(challenge, 68), RawSmb.U16(challenge, 70))), 0, Session); b[66] = 1;
            var success = await Exchange(b, sessionSetup: true); ChannelKey = Key(ntlm); Signature(success, ChannelKey, Dialect);
        }
        public async Task<(ulong P, ulong V)> Open(string name, bool directory = false)
        {
            var b = await Exchange(RawSmb.Create(name, directory, 0, Session, Tree)); Signature(b, ChannelKey, Dialect);
            return (RawSmb.U64(b, 128), RawSmb.U64(b, 136));
        }
        public ValueTask DisposeAsync() { client.Dispose(); return ValueTask.CompletedTask; }
    }
}
