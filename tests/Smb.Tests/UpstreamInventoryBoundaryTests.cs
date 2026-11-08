using System.Net;
using System.Net.Sockets;
using Smb.Auth.Ntlm;
using Smb.Testing;

internal static partial class UpstreamInventoryTests
{
    static IEnumerable<(string Name, Func<Task> Run)> BoundaryCases()
    {
        foreach (var kind in new[] { "session", "tree", "create-name", "create-context", "write", "ioctl", "directory", "query", "set" })
        {
            yield return ($"upstream.inventory.bounds.{kind}-overflow", () => BufferBoundary(kind, true, 0));
            foreach (var offset in new[] { 0, 64, -1 })
                yield return ($"upstream.inventory.bounds.{kind}-below-{offset}", () => BufferBoundary(kind, false, offset));
        }
        foreach (var kind in new[] { "create", "directory" })
            foreach (var high in new[] { false, true })
                yield return ($"upstream.inventory.names.{kind}-unpaired-{high}", () => MalformedName(kind, high));
        foreach (var length in new ushort[] { 0, 15, 17 })
            yield return ($"upstream.inventory.auth.keyexchange-length-{length}", () => InvalidKeyLength(length));
        foreach (var count in new ushort[] { 1, 3, 4 })
            foreach (var offset in new uint[] { 64, 96, 0xfffffff8 })
                yield return ($"upstream.inventory.negotiate.context-overlap-{count}-{offset}", () => NegotiateOverlap(count, offset));
        yield return ("upstream.inventory.negotiate.truncated-max-dialects", TruncatedDialects);
        yield return ("upstream.inventory.negotiate.valid-max-dialects", MaxDialects);
        yield return ("upstream.inventory.auth.type3-before-challenge", InitialType3);
        yield return ("upstream.inventory.auth.sessionless-echo-with-live-session", SessionlessEcho);
        yield return ("upstream.inventory.auth.no-version-64-byte-header", () => OptionalAuthenticateHeader(false));
        yield return ("upstream.inventory.auth.workstation-offset72-without-mic", () => OptionalAuthenticateHeader(true));
        foreach (var field in new[] { 12, 20, 28, 36, 44, 52 })
            foreach (var range in new[] { "header", "mic", "overrun", "wrap" })
                yield return ($"upstream.inventory.auth.buffer-{field}-{range}", () => AuthenticateBuffer(field, range));
    }
    static async Task BufferBoundary(string kind, bool overflow, int offset)
    {
        if (kind == "session") { await InitialSetupBoundary(overflow, offset); return; }
        await using var h = await UpstreamLocalFixture.StartAsync(); await using var c = await h.ConnectAsync();
        var id = await MetadataOpen(c, false); await c.WriteAsync(id, [42]); var directory = await MetadataOpen(c, true, "scan");
        byte[] b; int field, lengthField, lower; bool wideOffset = false, wideLength = false;
        switch (kind)
        {
            case "session": b = RawSmb.SessionSetup([1], c.NextMessageId(), c.Session); field = 76; lengthField = 78; lower = 88; break;
            case "tree": b = RawSmb.TreeConnect("\\\\localhost\\P0", c.NextMessageId(), c.Session); field = 68; lengthField = 70; lower = 72; break;
            case "create-name": b = RawSmb.Create("other", false, c.NextMessageId(), c.Session, c.Tree); field = 108; lengthField = 110; lower = 120; break;
            case "create-context": b = CreateWithContexts(c, Context("InvX", new byte[8])); field = 112; lengthField = 116; lower = 120; wideOffset = wideLength = true; break;
            case "write": b = RawSmb.Write(id, [1], 0, c.NextMessageId(), c.Session, c.Tree); field = 66; lengthField = 68; lower = 112; wideLength = true; break;
            case "ioctl": b = P5Tests.Ioctl(id, 0x00140078, [1], 24); RawSmb.Put64(b, 24, c.NextMessageId()); RawSmb.Put64(b, 40, c.Session); RawSmb.Put32(b, 36, c.Tree); field = 88; lengthField = 92; lower = 120; wideOffset = wideLength = true; break;
            case "directory": b = RawSmb.Enumerate(directory, c.NextMessageId(), c.Session, c.Tree); field = 88; lengthField = 90; lower = 96; break;
            case "query": b = Query(c, id, 4); Array.Resize(ref b, b.Length + 1); field = 72; lengthField = 76; lower = 104; wideLength = true; break;
            default: b = Set(c, id, 20, new byte[8]); field = 72; lengthField = 68; lower = 96; wideLength = true; break;
        }
        var off = overflow ? wideOffset ? 0xfffffff8u : 0xff00u : (uint)(offset == -1 ? lower - 1 : offset);
        var length = overflow ? wideLength ? uint.MaxValue : 0x100u : kind is "tree" or "create-name" or "directory" ? 2u : 1u;
        if (wideOffset) RawSmb.Put32(b, field, off); else RawSmb.Put16(b, field, (ushort)off);
        if (wideLength) RawSmb.Put32(b, lengthField, length); else RawSmb.Put16(b, lengthField, (ushort)length);
        await c.ExchangeAsync(b, Invalid);
        Check.That((await c.ReadAsync(id, 1)).SequenceEqual(new byte[] { 42 }), "invalid buffer preserves existing data and session");
        Check.That(!File.Exists(h.PathFor("other")) && !File.Exists(h.PathFor("contexts")), "malformed request does not create a name");
        await c.CloseAsync(directory); await c.CloseAsync(id);
    }
    static async Task MalformedName(string kind, bool high)
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); await using var c = await h.ConnectAsync();
        var directory = await MetadataOpen(c, true, "scan");
        var b = kind == "create" ? RawSmb.Create("xx", false, c.NextMessageId(), c.Session, c.Tree) : RawSmb.Enumerate(directory, c.NextMessageId(), c.Session, c.Tree);
        var offset = kind == "create" ? RawSmb.U16(b, 108) : RawSmb.U16(b, 88); Array.Resize(ref b, offset + 4);
        RawSmb.Put16(b, kind == "create" ? 110 : 90, 4); RawSmb.Put16(b, offset, high ? (ushort)0xd800 : (ushort)0xdc00); RawSmb.Put16(b, offset + 2, 0x78);
        await c.ExchangeAsync(b, Invalid); Check.Equal(1, Directory.GetFileSystemEntries(h.RootPath).Length, "invalid Unicode cannot materialize replacement-character filename"); await c.CloseAsync(directory);
    }
    sealed class RawPeer : IAsyncDisposable
    {
        readonly TcpClient tcp = new(); public ulong Mid;
        public async Task Connect(IPEndPoint endpoint) => await tcp.ConnectAsync(endpoint);
        public async Task<byte[]> Exchange(byte[] packet, uint? expected)
        {
            using var timeout = new CancellationTokenSource(Check.Timeout); var stream = tcp.GetStream();
            var frame = new byte[packet.Length + 4]; frame[1] = (byte)(packet.Length >> 16); frame[2] = (byte)(packet.Length >> 8); frame[3] = (byte)packet.Length; packet.CopyTo(frame, 4);
            await stream.WriteAsync(frame, timeout.Token); var prefix = new byte[4]; await stream.ReadExactlyAsync(prefix, timeout.Token);
            var length = prefix[1] << 16 | prefix[2] << 8 | prefix[3]; Check.That(length is >= 64 and <= 1024 * 1024, "bounded raw peer response"); var b = new byte[length]; await stream.ReadExactlyAsync(b, timeout.Token);
            RawSmb.Response(b, RawSmb.U16(packet, 12), RawSmb.U64(packet, 24), expected ?? RawSmb.U32(b, 8)); return b;
        }
        public ValueTask DisposeAsync() { tcp.Dispose(); return ValueTask.CompletedTask; }
    }
    static async Task InitialSetupBoundary(bool overflow, int offset)
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); await using var p = new RawPeer(); await p.Connect(h.Server.Endpoint);
        await p.Exchange(RawSmb.Negotiate(p.Mid++), 0);
        var request = RawSmb.SessionSetup([1], p.Mid++); RawSmb.Put16(request, 76, overflow ? (ushort)0xff00 : offset == -1 ? (ushort)87 : (ushort)offset);
        RawSmb.Put16(request, 78, overflow ? (ushort)0x100 : (ushort)1); await p.Exchange(request, Invalid);
        var client = new NtlmClient(HostFixture.Domain, HostFixture.User, HostFixture.Password);
        var challenge = await p.Exchange(RawSmb.SessionSetup(client.BuildNegotiate(), p.Mid++), 0xc0000016); var session = RawSmb.U64(challenge, 40);
        var token = client.BuildAuthenticate(RawSmb.Buffer(challenge, RawSmb.U16(challenge, 68), RawSmb.U16(challenge, 70))); await p.Exchange(RawSmb.SessionSetup(token, p.Mid++, session), 0);
        var echo = RawSmb.Header(13, 4, p.Mid++, session); RawSmb.Put16(echo, 64, 4); RawSmb.Sign(echo, client.ExportedSessionKey); await p.Exchange(echo, 0);
    }
    static async Task InvalidKeyLength(ushort length)
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); await using var p = new RawPeer(); await p.Connect(h.Server.Endpoint);
        await p.Exchange(RawSmb.Negotiate(p.Mid++), 0);
        var client = new NtlmClient(HostFixture.Domain, HostFixture.User, HostFixture.Password);
        var challenge = await p.Exchange(RawSmb.SessionSetup(client.BuildNegotiate(), p.Mid++), 0xc0000016); var session = RawSmb.U64(challenge, 40);
        var token = client.BuildAuthenticate(RawSmb.Buffer(challenge, RawSmb.U16(challenge, 68), RawSmb.U16(challenge, 70)));
        Check.That((RawSmb.U32(token, 60) & 0x40000000) != 0, "valid control negotiated NTLM key exchange");
        // Put a correctly bounded key buffer of the wrong size on a valid proof.
        var offset = token.Length; Array.Resize(ref token, offset + length); RawSmb.Put16(token, 52, length); RawSmb.Put16(token, 54, length); RawSmb.Put32(token, 56, (uint)offset);
        await p.Exchange(RawSmb.SessionSetup(token, p.Mid++, session), Invalid);
        // A fresh independent valid exchange on the same transport remains usable.
        client = new NtlmClient(HostFixture.Domain, HostFixture.User, HostFixture.Password); challenge = await p.Exchange(RawSmb.SessionSetup(client.BuildNegotiate(), p.Mid++), 0xc0000016); session = RawSmb.U64(challenge, 40);
        token = client.BuildAuthenticate(RawSmb.Buffer(challenge, RawSmb.U16(challenge, 68), RawSmb.U16(challenge, 70))); await p.Exchange(RawSmb.SessionSetup(token, p.Mid++, session), 0);
        var echo = RawSmb.Header(13, 4, p.Mid++, session); RawSmb.Put16(echo, 64, 4); RawSmb.Sign(echo, client.ExportedSessionKey); await p.Exchange(echo, 0);
    }
    static async Task<(ulong Session, byte[] Key)> PeerLogin(RawPeer p)
    {
        var client = new NtlmClient(HostFixture.Domain, HostFixture.User, HostFixture.Password);
        var challenge = await p.Exchange(RawSmb.SessionSetup(client.BuildNegotiate(), p.Mid++), 0xc0000016); var session = RawSmb.U64(challenge, 40);
        var token = client.BuildAuthenticate(RawSmb.Buffer(challenge, RawSmb.U16(challenge, 68), RawSmb.U16(challenge, 70))); await p.Exchange(RawSmb.SessionSetup(token, p.Mid++, session), 0);
        return (session, client.ExportedSessionKey);
    }
    static async Task SessionlessEcho()
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); await using var p = new RawPeer(); await p.Connect(h.Server.Endpoint); await p.Exchange(RawSmb.Negotiate(p.Mid++), 0);
        var session = await PeerLogin(p); var echo = RawSmb.Header(13, 4, p.Mid++, 0); RawSmb.Put16(echo, 64, 4); var response = await p.Exchange(echo, 0);
        Check.Equal(0ul, RawSmb.U64(response, 40), "sessionless ECHO response does not inherit live connection session");
        Check.Equal(0u, RawSmb.U32(response, 16) & 8, "sessionless ECHO is unsigned");
        echo = RawSmb.Header(13, 4, p.Mid++, session.Session); RawSmb.Put16(echo, 64, 4); RawSmb.Sign(echo, session.Key); await p.Exchange(echo, 0);
    }
    static async Task InitialType3()
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); await using var original = new RawPeer(); await original.Connect(h.Server.Endpoint); await original.Exchange(RawSmb.Negotiate(original.Mid++), 0);
        var client = new NtlmClient(HostFixture.Domain, HostFixture.User, HostFixture.Password);
        var challenge = await original.Exchange(RawSmb.SessionSetup(client.BuildNegotiate(), original.Mid++), 0xc0000016);
        var token = client.BuildAuthenticate(RawSmb.Buffer(challenge, RawSmb.U16(challenge, 68), RawSmb.U16(challenge, 70)));
        await using var peer = new RawPeer(); await peer.Connect(h.Server.Endpoint); await peer.Exchange(RawSmb.Negotiate(peer.Mid++), 0);
        var response = await peer.Exchange(RawSmb.SessionSetup(token, peer.Mid++), null);
        Check.That((RawSmb.U32(response, 8) & 0xc0000000) == 0xc0000000, "type3 without this transport's server challenge cannot establish a session");
        var session = await PeerLogin(peer); var echo = RawSmb.Header(13, 4, peer.Mid++, session.Session); RawSmb.Put16(echo, 64, 4); RawSmb.Sign(echo, session.Key); await peer.Exchange(echo, 0);
    }
    static async Task OptionalAuthenticateHeader(bool workstationAt72)
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); await using var p = new RawPeer(); await p.Connect(h.Server.Endpoint); await p.Exchange(RawSmb.Negotiate(p.Mid++), 0);
        var client = new NtlmClient(HostFixture.Domain, HostFixture.User, HostFixture.Password);
        var challenge = await p.Exchange(RawSmb.SessionSetup(client.BuildNegotiate(), p.Mid++), 0xc0000016); var session = RawSmb.U64(challenge, 40);
        var token = client.BuildAuthenticate(RawSmb.Buffer(challenge, RawSmb.U16(challenge, 68), RawSmb.U16(challenge, 70)));
        Check.Equal(0u, RawSmb.U32(token, 60) & 0x02000000, "control does not announce NTLM Version");
        if (workstationAt72) { RawSmb.Put16(token, 44, 4); RawSmb.Put16(token, 46, 4); RawSmb.Put32(token, 48, 72); }
        else
        {
            // Remove the builder's unannounced optional Version/MIC reservation.
            token = token[..64].Concat(token[88..]).ToArray();
            foreach (var field in new[] { 12, 20, 28, 36, 44, 52 }) if (RawSmb.U16(token, field) != 0) RawSmb.Put32(token, field + 4, RawSmb.U32(token, field + 4) - 24);
            Check.Equal(64u, RawSmb.U32(token, 16), "payload begins at the actual 64-byte mandatory header boundary");
        }
        await p.Exchange(RawSmb.SessionSetup(token, p.Mid++, session), 0);
        var echo = RawSmb.Header(13, 4, p.Mid++, session); RawSmb.Put16(echo, 64, 4); RawSmb.Sign(echo, client.ExportedSessionKey); await p.Exchange(echo, 0);
    }
    static async Task AuthenticateBuffer(int field, string range)
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); await using var p = new RawPeer(); await p.Connect(h.Server.Endpoint);
        await p.Exchange(RawSmb.Negotiate(p.Mid++), 0);
        var client = new NtlmClient(HostFixture.Domain, HostFixture.User, HostFixture.Password);
        var challenge = await p.Exchange(RawSmb.SessionSetup(client.BuildNegotiate(), p.Mid++), 0xc0000016); var session = RawSmb.U64(challenge, 40);
        var token = client.BuildAuthenticate(RawSmb.Buffer(challenge, RawSmb.U16(challenge, 68), RawSmb.U16(challenge, 70)), withMic: range == "mic");
        var offset = range switch { "header" => 10u, "mic" => 72u, "overrun" => (uint)token.Length - 1, _ => uint.MaxValue - 2 };
        RawSmb.Put16(token, field, 4); RawSmb.Put16(token, field + 2, 4); RawSmb.Put32(token, field + 4, offset);
        // Upstream AuthenticateMustReturnError requires rejection, without an
        // NTSTATUS oracle. Parse failure and proof/MIC failure are both legitimate.
        var response = await p.Exchange(RawSmb.SessionSetup(token, p.Mid++, session), null);
        Check.That((RawSmb.U32(response, 8) & 0xc0000000) == 0xc0000000, "malformed NTLM authenticate must fail, never establish a usable session");
        client = new NtlmClient(HostFixture.Domain, HostFixture.User, HostFixture.Password); challenge = await p.Exchange(RawSmb.SessionSetup(client.BuildNegotiate(), p.Mid++), 0xc0000016); session = RawSmb.U64(challenge, 40);
        token = client.BuildAuthenticate(RawSmb.Buffer(challenge, RawSmb.U16(challenge, 68), RawSmb.U16(challenge, 70))); await p.Exchange(RawSmb.SessionSetup(token, p.Mid++, session), 0);
        var echo = RawSmb.Header(13, 4, p.Mid++, session); RawSmb.Put16(echo, 64, 4); RawSmb.Sign(echo, client.ExportedSessionKey); await p.Exchange(echo, 0);
    }
    static async Task MaxDialects()
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); await using var p = new RawPeer(); await p.Connect(h.Server.Endpoint);
        var b = RawSmb.Negotiate(p.Mid++); Array.Resize(ref b, 100 + 2 * ushort.MaxValue); RawSmb.Put16(b, 66, ushort.MaxValue); RawSmb.Put16(b, b.Length - 2, 0x302);
        var response = await p.Exchange(b, 0); Check.Equal((ushort)0x302, RawSmb.U16(response, 68), "maximum declared dialect array includes last offered supported dialect");
        Check.That(RawSmb.U16(response, 120) >= 128 && RawSmb.U16(response, 122) > 0, "NEGOTIATE security buffer follows fixed fields");
        _ = RawSmb.Buffer(response, RawSmb.U16(response, 120), RawSmb.U16(response, 122));
    }
    static async Task NegotiateOverlap(ushort count, uint offset)
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); await using var p = new RawPeer(); await p.Connect(h.Server.Endpoint);
        var b = RawSmb.Negotiate(p.Mid++); Array.Resize(ref b, 192); RawSmb.Put16(b, 66, count);
        for (var i = 0; i < count; i++) RawSmb.Put16(b, 100 + i * 2, i + 1 == count ? (ushort)0x311 : (ushort)0x202);
        RawSmb.Put32(b, 92, offset); RawSmb.Put16(b, 96, 1); await p.Exchange(b, Invalid);
    }
    static async Task TruncatedDialects()
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); await using var p = new RawPeer(); await p.Connect(h.Server.Endpoint);
        var b = RawSmb.Negotiate(p.Mid++); Array.Resize(ref b, 100 + 2 * ushort.MaxValue - 1); RawSmb.Put16(b, 66, ushort.MaxValue);
        await p.Exchange(b, Invalid);
    }
}
