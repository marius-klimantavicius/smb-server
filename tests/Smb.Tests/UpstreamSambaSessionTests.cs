using System.Security.Cryptography;
using Smb.Auth.Ntlm;
using Smb.Testing;
using Smb.Server;
using Smb.Server.State;
using Smb.Crypto;
using System.Net.Sockets;
using Smb.Protocol.Enums;

internal static partial class UpstreamSambaTests
{
    static IEnumerable<(string Name, Func<Task> Run)> SessionCases()
    {
        foreach (var alg in new ushort[] { 0, 1, 2 })
            yield return ($"upstream.samba.session.sign-notify-cancel.{alg}", () => SignedNotify(alg, 0));
        foreach (var cipher in new ushort[] { 1, 2, 3, 4 })
            yield return ($"upstream.samba.session.encrypt-notify-cancel.{cipher}", () => SignedNotify(1, cipher));
        foreach (var kind in new[] { "collision-no-option", "collision-directory", "file-as-directory", "os2-name" })
            yield return ($"upstream.samba.session.smb3error.{kind}", () => SourceError(kind));
        yield return ("upstream.samba.session.bind-shutdown-exact-status", BindingShutdown);
        foreach (var mode in new[] { "invalid-auth", "different-user" })
            yield return ($"upstream.samba.session.bind-auth.{mode}", () => BindingIdentity(mode));
        yield return ("upstream.samba.session.reconnect-cached-source", CachedReconnect);
        yield return ("upstream.samba.session.previous-different-user", ForeignPrevious);
        yield return ("upstream.samba.session.reauth-self-previous", SelfPrevious);
        foreach (var dialect in new ushort[] { 0x300, 0x302 })
            yield return ($"upstream.samba.session.bind2.{dialect:x}", () => TwoSessionBinding(dialect));
        yield return ("upstream.samba.session.netapp-malformed-ntlmv2", NetappBlob);
        yield return ("upstream.samba.session.connect-source-workflow", SourceConnect);
        yield return ("upstream.samba.session.tcon-source-workflow", SourceTcon);
        foreach (var dialect in new ushort[] { 0x300, 0x302 })
            yield return ($"upstream.samba.session.bind1.{dialect:x}", () => SourceBind(dialect));
        foreach (var row in new[] { (A: (ushort)0x202, B: (ushort)0x202, Status: 0xc00000d0u), (A: (ushort)0x210, B: (ushort)0x210, Status: 0xc00000d0u), (A: (ushort)0x210, B: (ushort)0x300, Status: Invalid), (A: (ushort)0x300, B: (ushort)0x210, Status: 0xc00000d0u) })
            foreach (var same in new[] { true, false })
                yield return ($"upstream.samba.session.bind-negative.{row.A:x}-{row.B:x}.{same}", () => SourceBindNegative(row.A, row.B, same, row.Status));
        foreach (var mode in new[] { "valid", "bad-mic", "short-mic", "empty-without-sign" })
            yield return ($"upstream.samba.auth.spnego-mech-list.{mode}", () => MechanismListMic(mode));
        foreach (var flags in new uint[] { 0x00088205, 0xe0088205, 0xe0088215, 0xe0088225, 0xe0088235, 0x00000205, 0xe208b2b7 })
            yield return ($"upstream.samba.auth.flags.{flags:x8}", () => NegotiatedFlags(flags));
        foreach (var shape in new[] { "short", "short-fields", "version-short", "wrong-type", "bad-domain", "bad-workstation", "no-unicode" })
            yield return ($"upstream.samba.auth.negotiate.{shape}", () => BadNegotiate(shape));
        foreach (var length in new[] { 0, 1, 15, 17 })
            yield return ($"upstream.samba.auth.exported-key.length-{length}", () => BadExportedKey(length));
        yield return ("upstream.samba.session.query-invalid-session-id", InvalidSessionQuery);
        yield return ("upstream.samba.session.reauth-twice-query-position", ReauthTwice);
        yield return ("upstream.samba.session.reauth-failure-retires-only-target", ReauthFailure);
        yield return ("upstream.samba.session.reconnect-same-transport", ReconnectSameTransport);
        yield return ("upstream.samba.session.reconnect-failure-preserves-old", ReconnectFailure);
        yield return ("upstream.samba.session.reconnect-unknown-previous", UnknownPrevious);
    }
    static async Task NegotiatedFlags(uint flags)
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); using var p = new AuthPeer(); await p.Connect(h.Server.Endpoint);
        var token = new NtlmClient(HostFixture.Domain, HostFixture.User, HostFixture.Password).BuildNegotiate();
        if ((flags & 0x02000000) != 0) Array.Resize(ref token, 40);
        RawSmb.Put32(token, 12, flags);
        var b = await p.Exchange(RawSmb.SessionSetup(token, 0), route: false); Status(b, 0xc0000016, "valid NEGOTIATE gets challenge");
        var c = RawSmb.Buffer(b, RawSmb.U16(b, 68), RawSmb.U16(b, 70)); var actual = RawSmb.U32(c, 20);
        // MS-NLMP 2.2.2.5 / 3.2.5.1.1: supported requested flags,
        // Unicode preference, ESS excludes LM_KEY; 56/128 require SIGN/SEAL.
        var expected = 0x00818205u | (flags & 0x40080030);
        if ((flags & 0x30) != 0) expected |= flags & 0xa0000000;
        Check.Equal(expected, actual, "independent supported negotiation mask, without unsolicited or reserved flags");
    }
    static async Task BadNegotiate(string shape)
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); using var p = new AuthPeer(); await p.Connect(h.Server.Endpoint);
        var token = new NtlmClient(HostFixture.Domain, HostFixture.User, HostFixture.Password).BuildNegotiate();
        switch (shape)
        {
            case "short": token = token[..12]; break;
            case "short-fields": token = token[..16]; break;
            case "version-short": RawSmb.Put32(token, 12, RawSmb.U32(token, 12) | 0x02000000); break;
            case "wrong-type": RawSmb.Put32(token, 8, 2); break;
            case "bad-domain": RawSmb.Put32(token, 12, RawSmb.U32(token, 12) | 0x1000); RawSmb.Put16(token, 16, 4); RawSmb.Put32(token, 20, uint.MaxValue); break;
            case "bad-workstation": RawSmb.Put32(token, 12, RawSmb.U32(token, 12) | 0x2000); RawSmb.Put16(token, 24, 4); RawSmb.Put32(token, 28, 31); break;
            case "no-unicode": RawSmb.Put32(token, 12, RawSmb.U32(token, 12) & ~1u); break;
        }
        var b = await p.Exchange(RawSmb.SessionSetup(token, 0), route: false);
        Check.That(RawSmb.U32(b, 8) != 0xc0000016 && (RawSmb.U32(b, 8) & 0xc0000000) == 0xc0000000, "malformed/unsupported initial token terminally rejected");
        await p.Login(); Status(await p.Exchange(Create("fresh", 2)), Ok, "fresh authentication after rejection");
    }
    static async Task BadExportedKey(int length)
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); using var p = new AuthPeer(); await p.Connect(h.Server.Endpoint);
        var ntlm = new NtlmClient(HostFixture.Domain, HostFixture.User, HostFixture.Password);
        var b = await p.Exchange(RawSmb.SessionSetup(ntlm.BuildNegotiate(), 0), route: false); Status(b, 0xc0000016, "challenge");
        var auth = ntlm.BuildAuthenticate(RawSmb.Buffer(b, RawSmb.U16(b, 68), RawSmb.U16(b, 70)));
        var offset = RawSmb.U32(auth, 56); Array.Resize(ref auth, (int)offset + length);
        RawSmb.Put16(auth, 52, (ushort)length); RawSmb.Put16(auth, 54, (ushort)length);
        b = await p.Exchange(RawSmb.SessionSetup(auth, 0, RawSmb.U64(b, 40)), route: false);
        Check.That(RawSmb.U32(b, 8) != 0xc0000016 && (RawSmb.U32(b, 8) & 0xc0000000) == 0xc0000000, "KEY_EXCH requires a 16-byte encrypted exported key");
        await p.Login(); Status(await p.Exchange(Create("fresh", 2)), Ok, "key failure cannot poison next context");
    }
    static async Task InvalidSessionQuery()
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); using var p = new AuthPeer(); await p.Connect(h.Server.Endpoint); await p.Login();
        var id = Id(await p.Exchange(Create("file", 2))); var q = Query(id, 18); RawSmb.Put64(q, 40, p.Session + 1234);
        Status(await p.Exchange(q, route: false), 0xc0000203, "sessid.c QUERY_INFO invalid session");
        Status(await p.Exchange(Query(id, 14)), Ok, "original session still queries position");
    }
    static async Task ReauthTwice()
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); using var p = new AuthPeer(); await p.Connect(h.Server.Endpoint); await p.Login();
        var id = Id(await p.Exchange(Create("file", 2)));
        for (var i = 0; i < 2; i++) { await p.Login(reauth: true); Status(await p.Exchange(Query(id, 14)), Ok, "reauth1 position query after each reauth"); }
        Status(await p.Exchange(RawSmb.Close(id, 0, 0, 0)), Ok, "old open closes with original signing key");
    }
    static async Task ReauthFailure()
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); using var a = new AuthPeer(); using var b = new AuthPeer();
        await a.Connect(h.Server.Endpoint); await b.Connect(h.Server.Endpoint); await a.Login(); await b.Login();
        var id = Id(await a.Exchange(Create("file", 2, share: 0))); var other = Id(await b.Exchange(Create("other", 2)));
        var ntlm = new NtlmClient(HostFixture.Domain, HostFixture.User, "incorrect");
        var c = await a.Exchange(RawSmb.SessionSetup(ntlm.BuildNegotiate(), 0, a.Session), route: false); Status(c, 0xc0000016, "reauth starts");
        Status(await a.Exchange(RawSmb.SessionSetup(ntlm.BuildAuthenticate(RawSmb.Buffer(c, RawSmb.U16(c, 68), RawSmb.U16(c, 70))), 0, a.Session), route: false), 0xc000006d, "bad reauth proof");
        Status(await a.Exchange(Query(id, 14)), 0xc0000203, "failed reauth retires target session");
        Status(await b.Exchange(Query(other, 14)), Ok, "unrelated session survives failed reauth");
        Status(await b.Exchange(Create("file", 1, share: 0)), Ok, "failed session releases sharing reservation");
    }
    static async Task ReconnectSameTransport()
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); using var p = new AuthPeer(); await p.Connect(h.Server.Endpoint); await p.Login();
        var old = p.Session; var id = Id(await p.Exchange(Create("file", 2, access: Read | Write | 0x10000, share: 0, options: 0x1000)));
        await p.Login(previous: old);
        var q = Query(id, 14); RawSmb.Put64(q, 40, old); Status(await p.Exchange(q, route: false, integrity: "unsigned"), 0xc0000203, "reconnect2 old session removed on same transport");
        Status(await p.Exchange(Create("file", 1)), Missing, "reconnect2 closes delete-on-close open");
    }
    static async Task ReconnectFailure()
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); using var a = new AuthPeer(); using var b = new AuthPeer();
        await a.Connect(h.Server.Endpoint); await b.Connect(h.Server.Endpoint); await a.Login(); var id = Id(await a.Exchange(Create("file", 2)));
        var ntlm = new NtlmClient(HostFixture.Domain, HostFixture.User, "incorrect"); var req = RawSmb.SessionSetup(ntlm.BuildNegotiate(), 0); RawSmb.Put64(req, 80, a.Session);
        var c = await b.Exchange(req, route: false); Status(c, 0xc0000016, "replacement starts"); Status(await a.Exchange(Query(id, 14)), Ok, "challenge does not retire old session");
        req = RawSmb.SessionSetup(ntlm.BuildAuthenticate(RawSmb.Buffer(c, RawSmb.U16(c, 68), RawSmb.U16(c, 70))), 0, RawSmb.U64(c, 40)); RawSmb.Put64(req, 80, a.Session);
        Status(await b.Exchange(req, route: false), 0xc000006d, "replacement proof fails"); Status(await a.Exchange(Query(id, 14)), Ok, "failed replacement leaves old session alive");
    }
    static async Task UnknownPrevious()
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); using var p = new AuthPeer(); await p.Connect(h.Server.Endpoint); await p.Login(previous: 0x12345678);
        Status(await p.Exchange(Create("file", 2)), Ok, "unknown PreviousSessionId ignored after successful authentication");
    }
    static byte[] Tlv(byte tag, byte[] b) => (b.Length < 128 ? new byte[] { tag, (byte)b.Length } : new byte[] { tag, 0x82, (byte)(b.Length >> 8), (byte)b.Length }).Concat(b).ToArray();
    static byte[] ListMic(byte[] key, bool client, byte[] list)
    {
        var direction = client ? "client-to-server" : "server-to-client";
        var sign = MD5.HashData(key.Concat(System.Text.Encoding.ASCII.GetBytes("session key to " + direction + " signing key magic constant\0")).ToArray());
        var seal = MD5.HashData(key.Concat(System.Text.Encoding.ASCII.GetBytes("session key to " + direction + " sealing key magic constant\0")).ToArray());
        var checksum = HMACMD5.HashData(sign, new byte[4].Concat(list).ToArray())[..8];
        var state = Enumerable.Range(0, 256).ToArray(); var j = 0;
        for (var i = 0; i < 256; i++) { j = (j + state[i] + seal[i % seal.Length]) & 255; (state[i], state[j]) = (state[j], state[i]); }
        var x = 0; j = 0;
        for (var i = 0; i < 8; i++) { x = (x + 1) & 255; j = (j + state[x]) & 255; (state[x], state[j]) = (state[j], state[x]); checksum[i] ^= (byte)state[(state[x] + state[j]) & 255]; }
        return new byte[] { 1, 0, 0, 0 }.Concat(checksum).Concat(new byte[4]).ToArray();
    }
    static async Task MechanismListMic(string mode)
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); using var p = new AuthPeer(); await p.Connect(h.Server.Endpoint);
        byte[] list = Convert.FromHexString("300c060a2b06010401823702020a");
        var ntlm = new NtlmClient(HostFixture.Domain, HostFixture.User, HostFixture.Password); var token = ntlm.BuildNegotiate();
        if (mode != "empty-without-sign") RawSmb.Put32(token, 12, RawSmb.U32(token, 12) | 0x10);
        var init = Tlv(0x60, Convert.FromHexString("06062b0601050502").Concat(Tlv(0xa0, Tlv(0x30, Tlv(0xa0, list).Concat(Tlv(0xa2, Tlv(4, token))).ToArray()))).ToArray());
        var b = await p.Exchange(RawSmb.SessionSetup(init, 0), route: false); Status(b, 0xc0000016, "SPNEGO challenge"); var sid = RawSmb.U64(b, 40);
        var c = RawSmb.Buffer(b, RawSmb.U16(b, 68), RawSmb.U16(b, 70)); var at = c.AsSpan().IndexOf("NTLMSSP\0"u8); Check.That(at >= 0, "NTLM selected");
        var auth = ntlm.BuildAuthenticate(c[at..]); var mic = ListMic(ntlm.ExportedSessionKey, true, list);
        if (mode == "bad-mic") mic[4] ^= 1; if (mode == "short-mic") mic = mic[..15]; if (mode == "empty-without-sign") mic = [];
        var finish = Tlv(0xa1, Tlv(0x30, Tlv(0xa2, Tlv(4, auth)).Concat(Tlv(0xa3, Tlv(4, mic))).ToArray()));
        b = await p.Exchange(RawSmb.SessionSetup(finish, 0, sid), route: false); Status(b, mode == "valid" ? Ok : Denied, "incoming mechanism list MIC verified even when optional");
        if (mode == "valid")
        {
            var response = RawSmb.Buffer(b, RawSmb.U16(b, 68), RawSmb.U16(b, 70)); var expected = Tlv(0xa3, Tlv(4, ListMic(ntlm.ExportedSessionKey, false, list)));
            Check.That(response.AsSpan().IndexOf(expected) >= 0, "server returns independently verified direction-specific mechanism list MIC");
        }
    }

    static async Task NetappBlob()
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); using var p = new AuthPeer(); await p.Connect(h.Server.Endpoint); await p.Login();
        var ntlm = new NtlmClient(HostFixture.Domain, HostFixture.User, HostFixture.Password);
        var b = await p.Exchange(RawSmb.SessionSetup(ntlm.BuildNegotiate(), 0, p.Session), route: false); Status(b, 0xc0000016, "bug14932 reauth challenge");
        var auth = ntlm.BuildAuthenticate(RawSmb.Buffer(b, RawSmb.U16(b, 68), RawSmb.U16(b, 70)));
        var magic = Convert.FromHexString("abababababababababababababababab01010000000000003f3f3f3f3f3f3f3fb8823af1b3dd08150000000011a20881503822782b9447fe54947bff17275ab4f418badc2c38fd5bfb0ec1851ecc92bb9bb1c4d55314ff8c7649f5459019a2");
        var offset = auth.Length; Array.Resize(ref auth, offset + magic.Length); magic.CopyTo(auth, offset);
        RawSmb.Put16(auth, 20, (ushort)magic.Length); RawSmb.Put16(auth, 22, (ushort)magic.Length); RawSmb.Put32(auth, 24, (uint)offset);
        Status(await p.Exchange(RawSmb.SessionSetup(auth, 0, p.Session), route: false), Invalid, "source netapp diagnostic malformed AV list returns INVALID_PARAMETER");
    }
    static async Task SourceConnect()
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); using var p = new AuthPeer(); await p.Connect(h.Server.Endpoint); await p.Login();
        var req = Create("file", 3, options: 2); var a = Id(await p.Exchange(req)); var b = Id(await p.Exchange(req));
        var data = Enumerable.Range(0, 65536).Select(i => (byte)i).ToArray();
        for (var i = 0; i < 2; i++) { Status(await p.Exchange(RawSmb.Write(a, data, 0, 0, 0, 0)), Ok, "source 64KiB WRITE"); Status(await p.Exchange(Query(a, 18)), Ok, "source ALL_INFORMATION after WRITE"); }
        Status(await p.Exchange(Flush(a)), Ok, "source FLUSH"); var read = await p.Exchange(RawSmb.Read(a, 65536, 0, 0, 0, 0)); Status(read, Ok, "source READ"); Check.That(RawSmb.Buffer(read, read[66], RawSmb.U32(read, 68)).SequenceEqual(data), "source 64KiB exact bytes");
        foreach (var id in new[] { a, b }) { req = RawSmb.Close(id, 0, 0, 0); RawSmb.Put16(req, 66, 1); Status(await p.Exchange(req), Ok, "source full CLOSE"); }
        Status(await p.Exchange(RawSmb.Close(a, 0, 0, 0)), 0xc0000128, "source double CLOSE");
        // TreeId is routed by the peer; repeat TDIS and LOGOFF are intentionally stale.
        Status(await p.Exchange(RawSmb.TreeDisconnect(0, 0, 0)), Ok, "source TDIS"); Status(await p.Exchange(RawSmb.TreeDisconnect(0, 0, 0)), 0xc00000c9, "source repeated TDIS");
        Status(await p.Exchange(Logoff(0, p.Session)), Ok, "source LOGOFF"); Status(await p.Exchange(Logoff(0, p.Session)), 0xc0000203, "source repeated LOGOFF");
        var echo = RawSmb.Header(13, 4, 0, 0); RawSmb.Put16(echo, 64, 4); Status(await p.Exchange(echo, route: false, integrity: "unsigned"), Ok, "source sessionless keepalive after logoff");
    }
    static async Task SourceTcon()
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); using var p = new AuthPeer(); await p.Connect(h.Server.Endpoint); await p.Login();
        var id = Id(await p.Exchange(Create("file", 2, access: 3))); Status(await p.Exchange(RawSmb.Write(id, new byte[4], 130, 0, 0, 0)), Ok, "source initial offset130 WRITE");
        var tc = await p.Exchange(RawSmb.TreeConnect("\\\\localhost\\P0", 0, p.Session), route: false); Status(tc, Ok, "source secondary TCON"); var tid = RawSmb.U32(tc, 36);
        foreach (var tree in new[] { tid, tid + 1234 }) { var req = RawSmb.Write(id, new byte[4], 130, 0, p.Session, tree); Check.That(RawSmb.U32(await p.Exchange(req, route: false), 8) != 0, "source wrong tree rejected"); }
        var bad = RawSmb.Write(id, new byte[4], 130, 0, p.Session + 1, tid); Status(await p.Exchange(bad, route: false), 0xc0000203, "source invalid session");
        Status(await p.Exchange(RawSmb.Close(id, 0, 0, 0)), Ok, "source restores original tree and closes handle");
        var open = Create("file", 1); RawSmb.Put64(open, 40, p.Session); RawSmb.Put32(open, 36, tid); id = Id(await p.Exchange(open, route: false));
        var set = Set(id, 13, [1]); RawSmb.Put64(set, 40, p.Session); RawSmb.Put32(set, 36, tid); Status(await p.Exchange(set, route: false), Ok, "source delete via second tree");
        Status(await p.Exchange(RawSmb.Close(id, 0, p.Session, tid), route: false), Ok, "source completes unlink on second tree");
    }
    static void DirectDialect(SmbConnection c, ushort dialect)
    { c.Dialect = (SmbDialect)dialect; c.SigningAlgorithmId = dialect < 0x300 ? SmbSigningAlgorithmId.HmacSha256 : SmbSigningAlgorithmId.AesCmac; }
    static async Task SourceBindNegative(ushort first, ushort second, bool same, uint expected)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        d.Options.FeaturePolicy = SmbFeaturePolicy.MultichannelOnly; d.Options.EnableMultichannel = true; DirectDialect(d.Connection, first);
        var id = await d.Open(); var c = d.Channel(); DirectDialect(c, second); if (!same) c.ClientGuid = Guid.NewGuid().ToByteArray();
        foreach (var bind in new[] { true, false, false, true })
        {
            var req = RawSmb.SessionSetup(new NtlmClient("P0", "user", "password").BuildNegotiate(), 0, 1); req[66] = bind ? (byte)1 : (byte)0;
            Status(await d.Send(req, c), bind ? expected : 0xc0000203, "source binding/no-binding/no-context/repeated-binding rejection");
            Status(await d.Send(Query(id, 14)), Ok, "source original session survives invalid bind");
        }
    }
    static async Task SourceBind(ushort dialect)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        d.Options.FeaturePolicy = SmbFeaturePolicy.MultichannelOnly; d.Options.EnableMultichannel = true; DirectDialect(d.Connection, dialect);
        d.Session.SigningKey = Smb.Crypto.Smb3KeyDerivation.Derive((SmbDialect)dialect, SmbCipherId.None, d.Session.SessionKey, d.Session.SessionKey, new byte[64]).SigningKey;
        d.Session.Identity = new Smb.Auth.InMemoryIdentityBackend().AddUser("P0", "user", "password").Resolve("P0", "user");
        d.Session.Channels[d.Connection.ConnectionId] = new SmbChannel { Connection = d.Connection, SigningKey = d.Session.SigningKey };
        var id = await d.Open(); var c = d.Channel(); DirectDialect(c, dialect); d.State.Connections[c.ConnectionId] = c;
        try
        {
            var ntlm = new NtlmClient("P0", "user", "password"); var req = RawSmb.SessionSetup(ntlm.BuildNegotiate(), 0, 1); req[66] = 1;
            var b = await d.Send(req, c); Status(b, 0xc0000016, "source bind real NTLM challenge");
            req = RawSmb.SessionSetup(ntlm.BuildAuthenticate(RawSmb.Buffer(b, RawSmb.U16(b, 68), RawSmb.U16(b, 70))), 0, 1); req[66] = 1;
            var final = await d.Send(req, c); Status(final, Ok, "source bind authenticates same identity");
            var channelKey = Smb3KeyDerivation.Derive((SmbDialect)dialect, SmbCipherId.None, ntlm.ExportedSessionKey, ntlm.ExportedSessionKey, new byte[64]).SigningKey;
            Check.That(Smb2Signer.Verify(SmbSigningAlgorithmId.AesCmac, channelKey, final, RawSmb.U64(final, 24), true, false), "binding final response uses newly authenticated channel key, independent of original session key");
            Status(await d.Send(Query(id, 14)), Ok, "source original channel query");
            ulong channelMid = 3;
            async Task<byte[]> Bound(byte[] packet)
            {
                RawSmb.Put64(packet, 24, channelMid++); RawSmb.Put32(packet, 16, RawSmb.U32(packet, 16) | 8); Smb2Signer.SignInPlace(SmbSigningAlgorithmId.AesCmac, channelKey, packet, RawSmb.U64(packet, 24), false, false);
                return await d.Dispatcher.ProcessMessageAsync(c, packet);
            }
            Status(await Bound(Query(id, 14)), Ok, "source bound channel position query");
            Status(await Bound(RawSmb.Close(id, 0, 1, 42)), Ok, "source cross-channel CLOSE");
        }
        finally { await d.Dispatcher.OnConnectionClosedAsync(c); }
    }

    // Public algorithm workflows from session.c:test_session_sign_enc. The TCP
    // peer uses crypto helpers for packets; statuses, layouts and lifecycle
    // assertions come from the source/spec, never server state inspection.
    static async Task SignedNotify(ushort algorithm, ushort cipher)
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); h.Server.State.Options.DirectoryWatcher = new FakeWatcher(); using var p = new SessionWirePeer(algorithm, cipher); await p.Connect(h.Server.Endpoint);
        var root = Id(await p.Exchange(RawSmb.Create("", true, 0, 0, 0)));
        var create = Create("signed", 2, options: 0x1040); var id = Id(await p.Exchange(create));
        Status(await p.Exchange(Query(id, 14)), Ok, "source position before NOTIFY");
        var notify = P4Tests.Notify(root, 3, 1000); RawSmb.Put16(notify, 66, 1); // StructureSize32, WATCH_TREE1
        var notifyMid = await p.Send(notify); var interim = await p.Receive(); Status(interim, 0x103, "source NOTIFY pending");
        Check.That((RawSmb.U32(interim, 16) & 2) != 0, "NOTIFY has AsyncId");
        var cancel = RawSmb.Header(12, 4, notifyMid, p.Session); RawSmb.Put16(cancel, 64, 4); RawSmb.Put32(cancel, 16, 2); RawSmb.Put64(cancel, 32, RawSmb.U64(interim, 32));
        await p.Send(cancel, assign: false); var done = await p.Receive(); Status(done, 0xc0000120, "source cancelled NOTIFY final"); Check.Equal(notifyMid, RawSmb.U64(done, 24), "one targeted final response");
        Status(await p.Exchange(Query(id, 14)), Ok, "source session survives signed/encrypted CANCEL");
        Status(await p.Exchange(RawSmb.Close(id, 0, 0, 0)), Ok, "source file CLOSE"); Status(await p.Exchange(RawSmb.Close(root, 0, 0, 0)), Ok, "source root CLOSE");
    }
    sealed class SessionWirePeer(ushort algorithm, ushort cipher) : IDisposable
    {
        readonly TcpClient tcp = new(); byte[] hash = new byte[64]; byte[]? signing, encrypt, decrypt; ulong mid, nonce; uint tree; bool protectedIo;
        public ulong Session;
        void Hash(byte[] b) => hash = SHA512.HashData(hash.Concat(b).ToArray());
        public async Task Connect(System.Net.IPEndPoint endpoint)
        {
            using var timeout = new CancellationTokenSource(Check.Timeout); await tcp.ConnectAsync(endpoint.Address, endpoint.Port, timeout.Token);
            var n = RawSmb.Negotiate(); Array.Resize(ref n, 148); RawSmb.Put16(n, 100, 0x311); RawSmb.Put32(n, 72, 0x40); RawSmb.Put32(n, 92, 104); RawSmb.Put16(n, 96, 3);
            RawSmb.Put16(n, 104, 1); RawSmb.Put16(n, 106, 6); RawSmb.Put16(n, 112, 1); RawSmb.Put16(n, 116, 1);
            RawSmb.Put16(n, 120, 8); RawSmb.Put16(n, 122, 4); RawSmb.Put16(n, 128, 1); RawSmb.Put16(n, 130, algorithm);
            RawSmb.Put16(n, 136, 2); RawSmb.Put16(n, 138, 4); RawSmb.Put16(n, 144, 1); RawSmb.Put16(n, 146, cipher == 0 ? (ushort)1 : cipher);
            var b = await Exchange(n, route: false, preauth: true); Status(b, Ok, "source SMB311 algorithm negotiation"); Check.Equal((ushort)0x311, RawSmb.U16(b, 68), "source SMB311 selected");
            var ntlm = new NtlmClient(HostFixture.Domain, HostFixture.User, HostFixture.Password);
            b = await Exchange(RawSmb.SessionSetup(ntlm.BuildNegotiate(), 0), route: false, preauth: true); Status(b, 0xc0000016, "source NTLM challenge"); Session = RawSmb.U64(b, 40);
            var setup = RawSmb.SessionSetup(ntlm.BuildAuthenticate(RawSmb.Buffer(b, RawSmb.U16(b, 68), RawSmb.U16(b, 70))), mid++, Session); Hash(setup); await Frame(setup);
            var keys = Smb3KeyDerivation.Derive(SmbDialect.Smb311, (SmbCipherId)(cipher == 0 ? 1 : cipher), ntlm.ExportedSessionKey, ntlm.ExportedSessionKey, hash);
            signing = keys.SigningKey; encrypt = keys.DecryptionKey; decrypt = keys.EncryptionKey;
            b = await Receive(); Status(b, Ok, "source final setup stays plain and signed");
            protectedIo = cipher != 0;
            b = await Exchange(RawSmb.TreeConnect("\\\\localhost\\P0", 0, Session), route: false); Status(b, Ok, "source protected TREE_CONNECT"); tree = RawSmb.U32(b, 36);
        }
        public async Task<byte[]> Exchange(byte[] b, bool route = true, bool preauth = false)
        { await Send(b, route, preauth: preauth); var response = await Receive(); if (preauth) Hash(response); return response; }
        public async Task<ulong> Send(byte[] b, bool route = true, bool assign = true, bool preauth = false)
        {
            if (assign) RawSmb.Put64(b, 24, mid++); if (route) { RawSmb.Put64(b, 40, Session); if ((RawSmb.U32(b, 16) & 2) == 0) RawSmb.Put32(b, 36, tree); }
            var messageId = RawSmb.U64(b, 24); if (preauth) Hash(b);
            if (signing != null && !protectedIo) { RawSmb.Put32(b, 16, RawSmb.U32(b, 16) | 8); Smb2Signer.SignInPlace((SmbSigningAlgorithmId)algorithm, signing, b, messageId, false, RawSmb.U16(b, 12) == 12); }
            if (protectedIo) { var iv = new byte[Smb2Transform.NonceLength((SmbCipherId)cipher)]; RawSmb.Put64(iv, 0, ++nonce); b = Smb2Transform.Encrypt((SmbCipherId)cipher, encrypt!, Session, iv, b); }
            await Frame(b); return messageId;
        }
        async Task Frame(byte[] b)
        { using var timeout = new CancellationTokenSource(Check.Timeout); var f = new byte[b.Length + 4]; f[1] = (byte)(b.Length >> 16); f[2] = (byte)(b.Length >> 8); f[3] = (byte)b.Length; b.CopyTo(f, 4); await tcp.GetStream().WriteAsync(f, timeout.Token); }
        public async Task<byte[]> Receive()
        {
            using var timeout = new CancellationTokenSource(Check.Timeout); var prefix = new byte[4]; await tcp.GetStream().ReadExactlyAsync(prefix, timeout.Token); var length = prefix[1] << 16 | prefix[2] << 8 | prefix[3]; Check.That(length >= 64 && length < 1048576, "bounded session response");
            var b = new byte[length]; await tcp.GetStream().ReadExactlyAsync(b, timeout.Token);
            if (protectedIo) { Check.Equal((byte)0xfd, b[0], "source encrypted response"); b = Smb2Transform.Decrypt((SmbCipherId)cipher, decrypt!, b); }
            else { Check.Equal((byte)0xfe, b[0], "source unencrypted setup/signing response"); if (signing != null && RawSmb.U32(b, 8) != 0x103) { Check.That((RawSmb.U32(b, 16) & 8) != 0, "source signed response bit"); Check.That(Smb2Signer.Verify((SmbSigningAlgorithmId)algorithm, signing, b, RawSmb.U64(b, 24), true, false), "source response signature verifies"); } }
            return b;
        }
        public void Dispose() => tcp.Dispose();
    }

    static async Task CachedReconnect()
    {
        using var root = new P7cTests.Root(); await using var host = HostFixture.Build(root.Store(), 0, HostFixture.Domain, HostFixture.User, HostFixture.Password); host.State.Options.FeaturePolicy = SmbFeaturePolicy.Caching; await host.StartAsync();
        using var a = new AuthPeer(); using var b = new AuthPeer(); await a.Connect(host.Endpoint); await b.Connect(host.Endpoint); await a.Login();
        var req = Create("cached", 3, share: 0); req[67] = 9; var old = await a.Exchange(req); var id = Id(old); Check.Equal((byte)9, old[66], "source batch grant before reconnect");
        await b.Login(previous: a.Session); Status(await a.Exchange(Query(id, 14)), 0xc0000203, "source cached session retired");
        var replacement = await b.Exchange(req); id = Id(replacement); Check.Equal(1u, RawSmb.U32(replacement, 68), "source replacement opens existing object"); Check.Equal((byte)9, replacement[66], "source batch grant after reconnect");
        Status(await b.Exchange(RawSmb.Close(id, 0, 0, 0)), Ok, "source replacement cleanup");
    }
    static async Task ForeignPrevious()
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); h.Server.State.Options.SpnegoNegotiator = new NtlmSpnegoNegotiator(new Smb.Auth.InMemoryIdentityBackend().AddUser(HostFixture.Domain, HostFixture.User, HostFixture.Password).AddUser(HostFixture.Domain, "other", HostFixture.Password));
        using var a = new AuthPeer(); using var b = new AuthPeer(); await a.Connect(h.Server.Endpoint); await b.Connect(h.Server.Endpoint); await a.Login();
        var id = Id(await a.Exchange(Create("original", 2))); await b.Login(previous: a.Session, user: "other");
        Status(await a.Exchange(Query(id, 14)), Ok, "foreign authenticated user cannot retire another user's previous session"); Status(await b.Exchange(Create("other", 2)), Ok, "foreign replacement has its own usable session");
    }
    static async Task SelfPrevious()
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); using var p = new AuthPeer(); await p.Connect(h.Server.Endpoint); await p.Login(); var id = Id(await p.Exchange(Create("original", 2)));
        await p.Login(previous: p.Session, reauth: true); Status(await p.Exchange(Query(id, 14)), Ok, "self PreviousSessionId ignored during valid reauth");
    }
    static async Task TwoSessionBinding(ushort dialect)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); d.Options.FeaturePolicy = SmbFeaturePolicy.MultichannelOnly; d.Options.EnableMultichannel = true;
        DirectDialect(d.Connection, dialect); d.Session.SigningKey = Smb3KeyDerivation.Derive((SmbDialect)dialect, SmbCipherId.None, d.Session.SessionKey, d.Session.SessionKey, new byte[64]).SigningKey;
        var identity = new Smb.Auth.InMemoryIdentityBackend().AddUser("P0", "user", "password").Resolve("P0", "user"); d.Session.Identity = identity;
        d.Session.Channels[d.Connection.ConnectionId] = new SmbChannel { Connection = d.Connection, SigningKey = d.Session.SigningKey };
        var c2 = d.Channel(); var c3 = d.Channel(); DirectDialect(c2, dialect); DirectDialect(c3, dialect); d.State.Connections[c2.ConnectionId] = c2; d.State.Connections[c3.ConnectionId] = c3;
        // Explicit direct authenticated fixture for the second session; only the
        // binding exchanges below authenticate through NTLM. No TCP claim here.
        var s2 = new SmbSession { SessionId = 2, SessionGlobalId = 2, Connection = c2, State = SessionState.Valid, SigningRequired = true, SigningKey = d.Session.SigningKey.ToArray(), SessionKey = new byte[16], Identity = identity };
        s2.Channels[c2.ConnectionId] = new SmbChannel { Connection = c2, SigningKey = s2.SigningKey }; c2.Sessions[2] = s2; d.State.SessionGlobalList[2] = s2;
        s2.TreeConnects[42] = new SmbTreeConnect { TreeId = 42, Session = s2, Share = d.Tree.Share, MaximalAccess = 0x1f01ff };
        byte[] Scope(byte[] b, ulong sid) { RawSmb.Put64(b, 40, sid); return b; }
        try
        {
            var channelKeys = new Dictionary<ulong, byte[]>();
            var one = Id(await d.Send(Create("one", 2, access: 3, share: 0))); var two = Id(await d.Send(Scope(Create("two", 2, access: 3, share: 0), 2), c2));
            foreach (var sid in new ulong[] { 1, 2 })
            {
                var ntlm = new NtlmClient("P0", "user", "password"); var req = RawSmb.SessionSetup(ntlm.BuildNegotiate(), 0, sid); req[66] = 1;
                var b = await d.Send(req, c3); Status(b, 0xc0000016, "source third transport binding challenge"); req = RawSmb.SessionSetup(ntlm.BuildAuthenticate(RawSmb.Buffer(b, RawSmb.U16(b, 68), RawSmb.U16(b, 70))), 0, sid); req[66] = 1; Status(await d.Send(req, c3), Ok, "source third transport bound to each session"); channelKeys[sid] = Smb3KeyDerivation.Derive((SmbDialect)dialect, SmbCipherId.None, ntlm.ExportedSessionKey, ntlm.ExportedSessionKey, new byte[64]).SigningKey;
            }
            Status(await d.Send(Query(one, 14), c2), 0xc0000203, "unbound second transport cannot access session1"); Status(await d.Send(Scope(Query(two, 14), 2)), 0xc0000203, "unbound first transport cannot access session2");
            ulong thirdMid = 5;
            async Task<byte[]> Third(byte[] packet)
            {
                RawSmb.Put64(packet, 24, thirdMid++); RawSmb.Put32(packet, 16, RawSmb.U32(packet, 16) | 8); Smb2Signer.SignInPlace(SmbSigningAlgorithmId.AesCmac, channelKeys[RawSmb.U64(packet, 40)], packet, RawSmb.U64(packet, 24), false, false); return await d.Dispatcher.ProcessMessageAsync(c3, packet);
            }
            Status(await Third(Query(one, 14)), Ok, "bound third transport queries session1"); Status(await Third(Scope(Query(two, 14), 2)), Ok, "bound third transport queries session2");
            Status(await d.Send(Create("two", 1, access: 3, share: 0)), Sharing, "source session2 sharing survives binding"); Status(await d.Send(Scope(Create("one", 1, access: 3, share: 0), 2), c2), Sharing, "source session1 sharing survives binding");
            await d.Dispatcher.OnConnectionClosedAsync(c3);
            Status(await d.Send(Create("two", 1, access: 3, share: 0)), Sharing, "loss of shared third channel preserves owner session2");
            await d.Dispatcher.OnConnectionClosedAsync(c2);
            var opened = Id(await d.Send(Create("two", 1, access: 3, share: 0))); Status(await d.Send(RawSmb.Close(opened, 0, 1, 42)), Ok, "final session2 loss releases its sharing"); Status(await d.Send(Query(one, 14)), Ok, "session1 survives both channel losses");
        }
        finally { await d.Dispatcher.OnConnectionClosedAsync(c3); await d.Dispatcher.OnConnectionClosedAsync(c2); }
    }

    static async Task SourceError(string kind)
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); using var p = new AuthPeer(); await p.Connect(h.Server.Endpoint); await p.Login();
        if (kind.StartsWith("collision"))
        {
            var id = Id(await p.Exchange(Create("dir", 2, options: 1, attrs: 0x10))); Status(await p.Exchange(RawSmb.Close(id, 0, 0, 0)), Ok, "source seed directory");
            Status(await p.Exchange(Create("dir", 2, share: 0, options: kind == "collision-directory" ? 1u : 0u, attrs: 0x10)), Collision, "source directory collision");
        }
        else if (kind == "file-as-directory")
        { var id = Id(await p.Exchange(Create("file", 3))); Status(await p.Exchange(RawSmb.Close(id, 0, 0, 0)), Ok, "source seed regular file"); Status(await p.Exchange(Create("file", 1, options: 1, attrs: 0x10)), NotDirectory, "source regular file cannot open as directory"); }
        else Status(await p.Exchange(Create(".+,;=[].", 3)), Missing, "pinned source OS2 legacy filename result");
    }

    static async Task BindingIdentity(string mode)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); d.Options.FeaturePolicy = SmbFeaturePolicy.MultichannelOnly; d.Options.EnableMultichannel = true;
        var backend = new Smb.Auth.InMemoryIdentityBackend().AddUser("P0", "user", "password").AddUser("P0", "other", "password"); d.Options.SpnegoNegotiator = new NtlmSpnegoNegotiator(backend);
        DirectDialect(d.Connection, 0x300); d.Session.Identity = backend.Resolve("P0", "user"); d.Session.SigningKey = Smb3KeyDerivation.Derive(SmbDialect.Smb300, SmbCipherId.None, d.Session.SessionKey, d.Session.SessionKey, new byte[64]).SigningKey;
        d.Session.Channels[d.Connection.ConnectionId] = new SmbChannel { Connection = d.Connection, SigningKey = d.Session.SigningKey };
        var id = await d.Open(); var c = d.Channel(); DirectDialect(c, 0x300); d.State.Connections[c.ConnectionId] = c; ulong mid = 1;
        async Task<byte[]> Send(byte[] b, byte[] key)
        { RawSmb.Put64(b, 24, mid++); RawSmb.Put32(b, 16, RawSmb.U32(b, 16) | 8); Smb2Signer.SignInPlace(SmbSigningAlgorithmId.AesCmac, key, b, RawSmb.U64(b, 24), false, false); var reply = await d.Dispatcher.ProcessMessageAsync(c, b); c.ResponseSent(reply); return reply; }
        async Task<byte[]> Bind(NtlmClient ntlm, bool binding, byte[] key, uint expected)
        {
            var req = RawSmb.SessionSetup(ntlm.BuildNegotiate(), 0, 1); req[66] = binding ? (byte)1 : (byte)0;
            var b = await Send(req, key); Status(b, 0xc0000016, "source binding/reauth challenge"); req = RawSmb.SessionSetup(ntlm.BuildAuthenticate(RawSmb.Buffer(b, RawSmb.U16(b, 68), RawSmb.U16(b, 70))), 0, 1); req[66] = binding ? (byte)1 : (byte)0;
            Status(await Send(req, key), expected, "source binding/reauth final status"); return Smb3KeyDerivation.Derive(SmbDialect.Smb300, SmbCipherId.None, ntlm.ExportedSessionKey, ntlm.ExportedSessionKey, new byte[64]).SigningKey;
        }
        try
        {
            await Bind(new NtlmClient("P0", mode == "different-user" ? "other" : "user", mode == "invalid-auth" ? "bad-password" : "password"), true, d.Session.SigningKey, mode == "invalid-auth" ? 0xc000006du : 0xc00000bbu);
            Status(await Send(Query(id, 14), d.Session.SigningKey), 0xc0000203, "failed bind leaves channel unauthorized");
            if (mode == "invalid-auth")
            {
                // The original source's survival/retry convention conflicts with
                // MS-SMB2 3.3.5.5.3 terminal GSS teardown. Bad signatures fail
                // before GSS; foreign authenticated identity follows another rule.
                Status(await d.Send(Query(id, 14)), 0xc0000203, "terminal binding GSS failure retires original session");
                Check.That(d.Session.Opens.IsEmpty && d.Session.TreeConnects.IsEmpty && d.Session.Channels.IsEmpty, "terminal failure releases opens, trees and all channels");
                Check.That(!d.State.SessionGlobalList.ContainsKey(d.Session.SessionId), "terminal session removed from global index");
                return;
            }
            Status(await d.Send(Query(id, 14)), Ok, "foreign identity rejection preserves original session");
            var boundKey = await Bind(new NtlmClient("P0", "user", "password"), true, d.Session.SigningKey, Ok); Status(await Send(Query(id, 14), boundKey), Ok, "source correct-identity retry binds same connection");
            {
                await Bind(new NtlmClient("P0", "user", "bad-password"), false, boundKey, 0xc000006d);
                Status(await d.Send(Query(id, 14)), 0xc0000203, "source bad reauth on bound channel retires original channel too"); Status(await Send(Query(id, 14), boundKey), 0xc0000203, "source bad reauth retires all channels");
            }
        }
        finally { await d.Dispatcher.OnConnectionClosedAsync(c); }
    }

    static async Task BindingShutdown()
    {
        await using var d = new P2Tests.Direct(); d.Options.FeaturePolicy = SmbFeaturePolicy.MultichannelOnly; d.Options.EnableMultichannel = true; DirectDialect(d.Connection, 0x300);
        d.Session.Channels[d.Connection.ConnectionId] = new SmbChannel { Connection = d.Connection, SigningKey = d.Session.SigningKey };
        var c = d.Channel(); DirectDialect(c, 0x300); var id = await d.Open();
        var gate = new AsyncBarrier(); d.Store.Control.Enqueue("Read", new OperationStep(Barrier: gate, IgnoreCancellation: true));
        var read = d.Send(RawSmb.Read(id, 1, 0, 0, 1, 42)); await gate.Entered.WaitAsync(Check.Timeout); var closing = d.Dispatcher.OnConnectionClosedAsync(d.Connection).AsTask();
        try
        {
            Check.That(!closing.IsCompleted, "source final channel loss waits for physical read");
            var req = RawSmb.SessionSetup(new NtlmClient("P0", "user", "password").BuildNegotiate(), 0, 1); req[66] = 1;
            Status(await d.Send(req, c), 0xc0000203, "source shutdown session is USER_SESSION_DELETED while read still drains");
        }
        finally { gate.Release(); await read.WaitAsync(Check.Timeout); await closing.WaitAsync(Check.Timeout); await d.Dispatcher.OnConnectionClosedAsync(c); }
    }

}
