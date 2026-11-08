using System.Net.Sockets;
using System.Security.Cryptography;
using Smb.Auth.Ntlm;
using Smb.Protocol.Enums;
using Smb.Server;
using Smb.Testing;

internal static partial class UpstreamSambaTests
{
    static IEnumerable<(string Name, Func<Task> Run)> AdvancedCases()
    {
        foreach (var v1 in new[] { false, true })
            foreach (var share in Enumerable.Range(0, 8).Select(i => (uint)i))
            {
                foreach (var level in new byte[] { 0, 1, 8, 9 })
                {
                    if (share == 7 && (level == 9 || !v1 && level is 0 or 8)) continue;
                    yield return ($"upstream.samba.durable.oplock.{(v1 ? 1 : 2)}.{level}.{share}", () => DurableGrant(v1, share, level, null));
                }
                foreach (var state in new uint[] { 0, 1, 3, 5, 7 })
                {
                    if (share == 7 && state == 7) continue; // existing P7c TCP lease reconnects start with this grant
                    yield return ($"upstream.samba.durable.lease.{(v1 ? 1 : 2)}.{state}.{share}", () => DurableGrant(v1, share, 255, state));
                }
            }
        foreach (var from in new uint[] { 0, 1, 3, 5, 7 })
            foreach (var to in new uint[] { 0, 1, 3, 5, 7 })
            {
                if (from == 5 && to is 1 or 3 or 7 || from == 7 && to == 5) continue; // exact upstream.state.lease.subset-sidegrade
                yield return ($"upstream.samba.lease.upgrade.{from}.{to}", () => LeaseUpgrade(from, to));
            }
        foreach (var shape in new[] { "multi", "tiny", "overwrite", "sparse", "reverse-overlap", "streams", "two-keys", "bad-key", "partial-eof" })
            yield return ($"upstream.samba.copy.{shape}", () => CopyShape(shape));
        foreach (var command in new[] { "create", "read", "write", "flush", "query", "set", "lock", "unlock", "close" })
            yield return ($"upstream.samba.replay.regular.{command}", () => OrdinaryReplay(command));
        yield return ("upstream.samba.connect.full-lifetime", ConnectLifetime);
        foreach (var kind in new[] { "other-tree", "invalid-tree", "invalid-session" })
            yield return ($"upstream.samba.tcon.{kind}", () => WrongScope(kind));
        yield return ("upstream.samba.session.two-independent-logoffs", TwoLogoffs);
        yield return ("upstream.samba.session.previous-session-reconnect", PreviousSession);
        yield return ("upstream.samba.session.reauth-preserves-key", Reauthenticate);
        foreach (var kind in new[] { "unknown-user", "wrong-password", "malformed-token", "type3-first" })
            yield return ($"upstream.samba.auth.{kind}", () => AuthFailure(kind));
        yield return ("upstream.samba.auth.spnego-ntlm-roundtrip", SpnegoRoundtrip);
        yield return ("upstream.samba.auth.ntlm-negotiated-sign-flag", NtlmSignFlag);
        foreach (var kind in new[] { "unsigned", "bad-mac", "tampered-body" })
            yield return ($"upstream.samba.auth.integrity.{kind}", () => SigningFailure(kind));
    }
    static async Task DurableGrant(bool v1, uint share, byte level, uint? state)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        d.Options.FeaturePolicy = SmbFeaturePolicy.Durable; d.Connection.Dialect = SmbDialect.Smb300;
        d.Connection.ServerCapabilities |= Smb2Capabilities.Leasing;
        var b = state.HasValue ? LeaseRequest(state.Value) : Create("file", 3);
        b[67] = level; RawSmb.Put32(b, 96, share);
        var data = new byte[v1 ? 16 : 32];
        if (!v1) { RawSmb.Put32(data, 0, 2000); Guid.NewGuid().ToByteArray().CopyTo(data, 16); }
        b = P7cTests.Context(b, v1 ? "DHnQ" : "DH2Q", data);
        var response = await d.Send(b); var id = Id(response);
        try
        {
            // MS-SMB2 lease wire bits: READ=1, HANDLE=2, WRITE=4.
            var expected = state.HasValue ? (state.Value & 2) != 0 : level == 9;
            var context = Context(response, v1 ? "DHnQ" : "DH2Q");
            Check.Equal(expected, context != null, "pinned durable grant/share table: batch or handle caching is required");
            Check.Equal(level, response[66], "uncontended oplock/lease level in CREATE response");
            if (state.HasValue) Check.Equal(state.Value, RawSmb.U32(Context(response, "RqLs")!, 16), "uncontended lease state retained");
            if (context != null)
            {
                Check.Equal(8, context.Length, "durable grant response length");
                if (!v1) { Check.Equal(2000u, RawSmb.U32(context, 0), "durable timeout"); Check.Equal(0u, RawSmb.U32(context, 4), "ordinary grant has no persistent flag"); }
            }
        }
        finally { await Close(d, id); }
    }
    static byte[] LeaseRequest(uint state)
    {
        var b = Create("file", 3); b[67] = 255; var data = new byte[32];
        RawSmb.Put64(data, 0, 0x1111222233334444); RawSmb.Put64(data, 8, 0x5555666677778888); RawSmb.Put32(data, 16, state);
        return P7cTests.Context(b, "RqLs", data);
    }
    static byte[]? Context(byte[] b, string name)
    {
        var at = (int)RawSmb.U32(b, 144); var end = at + (int)RawSmb.U32(b, 148);
        while (at != 0 && at < end)
        {
            Check.That(at + 16 <= end && end <= b.Length, "bounded CREATE context");
            if (System.Text.Encoding.ASCII.GetString(b, at + RawSmb.U16(b, at + 4), RawSmb.U16(b, at + 6)) == name)
                return RawSmb.Buffer(b, at + RawSmb.U16(b, at + 10), RawSmb.U32(b, at + 12));
            var next = (int)RawSmb.U32(b, at); if (next == 0) break; Check.That(next >= 16 && (next & 7) == 0, "context advances"); at += next;
        }
        return null;
    }
    static async Task LeaseUpgrade(uint from, uint to)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        d.Options.FeaturePolicy = SmbFeaturePolicy.Caching; d.Connection.Dialect = SmbDialect.Smb300; d.Connection.ServerCapabilities |= Smb2Capabilities.Leasing;
        var a = await d.Send(LeaseRequest(from)); var first = Id(a); var b = await d.Send(LeaseRequest(to)); var second = Id(b);
        var expected = (from & to) == from ? to : from;
        foreach (var pair in new[] { (a, from), (b, expected) })
        {
            var data = Context(pair.Item1, "RqLs"); Check.That(data != null && data.Length == 32, "v1 lease response present");
            Check.Equal(pair.Item2, RawSmb.U32(data!, 16), "pinned lease_upgrade2_tests grant");
        }
        // Querying by a third same-key open must observe the common retained state.
        var c = await d.Send(LeaseRequest(0)); var third = Id(c); Check.Equal(expected, RawSmb.U32(Context(c, "RqLs")!, 16), "same key retains upgraded common state");
        await Close(d, first); await Close(d, second); await Close(d, third);
    }
    static byte[] CopyRequest((ulong P, ulong V) dst, byte[] key, params (ulong S, ulong T, uint N)[] ranges)
    {
        var data = new byte[32 + 24 * ranges.Length]; key.CopyTo(data, 0); RawSmb.Put32(data, 24, (uint)ranges.Length);
        for (var i = 0; i < ranges.Length; i++) { var at = 32 + 24 * i; RawSmb.Put64(data, at, ranges[i].S); RawSmb.Put64(data, at + 8, ranges[i].T); RawSmb.Put32(data, at + 16, ranges[i].N); }
        return P5Tests.Ioctl(dst, 0x1440f2, data, 12);
    }
    static async Task<byte[]> ResumeKey(P2Tests.Direct d, (ulong P, ulong V) id)
    {
        var b = await d.Send(P5Tests.Ioctl(id, 0x140078, [], 32)); Status(b, Ok, "REQUEST_RESUME_KEY");
        Check.Equal(32u, RawSmb.U32(b, 100), "resume-key structure size"); return b.AsSpan(112, 24).ToArray();
    }
    static async Task CopyShape(string shape)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); d.Options.FeaturePolicy = SmbFeaturePolicy.CopyOnly;
        var bytes = Enumerable.Range(0, 64).Select(i => (byte)(i * 3 + 1)).ToArray();
        if (shape == "streams") await Close(d, await Open(d, disposition: 2));
        var src = await Open(d, shape == "streams" ? "file:source" : "file", 3);
        Status(await d.Send(RawSmb.Write(src, bytes, 0, 0, 1, 42)), Ok, "seed source via WRITE");
        var dst = shape == "reverse-overlap" ? src : await Open(d, shape == "streams" ? "file:target" : "target", 3);
        var key = await ResumeKey(d, src);
        if (shape == "two-keys")
        {
            var other = await Open(d); var secondKey = await ResumeKey(d, other);
            Check.That(!key.SequenceEqual(secondKey), "different opens get distinct resume keys");
            var repeatedKey = await ResumeKey(d, src);
            Check.That(key.SequenceEqual(repeatedKey), "same open has stable resume key");
            await Close(d, other); Status(await d.Send(CopyRequest(dst, key, (0, 0, 64))), Ok, "closing peer does not invalidate source key");
            await Data(d, dst, bytes); return;
        }
        if (shape == "bad-key")
        {
            key[0] ^= 1; Status(await d.Send(CopyRequest(dst, key, (0, 0, 64))), Missing, "unissued resume key rejected"); await Data(d, dst, []); return;
        }
        if (shape == "partial-eof")
        {
            var b = await d.Send(CopyRequest(dst, key, (0, 0, 4), (63, 4, 4))); Status(b, 0xc0000011, "second chunk past source EOF");
            Check.Equal(1u, RawSmb.U32(b, 112), "first chunk completed before EOF"); Check.Equal(4u, RawSmb.U32(b, 120), "only complete source chunk copied"); await Data(d, dst, bytes[..4]); return;
        }
        (ulong S, ulong T, uint N)[] chunks = shape switch
        {
            "multi" => [(32, 0, 16), (0, 16, 16), (16, 32, 16)],
            "tiny" => Enumerable.Range(0, 16).Select(i => ((ulong)(15 - i), (ulong)i, 1u)).ToArray(),
            "sparse" => [(8, 4096, 8)], "reverse-overlap" => [(16, 0, 32)],
            "overwrite" => [(16, 8, 16)], _ => [(0, 0, 64)]
        };
        byte[] expected;
        if (shape == "overwrite") { Status(await d.Send(RawSmb.Write(dst, new byte[64], 0, 0, 1, 42)), Ok, "seed destination"); expected = new byte[64]; bytes.AsSpan(16, 16).CopyTo(expected.AsSpan(8)); }
        else if (shape == "reverse-overlap") { expected = bytes.ToArray(); bytes.AsSpan(16, 32).CopyTo(expected); }
        else if (shape == "sparse") { expected = new byte[4104]; bytes.AsSpan(8, 8).CopyTo(expected.AsSpan(4096)); }
        else if (shape == "multi") expected = bytes[32..48].Concat(bytes[..16]).Concat(bytes[16..32]).ToArray();
        else if (shape == "tiny") expected = bytes[..16].Reverse().ToArray();
        else expected = bytes;
        var response = await d.Send(CopyRequest(dst, key, chunks)); Status(response, Ok, "COPYCHUNK shape");
        Check.Equal((uint)chunks.Length, RawSmb.U32(response, 112), "exact completed chunk count");
        Check.Equal(chunks.Aggregate(0u, (n, c) => n + c.N), RawSmb.U32(response, 120), "exact total copied bytes"); await Data(d, dst, expected);
        if (shape != "reverse-overlap") await Data(d, src, bytes);
    }
    static async Task OrdinaryReplay(string command)
    {
        await using var d = new P2Tests.Direct(); d.Connection.Dialect = SmbDialect.Smb300;
        var create = Create("file", 3); RawSmb.Put32(create, 16, 0x20000000); var id = Id(await d.Send(create));
        Status(await d.Send(RawSmb.Write(id, [1, 2, 3], 0, 0, 1, 42)), Ok, "seed ordinary open");
        var data = new byte[8]; RawSmb.Put64(data, 0, 0x1000);
        var request = command switch
        {
            "create" => Create("file", 3), "read" => RawSmb.Read(id, 3, 0, 0, 1, 42), "write" => RawSmb.Write(id, [4, 5, 6], 0, 0, 1, 42),
            "query" => Query(id, 14), "set" => Set(id, 14, data), "lock" => Lock(id, 0, 1), "unlock" => Lock(id, 0, 1, 4),
            "close" => RawSmb.Close(id, 0, 1, 42), _ => Flush(id)
        };
        if (command == "unlock") Status(await d.Send(Lock(id, 0, 1)), Ok, "prepare ordinary unlock");
        RawSmb.Put32(request, 16, RawSmb.U32(request, 16) | 0x20000000); var b = await d.Send(request); Status(b, Ok, "replay flag ignored for regular non-durable operation");
        if (command == "write") await Data(d, id, [4, 5, 6]);
        if (command == "set") { b = await d.Send(Query(id, 14)); Status(b, Ok, "query position after replay-flagged SET"); Check.Equal(0x1000ul, RawSmb.U64(b, RawSmb.U16(b, 66)), "position mutation occurred"); }
        if (command == "close") Status(await d.Send(RawSmb.Close(id, 0, 1, 42)), 0xc0000128, "ordinary CLOSE was actually executed");
    }
    static byte[] Flush((ulong P, ulong V) id)
    { var b = RawSmb.Header(7, 24, 0, 1, 42); RawSmb.Put16(b, 64, 24); RawSmb.Put64(b, 72, id.P); RawSmb.Put64(b, 80, id.V); return b; }
    static byte[] Logoff(ulong mid, ulong sid) { var b = RawSmb.Header(2, 4, mid, sid); RawSmb.Put16(b, 64, 4); return b; }
    static async Task ConnectLifetime()
    {
        await using var h = new HostFixture(); await h.StartAsync(); await using var c = await h.ConnectAsync();
        var a = await c.CreateAsync("file"); var b = await c.CreateAsync("file"); await c.WriteAsync(a, Payload);
        var flush = Flush(a); RawSmb.Put64(flush, 24, c.NextMessageId()); RawSmb.Put64(flush, 40, c.Session); RawSmb.Put32(flush, 36, c.Tree); await c.ExchangeAsync(flush, size: 4);
        Check.That((await c.ReadAsync(b, (uint)Payload.Length)).SequenceEqual(Payload), "second open reads first open's data");
        var close = RawSmb.Close(a, c.NextMessageId(), c.Session, c.Tree); RawSmb.Put16(close, 66, 1);
        var response = await c.ExchangeAsync(close, size: 60); Check.Equal((ulong)Payload.Length, RawSmb.U64(response, 104), "full CLOSE returns EOF");
        await c.CloseAsync(b); await c.ExchangeAsync(RawSmb.Close(a, c.NextMessageId(), c.Session, c.Tree), 0xc0000128, 9);
        await c.DisconnectTreeAsync(); await c.ExchangeAsync(RawSmb.TreeDisconnect(c.NextMessageId(), c.Session, c.Tree), 0xc00000c9, 9);
        await c.ExchangeAsync(Logoff(c.NextMessageId(), c.Session), size: 4); await c.ExchangeAsync(Logoff(c.NextMessageId(), c.Session), 0xc0000203, 9);
    }
    static async Task WrongScope(string kind)
    {
        await using var h = new HostFixture(); await h.StartAsync(); await using var c = await h.ConnectAsync(); var id = await c.CreateAsync("file"); await c.WriteAsync(id, Payload);
        var response = await c.ExchangeAsync(RawSmb.TreeConnect("\\\\localhost\\P0", c.NextMessageId(), c.Session), size: 16); var otherTree = RawSmb.U32(response, 36);
        var request = RawSmb.Write(id, [99], 0, c.NextMessageId(), kind == "invalid-session" ? c.Session + 1234 : c.Session, kind == "other-tree" ? otherTree : kind == "invalid-tree" ? uint.MaxValue - 1 : c.Tree);
        var rejected = await c.ExchangeAsync(request, kind == "invalid-session" ? 0xc0000203u : 0xc0000128u, 9);
        Check.That((await c.ReadAsync(id, (uint)Payload.Length)).SequenceEqual(Payload), "rejected scope cannot mutate live handle"); await c.CloseAsync(id);
    }
    static async Task TwoLogoffs()
    {
        await using var h = new HostFixture(); await h.StartAsync(); await using var a = await h.ConnectAsync(); await using var b = await h.ConnectAsync();
        var id = await a.CreateAsync("file"); await a.WriteAsync(id, Payload); await b.ExchangeAsync(Logoff(b.NextMessageId(), b.Session), size: 4);
        Check.That((await a.ReadAsync(id, (uint)Payload.Length)).SequenceEqual(Payload), "logging off another session leaves first alive");
        await a.CloseAsync(id); await a.ExchangeAsync(Logoff(a.NextMessageId(), a.Session), size: 4);
    }
    static async Task PreviousSession()
    {
        await using var h = new HostFixture(); await h.StartAsync(); using var a = new AuthPeer(); await a.Connect(h.Server.Endpoint); await a.Login();
        var opened = await a.Exchange(Create("file", 3)); var oldId = Id(opened);
        using var b = new AuthPeer(); await b.Connect(h.Server.Endpoint); await b.Login(previous: a.Session);
        Status(await a.Exchange(Query(oldId, 14)), 0xc0000203, "PreviousSessionId invalidates old session");
        Status(await b.Exchange(Create("file", 1, share: 0)), Ok, "reconnect releases old share reservation");
    }
    static async Task Reauthenticate()
    {
        await using var h = new HostFixture(); await h.StartAsync(); using var p = new AuthPeer(); await p.Connect(h.Server.Endpoint); await p.Login();
        var id = Id(await p.Exchange(Create("file", 3))); Status(await p.Exchange(RawSmb.Write(id, Payload, 0, 0, 1, 42)), Ok, "seed before reauthentication");
        await p.Login(reauth: true); var b = await p.Exchange(RawSmb.Read(id, (uint)Payload.Length, 0, 0, 1, 42)); Status(b, Ok, "original signed handle survives reauthentication");
        Check.That(RawSmb.Buffer(b, b[66], RawSmb.U32(b, 68)).SequenceEqual(Payload), "same handle/data after reauth");
    }
    static async Task AuthFailure(string kind)
    {
        await using var h = new HostFixture(); await h.StartAsync(); using var p = new AuthPeer(); await p.Connect(h.Server.Endpoint);
        if (kind is "unknown-user" or "wrong-password")
        {
            var ntlm = new NtlmClient(HostFixture.Domain, kind == "unknown-user" ? "nonexistent-user" : HostFixture.User, kind == "wrong-password" ? "definitely-wrong" : HostFixture.Password);
            var b = await p.Exchange(RawSmb.SessionSetup(ntlm.BuildNegotiate(), 0), route: false); Status(b, 0xc0000016, "NTLM challenge for unvalidated identity");
            var auth = RawSmb.SessionSetup(ntlm.BuildAuthenticate(RawSmb.Buffer(b, RawSmb.U16(b, 68), RawSmb.U16(b, 70))), 0, RawSmb.U64(b, 40));
            Status(await p.Exchange(auth, route: false), 0xc000006d, "incorrect identity/proof produces LOGON_FAILURE");
        }
        else
        {
            byte[] token = kind == "type3-first" ? [78,84,76,77,83,83,80,0,3,0,0,0] : [0x60,0x82,0xff,0xff,0x06];
            var b = await p.Exchange(RawSmb.SessionSetup(token, 0), route: false);
            // MS-SMB2 3.3.5.5.3 propagates the mechanism's error status; it does
            // not mandate LOGON_FAILURE for malformed GSS/NTLM tokens.
            Check.That(RawSmb.U32(b, 8) != 0xc0000016 && (RawSmb.U32(b, 8) & 0xc0000000) == 0xc0000000,
                "invalid authentication token must produce a terminal error, not a challenge or success");
        }
        Status(await p.Exchange(Create("unauthenticated", 2), route: false), 0xc0000203, "failed auth cannot authorize file operation");
        await p.Login(); Status(await p.Exchange(Create("valid-after-failure", 2)), Ok, "fresh valid exchange after failed auth");
    }
    static async Task SpnegoRoundtrip()
    {
        await using var h = new HostFixture(); await h.StartAsync(); using var p = new AuthPeer(); await p.Connect(h.Server.Endpoint); await p.Login(spnego: true);
        var id = Id(await p.Exchange(Create("file", 2))); Status(await p.Exchange(RawSmb.Write(id, Payload, 0, 0, 1, 42)), Ok, "SPNEGO session writes signed request");
        var b = await p.Exchange(RawSmb.Read(id, (uint)Payload.Length, 0, 0, 1, 42)); Status(b, Ok, "SPNEGO session reads signed response"); Check.That(RawSmb.Buffer(b, b[66], RawSmb.U32(b, 68)).SequenceEqual(Payload), "SPNEGO roundtrip bytes");
    }
    static async Task NtlmSignFlag()
    {
        await using var h = new HostFixture(); await h.StartAsync(); using var p = new AuthPeer(); await p.Connect(h.Server.Endpoint);
        var token = new NtlmClient(HostFixture.Domain, HostFixture.User, HostFixture.Password).BuildNegotiate();
        RawSmb.Put32(token, 12, RawSmb.U32(token, 12) | 0x10);
        var b = await p.Exchange(RawSmb.SessionSetup(token, 0), route: false); Status(b, 0xc0000016, "NTLM challenge");
        var challenge = RawSmb.Buffer(b, RawSmb.U16(b, 68), RawSmb.U16(b, 70));
        Check.That(challenge.AsSpan(0, 8).SequenceEqual("NTLMSSP\0"u8), "raw NTLM challenge signature");
        Check.Equal(2u, RawSmb.U32(challenge, 8), "NTLM CHALLENGE_MESSAGE type");
        Check.That((RawSmb.U32(challenge, 20) & 0x10) != 0, "NTLM negotiate SIGN must survive in the challenge (external Samba client downgrade check)");
    }
    static async Task SigningFailure(string kind)
    {
        await using var h = new HostFixture(); await h.StartAsync(); using var p = new AuthPeer(); await p.Connect(h.Server.Endpoint); await p.Login(); var id = Id(await p.Exchange(Create("file", 2)));
        var request = RawSmb.Write(id, [1, 2, 3], 0, 0, 1, 42);
        Status(await p.Exchange(request, integrity: kind), Denied, "required signing rejects " + kind);
        var b = await p.Exchange(RawSmb.Read(id, 1, 0, 0, 1, 42)); Status(b, 0xc0000011, "unauthenticated mutation did not execute");
    }
    // Tiny SMB2.0.2 TCP peer: framing, routing and response HMAC are independent.
    // Reuses the existing NTLM client for proofs; no production SMB serializers.
    sealed class AuthPeer : IDisposable
    {
        readonly TcpClient tcp = new(); ulong mid; byte[]? key;
        public ulong Session; uint tree;
        public async Task Connect(System.Net.IPEndPoint endpoint)
        {
            using var timeout = new CancellationTokenSource(Check.Timeout); await tcp.ConnectAsync(endpoint.Address, endpoint.Port, timeout.Token);
            var b = await Exchange(RawSmb.Negotiate(), route: false); Status(b, Ok, "NEGOTIATE"); Check.Equal((ushort)0x202, RawSmb.U16(b, 68), "SMB202 dialect"); Check.That((RawSmb.U16(b, 66) & 2) != 0, "signing remains required");
        }
        static byte[] Der(byte tag, byte[] data) => data.Length < 128 ? new[] { tag, (byte)data.Length }.Concat(data).ToArray() : new[] { tag, (byte)0x82, (byte)(data.Length >> 8), (byte)data.Length }.Concat(data).ToArray();
        public async Task Login(ulong previous = 0, bool reauth = false, bool spnego = false, string user = HostFixture.User)
        {
            // A fresh SessionId=0 handshake has no session signing key (3.3.5.2.4).
            if (!reauth) key = null;
            var ntlm = new NtlmClient(HostFixture.Domain, user, HostFixture.Password); var token = ntlm.BuildNegotiate();
            if (spnego)
            {
                byte[] oid = [6,10,43,6,1,4,1,0x82,0x37,2,2,10];
                token = Der(0x60, new byte[] {6,6,43,6,1,5,5,2}.Concat(Der(0xa0, Der(0x30, Der(0xa0, Der(0x30, oid)).Concat(Der(0xa2, Der(4, token))).ToArray()))).ToArray());
            }
            var request = RawSmb.SessionSetup(token, 0, reauth ? Session : 0); RawSmb.Put64(request, 80, previous);
            var b = await Exchange(request, route: false); Status(b, 0xc0000016, "SESSION_SETUP challenge"); var sid = RawSmb.U64(b, 40);
            var challenge = RawSmb.Buffer(b, RawSmb.U16(b, 68), RawSmb.U16(b, 70));
            if (spnego) { var at = challenge.AsSpan().IndexOf("NTLMSSP\0"u8); Check.That(at >= 0, "SPNEGO challenge contains NTLM response token"); challenge = challenge[at..]; }
            token = ntlm.BuildAuthenticate(challenge); if (spnego) token = Der(0xa1, Der(0x30, Der(0xa2, Der(4, token))));
            request = RawSmb.SessionSetup(token, 0, sid); RawSmb.Put64(request, 80, previous);
            b = await Exchange(request, route: false); Status(b, Ok, "SESSION_SETUP authenticated"); Check.Equal(sid, RawSmb.U64(b, 40), "SessionId stable across auth exchange"); Check.Equal((ushort)0, RawSmb.U16(b, 66), "neither guest nor null session");
            if (!reauth) { Session = sid; key = ntlm.ExportedSessionKey; b = await Exchange(RawSmb.TreeConnect("\\\\localhost\\P0", 0, sid), route: false); Status(b, Ok, "authenticated TREE_CONNECT"); tree = RawSmb.U32(b, 36); }
        }
        public async Task<byte[]> Exchange(byte[] request, bool route = true, string? integrity = null)
        {
            RawSmb.Put64(request, 24, mid++); if (route) { RawSmb.Put64(request, 40, Session); RawSmb.Put32(request, 36, tree); }
            if (key != null && integrity != "unsigned") { RawSmb.Sign(request, key); if (integrity == "bad-mac") request[48] ^= 0x80; if (integrity == "tampered-body") request[^1] ^= 1; }
            using var timeout = new CancellationTokenSource(Check.Timeout); var stream = tcp.GetStream(); var frame = new byte[request.Length + 4]; frame[1] = (byte)(request.Length >> 16); frame[2] = (byte)(request.Length >> 8); frame[3] = (byte)request.Length; request.CopyTo(frame, 4); await stream.WriteAsync(frame, timeout.Token);
            var prefix = new byte[4]; await stream.ReadExactlyAsync(prefix, timeout.Token); Check.Equal((byte)0, prefix[0], "SMB TCP response type"); var length = prefix[1] << 16 | prefix[2] << 8 | prefix[3]; Check.That(length >= 64 && length <= 1048576, "bounded response");
            var b = new byte[length]; await stream.ReadExactlyAsync(b, timeout.Token); Check.Equal(RawSmb.U64(request, 24), RawSmb.U64(b, 24), "response MessageId"); Check.Equal(RawSmb.U16(request, 12), RawSmb.U16(b, 12), "response command");
            if (key != null && integrity != "unsigned" && RawSmb.U64(b, 40) == Session && RawSmb.U32(b, 8) != 0xc0000203 && !(RawSmb.U16(b, 12) == 1 && RawSmb.U32(b, 8) != 0))
            {
                Check.That((RawSmb.U32(b, 16) & 8) != 0, "authenticated reply signed"); var signature = b.AsSpan(48, 16).ToArray(); b.AsSpan(48, 16).Clear(); Check.That(HMACSHA256.HashData(key, b).AsSpan(0, 16).SequenceEqual(signature), "independent response HMAC"); signature.CopyTo(b, 48);
            }
            return b;
        }
        public void Dispose() => tcp.Dispose();
    }
}
