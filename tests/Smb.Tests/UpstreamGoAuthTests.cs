using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Smb.Testing;

internal static class UpstreamGoAuthTests
{
    const uint More = 0xc0000016, LogonFailure = 0xc000006d, Invalid = 0xc000000d, AccessDenied = 0xc0000022;
    // MS-NLMP 4.2.4.1: Password / User / Domain. Shared with the pinned Go
    // Ntowfv2/SessionBaseKey vectors. No production NTLM client or hash helper.
    static readonly byte[] ResponseKey = Convert.FromHexString("0c868a403bfd7a93a3001ef22ef02e3f");
    static readonly byte[] NtlmOid = Convert.FromHexString("060a2b06010401823702020a");
    public static IEnumerable<(string Name, Func<Task> Run)> Cases()
    {
        foreach (var mode in new[] { "raw", "spnego", "spnego-golden-init", "keyexchange", "mic", "wrong-password", "wrong-user", "wrong-domain", "tampered-proof", "tampered-mic", "missing-mic", "short-proof", "truncated-auth", "overflow-auth" })
        { var value = mode; yield return ($"upstream.go.auth.ntlm.{value}", () => Authenticate(value)); }
        foreach (var mode in new[] { "empty", "garbage", "truncated-spnego", "unsupported-mechanism" })
        { var value = mode; yield return ($"upstream.go.auth.initial.{value}", () => InvalidInitial(value)); }
        foreach (var mode in new[] { "payload", "signature", "unsigned", "other-session-key" })
        { var value = mode; yield return ($"upstream.go.auth.integrity.{value}", () => Integrity(value)); }
        yield return ("upstream.go.auth.encrypted-ntlm-roundtrip", () => Encrypted(false));
        yield return ("upstream.go.auth.encrypted-tag-tamper", () => Encrypted(true));
        yield return ("upstream.go.auth.encrypted-optional-roundtrip", () => Encrypted(false, false));
        yield return ("upstream.go.auth.encrypted-optional-tag-tamper", () => Encrypted(true, false));
        yield return ("upstream.go.auth.challenge-replay", Replay);
        yield return ("upstream.go.auth.logoff-retires-key", Logoff);
        yield return ("upstream.go.auth.framing.fragmented-ntlm", Fragmented);
    }
    static byte[] Cat(params byte[][] data) => data.SelectMany(b => b).ToArray();
    static byte[] Tlv(byte tag, byte[] data)
    { var length = data.Length < 128 ? new[] { (byte)data.Length } : data.Length < 256 ? new[] { (byte)0x81, (byte)data.Length } : new[] { (byte)0x82, (byte)(data.Length >> 8), (byte)data.Length }; return Cat([tag], length, data); }
    static byte[] Init(byte[] token) => Tlv(0x60, Cat(Convert.FromHexString("06062b0601050502"), Tlv(0xa0, Tlv(0x30, Cat(Tlv(0xa0, Tlv(0x30, NtlmOid)), Tlv(0xa2, Tlv(4, token)))))));
    static byte[] Continue(byte[] token) => Tlv(0xa1, Tlv(0x30, Tlv(0xa2, Tlv(4, token))));
    static byte[] Negotiate()
    { var b = new byte[32]; "NTLMSSP\0"u8.CopyTo(b); RawSmb.Put32(b, 8, 1); RawSmb.Put32(b, 12, 0xe0088215); return b; }
    static byte[] Hmac(byte[] key, params byte[][] values) => HMACMD5.HashData(key, Cat(values));
    static byte[] Rc4(byte[] key, byte[] input)
    {
        var state = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray(); var j = 0;
        for (var i = 0; i < 256; i++) { j = (j + state[i] + key[i % key.Length]) & 255; (state[i], state[j]) = (state[j], state[i]); }
        var result = new byte[input.Length]; var x = 0; j = 0;
        for (var i = 0; i < input.Length; i++) { x = (x + 1) & 255; j = (j + state[x]) & 255; (state[x], state[j]) = (state[j], state[x]); result[i] = (byte)(input[i] ^ state[(state[x] + state[j]) & 255]); }
        return result;
    }
    static (byte[] Token, byte[] Key) Auth(byte[] challenge, string mode, byte[] negotiate)
    {
        Check.That(challenge.AsSpan(0, 8).SequenceEqual("NTLMSSP\0"u8) && RawSmb.U32(challenge, 8) == 2, "independent type-2 challenge");
        var info = challenge.AsSpan((int)RawSmb.U32(challenge, 44), RawSmb.U16(challenge, 40)).ToArray();
        var timestamp = new byte[8];
        for (var at = 0; at + 4 <= info.Length;)
        { var av = RawSmb.U16(info, at); var length = RawSmb.U16(info, at + 2); if (av == 7 && length == 8) info.AsSpan(at + 4, 8).CopyTo(timestamp); at += 4 + length; if (av == 0) break; }
        var mic = mode is "mic" or "tampered-mic" or "missing-mic";
        if (mic) info = Cat(info[..^4], Convert.FromHexString("060004000200000000000000"));
        var blob = Cat(Convert.FromHexString("0101000000000000"), timestamp, Convert.FromHexString("ffffff0011223344"), new byte[4], info, new byte[4]);
        var responseKey = ResponseKey.ToArray(); if (mode == "wrong-password") responseKey[0] ^= 1;
        var proof = Hmac(responseKey, challenge.AsSpan(24, 8).ToArray(), blob); var key = Hmac(responseKey, proof);
        if (mode == "tampered-proof") proof[0] ^= 1;
        var nt = Cat(proof, blob); if (mode == "short-proof") nt = nt[..15];
        var domain = Encoding.Unicode.GetBytes(mode == "wrong-domain" ? "Other" : "Domain"); var user = Encoding.Unicode.GetBytes(mode == "wrong-user" ? "Other" : "User"); var workstation = Encoding.Unicode.GetBytes("COMPUTER");
        var exchanged = mode == "keyexchange"; var wireKey = exchanged ? Rc4(key, Convert.FromHexString("55555555555555555555555555555555")) : Array.Empty<byte>();
        if (exchanged) key = Convert.FromHexString("55555555555555555555555555555555");
        var fields = new[] { new byte[24], nt, domain, user, workstation, wireKey }; var b = new byte[88 + fields.Sum(x => x.Length)]; "NTLMSSP\0"u8.CopyTo(b); RawSmb.Put32(b, 8, 3);
        var cursor = 88; for (var i = 0; i < fields.Length; i++) { RawSmb.Put16(b, 12 + 8 * i, (ushort)fields[i].Length); RawSmb.Put16(b, 14 + 8 * i, (ushort)fields[i].Length); RawSmb.Put32(b, 16 + 8 * i, (uint)cursor); fields[i].CopyTo(b, cursor); cursor += fields[i].Length; }
        RawSmb.Put32(b, 60, exchanged ? 0xe0888215u : 0xa0888215u);
        if (mic && mode != "missing-mic") Hmac(key, negotiate, challenge, b).CopyTo(b, 72);
        if (mode == "tampered-mic") b[72] ^= 1;
        if (mode == "truncated-auth") b = b[..50]; if (mode == "overflow-auth") RawSmb.Put32(b, 24, uint.MaxValue);
        return (b, key);
    }
    sealed class Host : IAsyncDisposable
    {
        public readonly HostFixture Fixture;
        public Host() { Fixture = new HostFixture(); Fixture.Server.State.Options.SpnegoNegotiator = new Smb.Auth.Ntlm.NtlmSpnegoNegotiator(new Smb.Auth.InMemoryIdentityBackend().AddUser("Domain", "User", "Password")); }
        public async Task Start() => await Fixture.StartAsync();
        public async ValueTask DisposeAsync() => await Fixture.DisposeAsync();
    }
    sealed class Client : IAsyncDisposable
    {
        readonly TcpClient tcp = new(); public ulong Mid, Session; public byte[]? Key; public bool Fragment;
        public ushort Dialect = 0x202; public bool Encrypt, Tamper; ulong nonce;
        byte[] CipherKey(bool outbound)
        {
            // MS-SMB2 3.2.5.3.1 / SP800-108 counter mode, 128-bit output.
            var label = Encoding.ASCII.GetBytes("SMB2AESCCM\0"); var context = Encoding.ASCII.GetBytes(outbound ? "ServerIn \0" : "ServerOut\0");
            return HMACSHA256.HashData(Key!, Cat([0, 0, 0, 1], label, [0], context, [0, 0, 0, 128]))[..16];
        }
        byte[] Seal(byte[] packet)
        {
            var transform = new byte[52 + packet.Length]; transform[0] = 0xfd; transform[1] = 0x53; transform[2] = 0x4d; transform[3] = 0x42;
            RawSmb.Put64(transform, 20, ++nonce); RawSmb.Put32(transform, 36, (uint)packet.Length); RawSmb.Put16(transform, 42, 1); RawSmb.Put64(transform, 44, Session);
            using var aes = new AesCcm(CipherKey(true)); aes.Encrypt(transform.AsSpan(20, 11), packet, transform.AsSpan(52), transform.AsSpan(4, 16), transform.AsSpan(20, 32));
            if (Tamper) transform[4] ^= 1; return transform;
        }
        byte[] Unseal(byte[] transform)
        {
            Check.That(transform.Length >= 52 && transform.AsSpan(0, 4).SequenceEqual(new byte[] { 0xfd, 0x53, 0x4d, 0x42 }), "encrypted response transform header");
            Check.Equal(Session, RawSmb.U64(transform, 44), "encrypted response session"); Check.Equal((ushort)1, RawSmb.U16(transform, 42), "AES128 CCM transform algorithm");
            Check.Equal((uint)transform.Length - 52, RawSmb.U32(transform, 36), "encrypted original size"); var packet = new byte[transform.Length - 52];
            using var aes = new AesCcm(CipherKey(false)); aes.Decrypt(transform.AsSpan(20, 11), transform.AsSpan(52), transform.AsSpan(4, 16), packet, transform.AsSpan(20, 32)); return packet;
        }
        public async Task Connect(IPEndPoint endpoint)
        { await tcp.ConnectAsync(endpoint); var negotiate = RawSmb.Negotiate(Mid++); RawSmb.Put16(negotiate, 100, Dialect); if (Dialect >= 0x300) RawSmb.Put32(negotiate, 72, 64); var b = await Exchange(negotiate, 0, 65); Check.Equal(Dialect, RawSmb.U16(b, 68), "selected offered dialect"); Check.That((RawSmb.U16(b, 66) & 2) != 0, "required signing preserved"); }
        public async Task<byte[]> Exchange(byte[] packet, uint status, ushort size, bool sign = false)
        {
            if (sign && !Encrypt) RawSmb.Sign(packet, Key!); var payload = Encrypt ? Seal(packet) : packet; var frame = new byte[4 + payload.Length]; frame[1] = (byte)(payload.Length >> 16); frame[2] = (byte)(payload.Length >> 8); frame[3] = (byte)payload.Length; payload.CopyTo(frame, 4);
            using var timeout = new CancellationTokenSource(Check.Timeout); var stream = tcp.GetStream();
            if (Fragment) { foreach (var b in frame) await stream.WriteAsync(new[] { b }, timeout.Token); } else await stream.WriteAsync(frame, timeout.Token);
            var prefix = new byte[4]; await stream.ReadExactlyAsync(prefix, timeout.Token); Check.Equal((byte)0, prefix[0], "TCP response frame type"); var length = prefix[1] << 16 | prefix[2] << 8 | prefix[3]; Check.That(length is >= 64 and < 1024 * 1024, "bounded SMB frame");
            var result = new byte[length]; await stream.ReadExactlyAsync(result, timeout.Token); if (Encrypt) result = Unseal(result); else if (RawSmb.U16(packet, 12) == 1) Check.That(result[0] == 0xfe, "SESSION_SETUP response must remain plain SMB2 before session-wide encryption"); RawSmb.Response(result, RawSmb.U16(packet, 12), RawSmb.U64(packet, 24), status, size);
            if (sign && !Encrypt && status == 0) { Check.That((RawSmb.U32(result, 16) & 8) != 0, "authenticated response is signed"); var copy = result.ToArray(); var signature = copy.AsSpan(48, 16).ToArray(); copy.AsSpan(48, 16).Clear(); Bytes(signature, HMACSHA256.HashData(Key!, copy)[..16], "independent authenticated response HMAC"); }
            return result;
        }
        public byte[] Echo() { var b = RawSmb.Header(13, 4, Mid++, Session); RawSmb.Put16(b, 64, 4); return b; }
        public async Task<byte[]> Challenge(bool spnego = false, byte[]? initial = null)
        {
            var token = initial ?? Negotiate(); var b = await Exchange(RawSmb.SessionSetup(spnego ? Init(token) : token, Mid++), More, 9); Session = RawSmb.U64(b, 40); Check.That(Session is not 0 and not ulong.MaxValue, "challenge allocates valid session ID");
            var security = RawSmb.Buffer(b, RawSmb.U16(b, 68), RawSmb.U16(b, 70)); if (spnego) { Check.That(security.AsSpan().IndexOf(Convert.FromHexString("a0030a0101")) >= 0, "SPNEGO accept-incomplete"); Check.That(security.AsSpan().IndexOf(NtlmOid) >= 0, "SPNEGO selects NTLM OID"); } var at = security.AsSpan().IndexOf("NTLMSSP\0"u8); Check.That(at >= 0, "SPNEGO/raw challenge carries NTLMSSP"); return security[at..];
        }
        public async Task Login()
        { var challenge = await Challenge(); var auth = Auth(challenge, "raw", Negotiate()); await Exchange(RawSmb.SessionSetup(auth.Token, Mid++, Session), 0, 9); Key = auth.Key; }
        public ValueTask DisposeAsync() { tcp.Dispose(); return ValueTask.CompletedTask; }
    }
    static void Bytes(byte[] expected, byte[] actual, string why) => Check.That(expected.SequenceEqual(actual), why);
    static async Task Authenticate(string mode)
    {
        await using var h = new Host(); await h.Start(); await using var c = new Client(); await c.Connect(h.Fixture.Server.Endpoint);
        var spnego = mode is "spnego" or "spnego-golden-init"; var golden = mode == "spnego-golden-init" ? Convert.FromHexString("4e544c4d5353500001000000978208e2000000000000000000000000000000000a005a290000000f") : null;
        var challenge = await c.Challenge(spnego, golden); var auth = Auth(challenge, mode, Negotiate());
        var success = mode is "raw" or "spnego" or "spnego-golden-init" or "keyexchange" or "mic";
        var status = success ? 0 : mode is "truncated-auth" or "overflow-auth" ? Invalid : LogonFailure;
        var response = await c.Exchange(RawSmb.SessionSetup(spnego ? Continue(auth.Token) : auth.Token, c.Mid++, c.Session), status, 9);
        if (success)
        {
            if (spnego) { var token = RawSmb.Buffer(response, RawSmb.U16(response, 68), RawSmb.U16(response, 70)); Check.That(token.AsSpan().IndexOf(Convert.FromHexString("a0030a0100")) >= 0, "SPNEGO accept-completed"); }
            Check.Equal((ushort)0, RawSmb.U16(response, 66), "not guest or anonymous"); c.Key = auth.Key; await c.Exchange(c.Echo(), 0, 4, true);
            var tree = await c.Exchange(RawSmb.TreeConnect("\\\\localhost\\P0", c.Mid++, c.Session), 0, 16, true);
            var tid = RawSmb.U32(tree, 36); var opened = await c.Exchange(RawSmb.Create("auth-success", false, c.Mid++, c.Session, tid), 0, 89, true);
            await c.Exchange(RawSmb.Close((RawSmb.U64(opened, 128), RawSmb.U64(opened, 136)), c.Mid++, c.Session, tid), 0, 60, true);
        }
        else await c.Exchange(c.Echo(), 0xc0000203, 9);
    }
    static async Task InvalidInitial(string mode)
    {
        await using var h = new Host(); await h.Start(); await using var c = new Client(); await c.Connect(h.Fixture.Server.Endpoint);
        var token = mode switch { "empty" => Array.Empty<byte>(), "garbage" => new byte[] { 1, 2, 3 }, "truncated-spnego" => Init(Negotiate())[..12], _ => Convert.FromHexString("601b06062b0601050502a011300fa00d300b06092a864886f712010202") };
        await c.Exchange(RawSmb.SessionSetup(token, c.Mid++), mode == "unsupported-mechanism" ? LogonFailure : Invalid, 9);
        // A rejected initial token does not prevent a fresh exchange on this TCP channel.
        await c.Login(); await c.Exchange(c.Echo(), 0, 4, true);
    }
    static async Task Integrity(string mode)
    {
        await using var h = new Host(); await h.Start(); await using var c = new Client(); await c.Connect(h.Fixture.Server.Endpoint); await c.Login();
        var tree = await c.Exchange(RawSmb.TreeConnect("\\\\localhost\\P0", c.Mid++, c.Session), 0, 16, true); var tid = RawSmb.U32(tree, 36);
        var packet = RawSmb.Create("must-not-exist", false, c.Mid++, c.Session, tid);
        if (mode != "unsigned") RawSmb.Sign(packet, c.Key!);
        if (mode == "payload") packet[^1] ^= 1;
        if (mode == "signature") packet[48] ^= 1;
        if (mode == "other-session-key") { await using var other = new Client(); await other.Connect(h.Fixture.Server.Endpoint); await other.Login(); RawSmb.Sign(packet, other.Key!); }
        await c.Exchange(packet, AccessDenied, 9);
        Check.Equal(0, h.Fixture.Store.ActiveHandles, "integrity failure cannot execute CREATE");
    }
    static async Task Replay()
    {
        await using var h = new Host(); await h.Start(); await using var a = new Client(); await using var b = new Client(); await a.Connect(h.Fixture.Server.Endpoint); await b.Connect(h.Fixture.Server.Endpoint);
        var ca = await a.Challenge(); var cb = await b.Challenge(); Check.That(!ca.AsSpan(24, 8).SequenceEqual(cb.AsSpan(24, 8)), "independent per-context server challenges");
        var auth = Auth(ca, "raw", Negotiate()); await b.Exchange(RawSmb.SessionSetup(auth.Token, b.Mid++, b.Session), LogonFailure, 9);
        await a.Exchange(RawSmb.SessionSetup(auth.Token, a.Mid++, a.Session), 0, 9); a.Key = auth.Key; await a.Exchange(a.Echo(), 0, 4, true);
    }
    static async Task Logoff()
    {
        await using var h = new Host(); await h.Start(); await using var c = new Client(); await c.Connect(h.Fixture.Server.Endpoint); await c.Login();
        var logoff = RawSmb.Header(2, 4, c.Mid++, c.Session); RawSmb.Put16(logoff, 64, 4); await c.Exchange(logoff, 0, 4, true);
        await c.Exchange(c.Echo(), 0xc0000203, 9, true);
    }
    static async Task Encrypted(bool tamper, bool required = true)
    {
        await using var h = new Host(); if (required) h.Fixture.Server.State.Options.RequireEncryption = true; await h.Start();
        await using var c = new Client { Dialect = 0x302 }; await c.Connect(h.Fixture.Server.Endpoint); await c.Login(); c.Encrypt = true;
        await c.Exchange(c.Echo(), 0, 4);
        if (tamper)
        {
            c.Tamper = true; var disconnected = false;
            try { await c.Exchange(c.Echo(), 0, 4); } catch (IOException) { disconnected = true; }
            Check.That(disconnected, "tampered AEAD tag terminates the transport"); return;
        }
        var tree = await c.Exchange(RawSmb.TreeConnect("\\\\localhost\\P0", c.Mid++, c.Session), 0, 16); var tid = RawSmb.U32(tree, 36);
        var opened = await c.Exchange(RawSmb.Create("encrypted", false, c.Mid++, c.Session, tid), 0, 89); var id = (RawSmb.U64(opened, 128), RawSmb.U64(opened, 136));
        var bytes = "secret payload over encrypted SMB3"u8.ToArray(); var write = await c.Exchange(RawSmb.Write(id, bytes, 0, c.Mid++, c.Session, tid), 0, 17); Check.Equal((uint)bytes.Length, RawSmb.U32(write, 68), "encrypted WRITE count");
        var read = await c.Exchange(RawSmb.Read(id, (uint)bytes.Length, 0, c.Mid++, c.Session, tid), 0, 17); Bytes(bytes, RawSmb.Buffer(read, read[66], RawSmb.U32(read, 68)), "encrypted roundtrip bytes");
        await c.Exchange(RawSmb.Close(id, c.Mid++, c.Session, tid), 0, 60);
    }
    static async Task Fragmented()
    {
        await using var h = new Host(); await h.Start(); await using var c = new Client { Fragment = true }; await c.Connect(h.Fixture.Server.Endpoint); await c.Login(); await c.Exchange(c.Echo(), 0, 4, true);
    }
}
