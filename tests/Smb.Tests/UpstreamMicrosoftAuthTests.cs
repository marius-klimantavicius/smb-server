using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Smb.Auth.Ntlm;
using Smb.Protocol.Enums;
using Smb.Testing;

internal static partial class UpstreamMicrosoftTests
{
    static IEnumerable<(string Name, Func<Task> Run)> AuthCases()
    {
        foreach (var dialect in new ushort[] { 0x202, 0x210, 0x300, 0x302, 0x311 })
        {
            yield return ($"upstream.microsoft.auth.signed-roundtrip-{dialect:x}", () => AuthRoundtrip(dialect));
            if (dialect != 0x202) yield return ($"upstream.microsoft.auth.wrong-signature-{dialect:x}", () => WrongSignature(dialect));
        }
        // Exact SMB202 bad credentials/token/logoff rows are now supplied by
        // UpstreamGoAuthTests and UpstreamSambaTests; do not count them twice.
        foreach (var kind in new[] { "unknown-session", "before-negotiate" })
            yield return ("upstream.microsoft.auth." + kind, () => AuthInvalid(kind));
        foreach (var kind in new[] { "no-context", "encryption-no-preauth", "compression-no-preauth", "encryption-compression-no-preauth", "invalid-hash", "short-context", "duplicate-preauth", "duplicate-encryption", "duplicate-signing", "duplicate-compression", "duplicate-rdma", "empty-signing", "netname", "no-common-dialect", "wildcard-only", "zero-dialects", "repeat-negotiate" })
            yield return ("upstream.microsoft.negotiate." + kind, () => NegotiateCase(kind));
        yield return ("upstream.microsoft.auth.reauthenticate-retains-open", Reauthenticate);
        yield return ("upstream.microsoft.auth.previous-session-different-dialect", PreviousSession);
        foreach (var algorithm in new ushort[] { 0, 2 })
            yield return ($"upstream.microsoft.auth.signing311-{algorithm}", () => SigningAlgorithm(algorithm));
        foreach (var cipher in new ushort[] { 1, 2, 3, 4 })
            yield return ($"upstream.microsoft.auth.encrypted311-{cipher}", () => EncryptedRoundtrip(0x311, cipher));
        yield return ("upstream.microsoft.auth.encrypted300-ccm", () => EncryptedRoundtrip(0x300, 1));
        foreach (var kind in new[] { "valid", "dialect-none", "dialect-other", "guid", "mode", "capabilities", "short-output", "smb311" })
            yield return ("upstream.microsoft.validate-negotiate." + kind, () => ValidateNegotiate(kind));
        foreach (var related in new[] { false, true })
            yield return ($"upstream.microsoft.auth.encrypted-compound-{related}", () => EncryptedCompound(related));
        yield return ("upstream.microsoft.negotiate.all-contexts", AllContexts);
        yield return ("upstream.microsoft.negotiate.no-cipher-overlap", NoCipherOverlap);
        yield return ("upstream.microsoft.auth.multichannel-encrypted", EncryptedChannels);
        yield return ("upstream.microsoft.auth.multichannel-failed-binding-retry", FailedBindingRetry);
        foreach (var global in new[] { false, true })
            yield return ($"upstream.microsoft.auth.encryption-policy-{global}", () => EncryptionPolicy(global));
    }

    // Auth/NtlmAuthentication BVT_NtlmAuth_Success; Negotiate BVT dialects;
    // Signing WrongSessionKey rows. Existing token generation is only the client
    // credential proof; all packets, statuses, signatures and effects are checked
    // at real signed TCP, without inspecting session/manager internals.
    static async Task AuthRoundtrip(ushort dialect)
    {
        await using var host = await UpstreamLocalFixture.StartAsync(); await using var c = await AuthWire.Connect(host.Server.Endpoint);
        await c.Negotiate(dialect); await c.Login();
        var tree = await c.Exchange(RawSmb.TreeConnect("\\\\localhost\\P0", 0, c.Session), 0, true);
        var tid = RawSmb.U32(tree, 36); Check.That(tid != 0, "tree ID allocated to authenticated user");
        var created = await c.Exchange(RawSmb.Create("signed-auth", false, 0, c.Session, tid), 0, true);
        var id = (RawSmb.U64(created, 128), RawSmb.U64(created, 136));
        var written = await c.Exchange(RawSmb.Write(id, [7, 9, 11], 0, 0, c.Session, tid), 0, true);
        Check.Equal(3u, RawSmb.U32(written, 68), "signed authenticated write");
        var read = await c.Exchange(RawSmb.Read(id, 3, 0, 0, c.Session, tid), 0, true);
        Check.That(ReadData(read).SequenceEqual(new byte[] { 7, 9, 11 }), "signed authenticated read");
        await c.Exchange(RawSmb.Close(id, 0, c.Session, tid), 0, true);
    }
    static async Task WrongSignature(ushort dialect)
    {
        await using var host = await UpstreamLocalFixture.StartAsync(); await using var c = await AuthWire.Connect(host.Server.Endpoint);
        await c.Negotiate(dialect); await c.Login();
        await c.Exchange(c.Echo(), 0, true);
        // Pinned upstream Signing.cs corrupts an otherwise correctly signed ECHO.
        // ACCESS_DENIED must be received before an optional transport disconnect.
        await c.Exchange(c.Echo(), Denied, true, corrupt: true);
    }
    static async Task SigningAlgorithm(ushort algorithm)
    {
        await using var host = await UpstreamLocalFixture.StartAsync(); await using var c = await AuthWire.Connect(host.Server.Endpoint);
        await c.Negotiate(0x311, signingAlgorithm: algorithm); await c.Login();
        await c.Exchange(c.Echo(), 0, true); await c.Exchange(c.Echo(), Denied, true, corrupt: true);
    }
    static async Task EncryptedRoundtrip(ushort dialect, ushort cipher)
    {
        await using var host = await UpstreamLocalFixture.StartAsync(); await using var c = await AuthWire.Connect(host.Server.Endpoint);
        await c.Negotiate(dialect, encryptionCipher: cipher); await c.Login();
        var tree = await c.Encrypted(RawSmb.TreeConnect("\\\\localhost\\P0", 0, c.Session)); var tid = RawSmb.U32(tree, 36);
        var created = await c.Encrypted(RawSmb.Create("cipher", false, 0, c.Session, tid)); var id = (RawSmb.U64(created, 128), RawSmb.U64(created, 136));
        var payload = Enumerable.Range(0, 4097).Select(i => (byte)(i * 13)).ToArray();
        var written = await c.Encrypted(RawSmb.Write(id, payload, 0, 0, c.Session, tid)); Check.Equal((uint)payload.Length, RawSmb.U32(written, 68), "encrypted WRITE count");
        var read = await c.Encrypted(RawSmb.Read(id, (uint)payload.Length, 0, 0, c.Session, tid));
        Check.That(ReadData(read).SequenceEqual(payload), "independent AEAD decryption yields exact file bytes");
        await c.Encrypted(RawSmb.Close(id, 0, c.Session, tid));
        Check.That(!c.NonzeroEncryptedSignature, "MS-SMB2 3.3.4.1.1 requires encrypted SMB header signature zero");
    }
    static async Task ValidateNegotiate(string kind)
    {
        await using var host = await UpstreamLocalFixture.StartAsync(); await using var c = await AuthWire.Connect(host.Server.Endpoint);
        var dialect = kind == "smb311" ? (ushort)0x311 : (ushort)0x300; await c.Negotiate(dialect); await c.Login();
        var input = new byte[26]; RawSmb.Put32(input, 0, 4); Convert.FromHexString("00112233445566778899AABBCCDDEEFF").CopyTo(input, 4);
        RawSmb.Put16(input, 20, 3); RawSmb.Put16(input, 22, 1); RawSmb.Put16(input, 24, dialect);
        if (kind == "dialect-none") RawSmb.Put16(input, 24, 0xffff);
        if (kind == "dialect-other") RawSmb.Put16(input, 24, 0x210);
        if (kind == "guid") input[4] ^= 1;
        if (kind == "mode") RawSmb.Put16(input, 20, 1);
        if (kind == "capabilities") RawSmb.Put32(input, 0, 0);
        var request = RawSmb.Header(11, 56 + input.Length, 0, c.Session); RawSmb.Put16(request, 64, 57); RawSmb.Put32(request, 68, 0x140204);
        RawSmb.Put64(request, 72, ulong.MaxValue); RawSmb.Put64(request, 80, ulong.MaxValue); RawSmb.Put32(request, 88, 120); RawSmb.Put32(request, 92, 26);
        RawSmb.Put32(request, 108, kind == "short-output" ? 23u : 24u); RawSmb.Put32(request, 112, 1); input.CopyTo(request, 120);
        if (kind != "valid") { await c.ExpectDisconnect(request); return; }
        var response = await c.Exchange(request, 0, true); Check.Equal(0x140204u, RawSmb.U32(response, 68), "validate IOCTL code");
        Check.Equal(ulong.MaxValue, RawSmb.U64(response, 72), "server control FileId persistent sentinel"); Check.Equal(ulong.MaxValue, RawSmb.U64(response, 80), "server control FileId volatile sentinel");
        Check.Equal(24u, RawSmb.U32(response, 100), "validate response fixed size");
        var data = RawSmb.Buffer(response, (int)RawSmb.U32(response, 96), RawSmb.U32(response, 100));
        Check.Equal(c.ServerCapabilities, RawSmb.U32(data, 0), "validated negotiated server capabilities");
        Check.That(data.AsSpan(4, 16).SequenceEqual(c.ServerGuid), "validated original server GUID");
        Check.Equal((ushort)3, RawSmb.U16(data, 20), "validated required signing mode"); Check.Equal(dialect, RawSmb.U16(data, 22), "validated selected dialect");
    }
    static async Task AllContexts()
    {
        await using var host = await UpstreamLocalFixture.StartAsync(); host.Server.State.Options.EnableCompression = true;
        host.Server.State.Options.CompressionPreference = [SmbCompressionAlgorithm.Lznt1];
        await using var c = await AuthWire.Connect(host.Server.Endpoint); await c.Negotiate(0x311, encryptionCipher: 2, compressionAlgorithm: 1);
        await c.Login(); await c.Exchange(c.Echo(), 0, true);
    }
    static async Task NoCipherOverlap()
    {
        await using var host = await UpstreamLocalFixture.StartAsync(); await using var c = await AuthWire.Connect(host.Server.Endpoint);
        await c.Negotiate(0x311, encryptionCipher: 0xffff, expectedCipher: 0); await c.Login(); await c.Exchange(c.Echo(), 0, true);
    }
    static async Task EncryptedCompound(bool related)
    {
        await using var host = await UpstreamLocalFixture.StartAsync(); await using var c = await AuthWire.Connect(host.Server.Endpoint);
        await c.Negotiate(0x300, encryptionCipher: 1); await c.Login();
        var tree = await c.Encrypted(RawSmb.TreeConnect("\\\\localhost\\P0", 0, c.Session)); var tid = RawSmb.U32(tree, 36);
        var created = await c.Encrypted(RawSmb.Create("compound", false, 0, c.Session, tid)); var id = (RawSmb.U64(created, 128), RawSmb.U64(created, 136));
        var first = RawSmb.Write(id, [1, 2, 3], 0, 0, c.Session, tid); var second = RawSmb.Read(id, 3, 0, 0, c.Session, tid);
        if (related) { RawSmb.Put32(second, 16, 4); RawSmb.Put32(second, 36, uint.MaxValue); RawSmb.Put64(second, 40, ulong.MaxValue); RawSmb.Put64(second, 80, ulong.MaxValue); RawSmb.Put64(second, 88, ulong.MaxValue); }
        var aligned = (first.Length + 7) & ~7; var message = new byte[aligned + second.Length]; RawSmb.Put32(first, 20, (uint)aligned); first.CopyTo(message, 0); second.CopyTo(message, aligned);
        var response = await c.Encrypted(message, compound: true); var next = (int)RawSmb.U32(response, 20);
        Check.That(next >= 80 && (next & 7) == 0 && next + 80 <= response.Length, "encrypted compound response chain bounded");
        Status(response, 0, "compound WRITE"); Check.Equal(3u, RawSmb.U32(response, 68), "compound write count");
        var read = response.AsSpan(next).ToArray(); Status(read, 0, "compound READ"); Check.Equal((ushort)8, RawSmb.U16(read, 12), "READ response command");
        Check.That(ReadData(read).SequenceEqual(new byte[] { 1, 2, 3 }), "encrypted related/unrelated chain observes preceding write");
        await c.Encrypted(RawSmb.Close(id, 0, c.Session, tid));
        Check.That(!c.NonzeroEncryptedSignature, "every encrypted compound SMB header signature is zero");
    }
    static async Task EncryptedChannels()
    {
        await using var host = await UpstreamLocalFixture.StartAsync(); host.Server.State.Options.FeaturePolicy = Smb.Server.SmbFeaturePolicy.MultichannelOnly; host.Server.State.Options.EnableMultichannel = true;
        await using var a = await AuthWire.Connect(host.Server.Endpoint); await a.Negotiate(0x300, encryptionCipher: 1); await a.Login();
        await using var b = await AuthWire.Connect(host.Server.Endpoint); await b.Negotiate(0x300, encryptionCipher: 1); await b.Login(bindTo: a);
        host.Server.State.Options.Shares.Add(new Smb.FileSystem.Share { Name = "ENC", EncryptData = true, FileStore = host.Server.State.Options.Shares.All.Single(s => s.Name == "P0").FileStore });
        var tree = await a.Encrypted(RawSmb.TreeConnect("\\\\localhost\\ENC", 0, a.Session)); var tid = RawSmb.U32(tree, 36);
        var created = await a.Encrypted(RawSmb.Create("channels", false, 0, a.Session, tid)); var id = (RawSmb.U64(created, 128), RawSmb.U64(created, 136));
        await a.Encrypted(RawSmb.Write(id, [4, 5, 6], 0, 0, a.Session, tid));
        await b.Exchange(RawSmb.Read(id, 3, 0, 0, b.Session, tid), Denied, true);
        var response = await b.Encrypted(RawSmb.Read(id, 3, 0, 0, b.Session, tid)); Check.That(ReadData(response).SequenceEqual(new byte[] { 4, 5, 6 }), "encrypted bound channel uses same session and file");
        await b.Encrypted(RawSmb.Close(id, 0, b.Session, tid));
    }
    static async Task FailedBindingRetry()
    {
        await using var host = await UpstreamLocalFixture.StartAsync(); host.Server.State.Options.FeaturePolicy = Smb.Server.SmbFeaturePolicy.MultichannelOnly; host.Server.State.Options.EnableMultichannel = true;
        await using var a = await AuthWire.Connect(host.Server.Endpoint); await a.Negotiate(0x300); await a.Login();
        await using var b = await AuthWire.Connect(host.Server.Endpoint); await b.Negotiate(0x300);
        await b.Login(password: "wrong-fixture-password", finalStatus: 0xc000006d, bindTo: a);
        // MS-SMB2 3.3.5.5.3 removes the established session on terminal
        // GSS error, including a binding exchange with a valid signature.
        await a.Exchange(a.Echo(), 0xc0000203, true);
        await b.Exchange(b.Echo(), 0xc0000203, true);
        var retired = a.Session;
        await a.Login(); Check.That(a.Session != retired, "fresh authentication allocates a new session after terminal binding failure");
        await a.Exchange(a.Echo(), 0, true); await b.Login(bindTo: a); await b.Exchange(b.Echo(), 0, true);
        await b.Login(password: "wrong-fixture-password", finalStatus: 0xc000006d, reauthenticate: true);
        await a.Exchange(a.Echo(), 0xc0000203, true); await b.Exchange(b.Echo(), 0xc0000203, true);
    }
    static async Task EncryptionPolicy(bool global)
    {
        await using var host = await UpstreamLocalFixture.StartAsync();
        if (global) host.Server.State.Options.RequireEncryption = true;
        else host.Server.State.Options.Shares.Add(new Smb.FileSystem.Share { Name = "ENC", EncryptData = true, FileStore = host.Server.State.Options.Shares.All.Single(s => s.Name == "P0").FileStore });
        await using var c = await AuthWire.Connect(host.Server.Endpoint); await c.Negotiate(0x300, encryptionCipher: 1); await c.Login(expectEncryption: global);
        var tree = await c.Encrypted(RawSmb.TreeConnect(global ? "\\\\localhost\\P0" : "\\\\localhost\\ENC", 0, c.Session)); var tid = RawSmb.U32(tree, 36);
        if (!global) Check.That((RawSmb.U32(tree, 68) & 0x8000) != 0, "encrypted share flag advertised");
        await c.Exchange(RawSmb.Create("denied", false, 0, c.Session, tid), Denied, true);
        var created = await c.Encrypted(RawSmb.Create("allowed", false, 0, c.Session, tid)); var id = (RawSmb.U64(created, 128), RawSmb.U64(created, 136));
        await c.Encrypted(RawSmb.Write(id, [9], 0, 0, c.Session, tid));
        var read = await c.Encrypted(RawSmb.Read(id, 1, 0, 0, c.Session, tid)); Check.That(ReadData(read).SequenceEqual(new byte[] { 9 }), "required encryption permits valid protected file workflow");
        await c.Encrypted(RawSmb.Close(id, 0, c.Session, tid));
    }
    static async Task AuthInvalid(string kind)
    {
        await using var host = await UpstreamLocalFixture.StartAsync(); await using var c = await AuthWire.Connect(host.Server.Endpoint);
        if (kind == "before-negotiate")
        {
            await c.Exchange(RawSmb.SessionSetup([], 0), Invalid); return;
        }
        await c.Negotiate(0x202);
        await c.Exchange(RawSmb.SessionSetup(new NtlmClient(HostFixture.Domain, HostFixture.User, HostFixture.Password).BuildNegotiate(), 0, 0x12345678), 0xc0000203);
    }
    static async Task NegotiateCase(string kind)
    {
        await using var host = await UpstreamLocalFixture.StartAsync(); await using var c = await AuthWire.Connect(host.Server.Endpoint);
        var request = AuthWire.NegotiatePacket(0x311);
        if (kind == "repeat-negotiate") { await c.Negotiate(0x202); await c.ExpectDisconnect(RawSmb.Negotiate(), sign: false); return; }
        switch (kind)
        {
            case "no-context": request = RawSmb.Negotiate(); RawSmb.Put16(request, 100, 0x311); break;
            case "encryption-no-preauth": case "compression-no-preauth": case "encryption-compression-no-preauth":
                Array.Resize(ref request, kind == "encryption-compression-no-preauth" ? 138 : 122); request.AsSpan(104).Clear();
                RawSmb.Put16(request, 96, kind == "encryption-compression-no-preauth" ? (ushort)2 : (ushort)1);
                if (kind != "compression-no-preauth") { RawSmb.Put16(request, 104, 2); RawSmb.Put16(request, 106, 4); RawSmb.Put16(request, 112, 1); RawSmb.Put16(request, 114, 2); }
                if (kind != "encryption-no-preauth") { var at = kind == "compression-no-preauth" ? 104 : 120; RawSmb.Put16(request, at, 3); RawSmb.Put16(request, at + 2, 10); RawSmb.Put16(request, at + 8, 1); RawSmb.Put16(request, at + 16, 1); }
                break;
            case "invalid-hash": RawSmb.Put16(request, 116, 0xffff); break;
            case "short-context": RawSmb.Put16(request, 106, 4); break;
            case "duplicate-preauth":
                Array.Resize(ref request, 136); request.AsSpan(104, 16).CopyTo(request.AsSpan(120)); RawSmb.Put16(request, 96, 2); break;
            case "duplicate-encryption": case "duplicate-signing": case "duplicate-compression": case "duplicate-rdma":
                var type = kind switch { "duplicate-encryption" => (ushort)2, "duplicate-signing" => (ushort)8, "duplicate-compression" => (ushort)3, _ => (ushort)7 };
                Array.Resize(ref request, 152); RawSmb.Put16(request, 96, 3);
                RawSmb.Put16(request, 120, type); RawSmb.Put16(request, 122, 8); request.AsSpan(128, 8).Clear(); RawSmb.Put16(request, 128, 1); RawSmb.Put16(request, 130, 1);
                request.AsSpan(120, 16).CopyTo(request.AsSpan(136)); break;
            case "empty-signing": RawSmb.Put16(request, 128, 0); break;
            case "netname":
                var name = System.Text.Encoding.Unicode.GetBytes("localhost"); Array.Resize(ref request, 128 + name.Length);
                RawSmb.Put16(request, 120, 5); RawSmb.Put16(request, 122, (ushort)name.Length); name.CopyTo(request, 128); break;
            case "no-common-dialect": request = RawSmb.Negotiate(); RawSmb.Put16(request, 100, 0xffff); break;
            case "wildcard-only": request = RawSmb.Negotiate(); RawSmb.Put16(request, 100, 0x2ff); break;
            case "zero-dialects": request = RawSmb.Negotiate(); RawSmb.Put16(request, 66, 0); break;
        }
        var expected = kind == "netname" ? 0u : kind is "no-common-dialect" or "wildcard-only" ? 0xc00000bbu : kind == "invalid-hash" ? 0xc05d0000u : Invalid;
        var response = await c.Exchange(request, expected);
        if (kind == "netname") Check.Equal((ushort)0x311, RawSmb.U16(response, 68), "NETNAME context does not change selected dialect");
    }
    static async Task Reauthenticate()
    {
        await using var host = await UpstreamLocalFixture.StartAsync(); await using var c = await AuthWire.Connect(host.Server.Endpoint);
        await c.Negotiate(0x300); await c.Login();
        var response = await c.Exchange(RawSmb.TreeConnect("\\\\localhost\\P0", 0, c.Session), 0, true); var tree = RawSmb.U32(response, 36);
        response = await c.Exchange(RawSmb.Create("reauth", false, 0, c.Session, tree), 0, true); var id = (RawSmb.U64(response, 128), RawSmb.U64(response, 136));
        await c.Exchange(RawSmb.Write(id, [42], 0, 0, c.Session, tree), 0, true);
        await c.Login(reauthenticate: true);
        response = await c.Exchange(RawSmb.Read(id, 1, 0, 0, c.Session, tree), 0, true);
        Check.That(ReadData(response).SequenceEqual(new byte[] { 42 }), "reauthentication preserves open and keys");
    }
    static async Task PreviousSession()
    {
        await using var host = await UpstreamLocalFixture.StartAsync(); await using var a = await AuthWire.Connect(host.Server.Endpoint);
        await a.Negotiate(0x300); await a.Login(); var old = a.Session;
        await using var b = await AuthWire.Connect(host.Server.Endpoint); await b.Negotiate(0x302); await b.Login(finalStatus: 0xc0000203, previousSession: old);
    }

    sealed class AuthWire : IAsyncDisposable
    {
        readonly TcpClient tcp = new(); ulong mid; ushort dialect, signing = 1, cipher; byte[] key = [], encryptKey = [], decryptKey = []; byte[] hash = new byte[64];
        public ulong Session;
        public bool NonzeroEncryptedSignature;
        public bool LastResponseCompressed;
        public uint ServerCapabilities;
        public byte[] ServerGuid = [];
        public static async Task<AuthWire> Connect(IPEndPoint endpoint)
        {
            var c = new AuthWire(); await c.tcp.ConnectAsync(endpoint.Address, endpoint.Port).WaitAsync(Check.Timeout); return c;
        }
        public async Task CloseAndWait()
        {
            // Half-close lets the peer observe EOF and finish channel teardown.
            // Its returned FIN is a public transport barrier; no private server
            // session table or timing retry establishes the retired-ID oracle.
            var stream = tcp.GetStream(); tcp.Client.Shutdown(SocketShutdown.Send); using var timeout = new CancellationTokenSource(Check.Timeout);
            Check.Equal(0, await stream.ReadAsync(new byte[1], timeout.Token), "server closes transport after peer EOF");
        }
        public byte[] Echo() { var b = RawSmb.Header(13, 4, 0, Session); RawSmb.Put16(b, 64, 4); return b; }
        public static byte[] NegotiatePacket(ushort dialect)
        {
            var b = RawSmb.Negotiate(); RawSmb.Put16(b, 68, 3); RawSmb.Put16(b, 100, dialect);
            if (dialect >= 0x210) RawSmb.Put32(b, 72, 4); // LARGE_MTU is explicitly offered.
            if (dialect != 0x311) return b;
            Array.Resize(ref b, 132); RawSmb.Put32(b, 92, 104); RawSmb.Put16(b, 96, 2);
            RawSmb.Put16(b, 104, 1); RawSmb.Put16(b, 106, 6); RawSmb.Put16(b, 112, 1); RawSmb.Put16(b, 116, 1);
            RawSmb.Put16(b, 120, 8); RawSmb.Put16(b, 122, 4); RawSmb.Put16(b, 128, 1); RawSmb.Put16(b, 130, 1); return b;
        }
        public async Task Negotiate(ushort offered, ushort signingAlgorithm = 1, ushort encryptionCipher = 0, ushort compressionAlgorithm = 0, ushort? expectedCipher = null, ushort clientSecurityMode = 3)
        {
            dialect = offered; signing = offered < 0x300 ? (ushort)0 : signingAlgorithm; cipher = encryptionCipher;
            var request = NegotiatePacket(offered);
            RawSmb.Put16(request, 68, clientSecurityMode);
            if (offered == 0x311) RawSmb.Put16(request, 130, signingAlgorithm);
            if (cipher != 0)
            {
                RawSmb.Put32(request, 72, RawSmb.U32(request, 72) | 64);
                if (offered == 0x311)
                {
                    Array.Resize(ref request, 148); RawSmb.Put16(request, 96, 3);
                    RawSmb.Put16(request, 136, 2); RawSmb.Put16(request, 138, 4); RawSmb.Put16(request, 144, 1); RawSmb.Put16(request, 146, cipher);
                }
            }
            if (compressionAlgorithm != 0)
            {
                var at = (request.Length + 7) & ~7; Array.Resize(ref request, at + 18); RawSmb.Put16(request, 96, (ushort)(RawSmb.U16(request, 96) + 1));
                RawSmb.Put16(request, at, 3); RawSmb.Put16(request, at + 2, 10); RawSmb.Put16(request, at + 8, 1); RawSmb.Put16(request, at + 16, compressionAlgorithm);
            }
            var b = await Exchange(request, 0);
            ServerCapabilities = RawSmb.U32(b, 88); ServerGuid = b.AsSpan(72, 16).ToArray();
            Check.Equal(offered, RawSmb.U16(b, 68), "selected exact offered dialect"); Check.That((RawSmb.U16(b, 66) & 3) == 3, "signing enabled and required");
            Check.That(RawSmb.U32(b, 92) >= 65536 && RawSmb.U32(b, 96) >= 65536 && RawSmb.U32(b, 100) >= 65536, "negotiated I/O limits");
            Check.That(RawSmb.U64(b, 72) != 0 || RawSmb.U64(b, 80) != 0, "nonzero server GUID");
            if (offered < 0x300) Check.That((RawSmb.U32(b, 88) & (2u | 8u | 16u | 32u | 64u)) == 0, "SMB3-only capabilities withheld");
            if (offered == 0x311)
            {
                var at = checked((int)RawSmb.U32(b, 124)); var count = RawSmb.U16(b, 70); var preauth = false;
                for (var i = 0; i < count; i++)
                {
                    Check.That(at >= 128 && at + 8 <= b.Length, "negotiate context header bounded"); var len = RawSmb.U16(b, at + 2);
                    Check.That(at + 8 + len <= b.Length, "negotiate context bounded");
                    if (RawSmb.U16(b, at) == 1) { Check.Equal((ushort)1, RawSmb.U16(b, at + 8), "one preauth hash"); Check.Equal((ushort)1, RawSmb.U16(b, at + 12), "SHA512 selected"); preauth = true; }
                    if (RawSmb.U16(b, at) == 8) { Check.Equal((ushort)1, RawSmb.U16(b, at + 8), "one signing algorithm"); Check.Equal(signingAlgorithm, RawSmb.U16(b, at + 10), "offered signing algorithm selected"); }
                    if (RawSmb.U16(b, at) == 2) { Check.Equal((ushort)1, RawSmb.U16(b, at + 8), "one encryption cipher"); Check.Equal(expectedCipher ?? cipher, RawSmb.U16(b, at + 10), "offered encryption cipher selected"); }
                    if (RawSmb.U16(b, at) == 3) { Check.Equal((ushort)1, RawSmb.U16(b, at + 8), "one compression algorithm"); Check.Equal(compressionAlgorithm, RawSmb.U16(b, at + 16), "offered compression algorithm selected"); Check.Equal(0u, RawSmb.U32(b, at + 12), "chained compression is not negotiated"); }
                    at += (8 + len + 7) & ~7;
                }
                Check.That(preauth, "SMB311 returns preauth context");
                if (expectedCipher == 0)
                {
                    var contextAt = (int)RawSmb.U32(b, 124); var found = false;
                    for (var i = 0; i < count; i++) { found |= RawSmb.U16(b, contextAt) == 2; contextAt += (8 + RawSmb.U16(b, contextAt + 2) + 7) & ~7; }
                    Check.That(found, "offered encryption context receives selected cipher zero when no overlap"); cipher = 0;
                }
            }
        }
        public async Task Login(string password = HostFixture.Password, string user = HostFixture.User, uint finalStatus = 0, bool reauthenticate = false, ulong previousSession = 0, AuthWire? bindTo = null, bool expectEncryption = false, byte clientSecurityMode = 3)
        {
            if (bindTo != null) { Session = bindTo.Session; key = bindTo.key; encryptKey = bindTo.encryptKey; decryptKey = bindTo.decryptKey; }
            var ntlm = new NtlmClient(HostFixture.Domain, user, password); var setup = RawSmb.SessionSetup(ntlm.BuildNegotiate(), 0, reauthenticate ? Session : 0);
            if (bindTo != null) { RawSmb.Put64(setup, 40, Session); setup[66] = 1; }
            setup[67] = clientSecurityMode; RawSmb.Put64(setup, 80, previousSession);
            var b = await Exchange(setup, 0xc0000016, reauthenticate || bindTo != null); var sid = RawSmb.U64(b, 40); Check.That(sid != 0, "interim allocates SessionId");
            var token = RawSmb.Buffer(b, RawSmb.U16(b, 68), RawSmb.U16(b, 70));
            Check.That(token.Length >= 48 && token.AsSpan(0, 8).SequenceEqual("NTLMSSP\0"u8) && RawSmb.U32(token, 8) == 2, "NTLM challenge wire message");
            setup = RawSmb.SessionSetup(ntlm.BuildAuthenticate(token), 0, sid); setup[67] = clientSecurityMode; RawSmb.Put64(setup, 80, previousSession);
            if (bindTo != null) setup[66] = 1;
            var bindingKey = bindTo == null ? null : SigningKey(ntlm.ExportedSessionKey);
            b = await Exchange(setup, finalStatus, reauthenticate || bindTo != null, responseSigningKey: finalStatus == 0 ? bindingKey : null);
            if (finalStatus != 0) return;
            Check.Equal(sid, RawSmb.U64(b, 40), "successful SessionId stable"); Check.Equal(expectEncryption ? (ushort)4 : (ushort)0, RawSmb.U16(b, 66), "ordinary non-guest session and encryption policy");
            Session = sid;
            if (bindTo != null) { key = bindingKey!; return; }
            if (reauthenticate) return; // Reauthentication preserves existing session/channel keys.
            if (dialect < 0x300) key = ntlm.ExportedSessionKey;
            else
            {
                key = SigningKey(ntlm.ExportedSessionKey); var keySize = cipher is 3 or 4 ? 32 : 16;
                encryptKey = Kdf(ntlm.ExportedSessionKey, dialect == 0x311 ? "SMBC2SCipherKey\0"u8.ToArray() : "SMB2AESCCM\0"u8.ToArray(), dialect == 0x311 ? hash : "ServerIn \0"u8.ToArray(), keySize);
                decryptKey = Kdf(ntlm.ExportedSessionKey, dialect == 0x311 ? "SMBS2CCipherKey\0"u8.ToArray() : "SMB2AESCCM\0"u8.ToArray(), dialect == 0x311 ? hash : "ServerOut\0"u8.ToArray(), keySize);
            }
        }
        public async Task RejectRetiredBinding(AuthWire old)
        {
            Session = old.Session; key = old.key;
            var request = RawSmb.SessionSetup(new NtlmClient(HostFixture.Domain, HostFixture.User, HostFixture.Password).BuildNegotiate(), 0, Session); request[66] = 1;
            await Exchange(request, 0xc0000203, true);
        }
        public async Task BeginAuthentication()
        {
            var response = await Exchange(RawSmb.SessionSetup(new NtlmClient(HostFixture.Domain, HostFixture.User, HostFixture.Password).BuildNegotiate(), 0), 0xc0000016);
            Session = RawSmb.U64(response, 40);
        }
        public async Task RejectInitialBinding(AuthWire old, uint expected, bool signed, bool inProgress = false)
        {
            Session = old.Session; key = old.key;
            var request = RawSmb.SessionSetup(new NtlmClient(HostFixture.Domain, HostFixture.User, HostFixture.Password).BuildNegotiate(), 0, Session); request[66] = 1;
            if (inProgress) RawSmb.Put32(request, 16, 8); // No established session key yet; state check precedes signature verification.
            await Exchange(request, expected, signed && !inProgress);
        }
        byte[] SigningKey(byte[] sessionKey) => dialect < 0x300 ? sessionKey : Kdf(sessionKey,
            dialect == 0x311 ? "SMBSigningKey\0"u8.ToArray() : "SMB2AESCMAC\0"u8.ToArray(), dialect == 0x311 ? hash : "SmbSign\0"u8.ToArray(), 16);
        static byte[] Kdf(byte[] secret, byte[] label, byte[] context, int length)
        {
            // SP800-108 counter mode: [i]32 || label || 0 || context || [L]32.
            var input = new byte[4 + label.Length + 1 + context.Length + 4]; input[3] = 1; label.CopyTo(input, 4); context.CopyTo(input, 5 + label.Length);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(input.Length - 4), (uint)(length * 8));
            return HMACSHA256.HashData(secret, input)[..length];
        }
        public async Task<byte[]> Encrypted(byte[] message, bool compound = false, ushort compressionAlgorithm = 0)
        {
            var sequence = mid; mid += Math.Max(1u, RawSmb.U16(message, 6)); RawSmb.Put64(message, 24, sequence); var command = RawSmb.U16(message, 12);
            if (compound)
            {
                var next = (int)RawSmb.U32(message, 20); RawSmb.Put64(message, next + 24, mid++);
            }
            if (compressionAlgorithm != 0) message = CompressLiterals(message, compressionAlgorithm, 0);
            var frame = new byte[52 + message.Length]; new byte[] { 0xfd, 0x53, 0x4d, 0x42 }.CopyTo(frame, 0);
            var nonce = RandomNumberGenerator.GetBytes(cipher is 1 or 3 ? 11 : 12); nonce.CopyTo(frame, 20);
            RawSmb.Put32(frame, 36, (uint)message.Length); RawSmb.Put16(frame, 42, 1); RawSmb.Put64(frame, 44, Session);
            if (cipher is 1 or 3) { using var aead = new AesCcm(encryptKey); aead.Encrypt(nonce, message, frame.AsSpan(52), frame.AsSpan(4, 16), frame.AsSpan(20, 32)); }
            else { using var aead = new AesGcm(encryptKey, 16); aead.Encrypt(nonce, message, frame.AsSpan(52), frame.AsSpan(4, 16), frame.AsSpan(20, 32)); }
            using var timeout = new CancellationTokenSource(Check.Timeout); var stream = tcp.GetStream(); var prefix = new byte[4];
            prefix[1] = (byte)(frame.Length >> 16); prefix[2] = (byte)(frame.Length >> 8); prefix[3] = (byte)frame.Length;
            await stream.WriteAsync(prefix, timeout.Token); await stream.WriteAsync(frame, timeout.Token);
            await stream.ReadExactlyAsync(prefix, timeout.Token); var length = prefix[1] << 16 | prefix[2] << 8 | prefix[3];
            Check.That(length is >= 52 and < 2 * 1024 * 1024, "encrypted response bounded"); var response = new byte[length]; await stream.ReadExactlyAsync(response, timeout.Token);
            var plain = DecryptResponse(response);
            if (!compound) RawSmb.Response(plain, command, sequence);
            else { Status(plain, 0, "encrypted compound first status"); Check.Equal(sequence, RawSmb.U64(plain, 24), "encrypted compound first MessageId"); }
            return plain;
        }
        byte[] DecryptResponse(byte[] response)
        {
            Check.That(response.Length >= 52 && response.AsSpan(0, 4).SequenceEqual(new byte[] { 0xfd, 0x53, 0x4d, 0x42 }), "encrypted response protocol marker");
            Check.Equal(Session, RawSmb.U64(response, 44), "transform SessionId"); Check.Equal((ushort)1, RawSmb.U16(response, 42), "transform encrypted flag");
            Check.Equal((uint)(response.Length - 52), RawSmb.U32(response, 36), "transform original size");
            var plain = new byte[response.Length - 52];
            if (cipher is 1 or 3) { using var aead = new AesCcm(decryptKey); aead.Decrypt(response.AsSpan(20, 11), response.AsSpan(52), response.AsSpan(4, 16), plain, response.AsSpan(20, 32)); }
            else { using var aead = new AesGcm(decryptKey, 16); aead.Decrypt(response.AsSpan(20, 12), response.AsSpan(52), response.AsSpan(4, 16), plain, response.AsSpan(20, 32)); }
            LastResponseCompressed = plain[0] == 0xfc; if (LastResponseCompressed) plain = DecodeCompression(plain);
            NonzeroEncryptedSignature |= plain.AsSpan(48, 16).IndexOfAnyExcept((byte)0) != -1;
            return plain;
        }
        public async Task<byte[]> Exchange(byte[] b, uint expected, bool signed = false, bool corrupt = false, ushort compressionAlgorithm = 0, int prefixLength = 0, byte[]? responseSigningKey = null)
        {
            var sequence = mid; mid += Math.Max(1u, RawSmb.U16(b, 6)); RawSmb.Put64(b, 24, sequence);
            if (signed)
            {
                RawSmb.Put32(b, 16, RawSmb.U32(b, 16) | 8); b.AsSpan(48, 16).Clear(); Signature(b).CopyTo(b, 48);
                if (corrupt) b[48] ^= 0x80;
            }
            var cmd = RawSmb.U16(b, 12); if (dialect == 0x311 && cmd is 0 or 1) hash = SHA512.HashData([.. hash, .. b]);
            if (compressionAlgorithm != 0) b = CompressLiterals(b, compressionAlgorithm, prefixLength);
            var frame = new byte[b.Length + 4]; frame[1] = (byte)(b.Length >> 16); frame[2] = (byte)(b.Length >> 8); frame[3] = (byte)b.Length; b.CopyTo(frame, 4);
            using var timeout = new CancellationTokenSource(Check.Timeout); var stream = tcp.GetStream(); await stream.WriteAsync(frame, timeout.Token);
            var prefix = new byte[4]; await stream.ReadExactlyAsync(prefix, timeout.Token); Check.Equal((byte)0, prefix[0], "direct TCP frame type");
            var length = prefix[1] << 16 | prefix[2] << 8 | prefix[3]; Check.That(length is >= 64 and <= 2 * 1024 * 1024, "bounded response frame");
            var response = new byte[length]; await stream.ReadExactlyAsync(response, timeout.Token);
            LastResponseCompressed = response[0] == 0xfc;
            if (LastResponseCompressed) response = DecodeCompression(response);
            else if (response[0] == 0xfd) response = DecryptResponse(response);
            RawSmb.Response(response, cmd, sequence, expected);
            if (dialect == 0x311 && (cmd == 0 || cmd == 1 && expected == 0xc0000016)) hash = SHA512.HashData([.. hash, .. response]);
            if (signed && expected == 0)
            {
                Check.That((RawSmb.U32(response, 16) & 8) != 0, "successful authenticated response signed");
                var signature = response.AsSpan(48, 16).ToArray(); var copy = response.ToArray(); copy.AsSpan(48, 16).Clear();
                var originalKey = key; if (responseSigningKey != null) key = responseSigningKey;
                try { Check.That(signature.SequenceEqual(Signature(copy)), "response signature independently verified with protocol-selected channel key"); }
                finally { key = originalKey; }
            }
            return response;
        }
        public async Task ExpectDisconnect(byte[] request, bool raw = false, bool sign = true)
        {
            if (!raw) { RawSmb.Put64(request, 24, mid++); if (sign) { RawSmb.Put32(request, 16, RawSmb.U32(request, 16) | 8); Signature(request).CopyTo(request, 48); } }
            var frame = new byte[request.Length + 4]; frame[1] = (byte)(request.Length >> 16); frame[2] = (byte)(request.Length >> 8); frame[3] = (byte)request.Length; request.CopyTo(frame, 4);
            using var timeout = new CancellationTokenSource(Check.Timeout); var stream = tcp.GetStream();
            await stream.WriteAsync(frame, timeout.Token);
            try
            {
                var first = new byte[1]; var read = await stream.ReadAsync(first, timeout.Token);
                Check.Equal(0, read, "invalid validate-negotiate MUST terminate transport without response");
            }
            catch (IOException e) when (e.InnerException is SocketException) { /* Connection reset also terminates transport. */ }
        }
        byte[] Signature(byte[] message)
        {
            if (signing == 0) return HMACSHA256.HashData(key, message)[..16];
            if (signing == 2)
            {
                var nonce = new byte[12]; message.AsSpan(24, 8).CopyTo(nonce); if ((RawSmb.U32(message, 16) & 1) != 0) nonce[8] = 1;
                using var gmac = new AesGcm(key, 16); var tag = new byte[16]; gmac.Encrypt(nonce, Array.Empty<byte>(), Array.Empty<byte>(), tag, message); return tag;
            }
            // RFC4493 AES-CMAC, independent of the server's signer.
            using var aes = Aes.Create(); aes.Key = key; var zero = new byte[16];
            var l = aes.EncryptEcb(zero, System.Security.Cryptography.PaddingMode.None); var k1 = Double(l); var k2 = Double(k1);
            var blocks = Math.Max(1, (message.Length + 15) / 16); var last = new byte[16]; var remaining = message.Length - (blocks - 1) * 16;
            message.AsSpan((blocks - 1) * 16, remaining).CopyTo(last); if (remaining < 16) last[remaining] = 0x80;
            var subkey = remaining == 16 ? k1 : k2; for (var i = 0; i < 16; i++) last[i] ^= subkey[i];
            var state = new byte[16];
            for (var block = 0; block < blocks; block++)
            {
                for (var i = 0; i < 16; i++) state[i] ^= block == blocks - 1 ? last[i] : message[block * 16 + i];
                state = aes.EncryptEcb(state, System.Security.Cryptography.PaddingMode.None);
            }
            return state;
        }
        static byte[] Double(byte[] value)
        {
            var result = new byte[16]; for (var i = 0; i < 16; i++) result[i] = (byte)(value[i] << 1 | (i < 15 ? value[i + 1] >> 7 : 0));
            if ((value[0] & 128) != 0) result[15] ^= 0x87; return result;
        }
        public ValueTask DisposeAsync() { tcp.Dispose(); return ValueTask.CompletedTask; }
    }
}
