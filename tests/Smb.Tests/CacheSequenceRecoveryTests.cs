using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.Crypto;
using Smb.FileSystem;
using Smb.Host;
using Smb.Server;
using Smb.Testing;

// Real TCP, independently ordered commands and literal lease states. No cache,
// retained-open or session state is seeded. See MS-SMB2 3.3.4.7, 3.3.5.9.8/.11,
// 3.3.5.22.2. The signing/KDF peer is local to this suite.
internal static partial class CacheSequenceRecoveryTests
{
    public static IEnumerable<(string Name, Func<Task> Run)> Cases()
    {
        foreach (var test in RepairCases()) yield return test;
        foreach (var dialect in new ushort[] { 0x210, 0x300, 0x302, 0x311 })
        {
            foreach (var durable in new[] { false, true })
            {
                yield return ($"cache.sequence.tcp.shared.{dialect:x}.{durable}", () => Shared(dialect, durable));
                yield return ($"cache.sequence.tcp.escalation.{dialect:x}.{durable}", () => Escalation(dialect, durable));
            }
            yield return ($"cache.sequence.tcp.retained-member.{dialect:x}", () => Retained(dialect));
            yield return ($"cache.sequence.tcp.retained-subset-purge.{dialect:x}", () => Retained(dialect, keep: false));
            yield return ($"cache.sequence.tcp.unchanged-epoch.{dialect:x}", () => Epoch(dialect));
        }
    }
    sealed class Fixture : IAsyncDisposable
    {
        internal readonly P7cTests.Root Root = new();
        internal readonly SmbServer Server;
        internal SmbServerOptions Options { get; private set; } = null!;
        internal Fixture(bool durable = true)
        {
            Server = SmbServerBuilder.Create().WithEndpoint(IPAddress.Loopback, 0)
                .UseAuthentication(new NtlmSpnegoNegotiator(new InMemoryIdentityBackend()
                    .AddUser(HostFixture.Domain, HostFixture.User, HostFixture.Password)))
                .AddShare(new Share { Name = "P0", FileStore = Root.Store() })
                .Configure(o => { Options = o; o.FeaturePolicy = durable ? SmbFeaturePolicy.Durable : SmbFeaturePolicy.Caching;
                    o.DurableHandleTimeout = TimeSpan.FromMinutes(2); o.OplockBreakTimeout = TimeSpan.FromMinutes(2); }).Build();
        }
        internal async Task<Peer> Connect(ushort dialect, Guid client)
        { var peer = new Peer(); await peer.Login(Server.Endpoint, dialect, client); return peer; }
        public async ValueTask DisposeAsync()
        { await Server.StopAsync(TimeSpan.Zero).WaitAsync(Check.Timeout); await Server.DisposeAsync(); Root.Dispose(); }
    }
    static byte[] Lease(ushort dialect, uint state, ulong key = 1, uint disposition = 1, Guid? durable = null)
    {
        var b = RawSmb.Create("file", false, 0, 0, 0); RawSmb.Put32(b, 100, disposition); b[67] = 255;
        if (durable is { } guid)
        {
            var data = new byte[dialect < 0x300 ? 16 : 32];
            if (dialect >= 0x300) { RawSmb.Put32(data, 0, 120000); guid.ToByteArray().CopyTo(data, 16); }
            b = P7cTests.Context(b, dialect < 0x300 ? "DHnQ" : "DH2Q", data);
        }
        var lease = new byte[dialect < 0x300 ? 32 : 52]; RawSmb.Put64(lease, 0, key); RawSmb.Put64(lease, 8, ~key); RawSmb.Put32(lease, 16, state);
        if (lease.Length == 52) RawSmb.Put16(lease, 48, 19);
        return P7cTests.Context(b, "RqLs", lease);
    }
    static byte[] Context(byte[] b, string name = "RqLs")
    {
        int at = (int)RawSmb.U32(b, 144), end = at + (int)RawSmb.U32(b, 148);
        while (at >= 152 && at + 16 <= end && end <= b.Length)
        {
            if (Encoding.ASCII.GetString(b, at + RawSmb.U16(b, at + 4), RawSmb.U16(b, at + 6)) == name)
                return RawSmb.Buffer(b, at + RawSmb.U16(b, at + 10), RawSmb.U32(b, at + 12));
            var next = (int)RawSmb.U32(b, at); if (next == 0) break; Check.That(next >= 16 && next % 8 == 0, "bounded response contexts"); at += next;
        }
        throw new InvalidOperationException("missing " + name);
    }
    static (ulong P, ulong V) Id(byte[] b) { Status(b, 0, "CREATE"); return (RawSmb.U64(b, 128), RawSmb.U64(b, 136)); }
    static void Status(byte[] b, uint status, string why) => Check.Equal(status, RawSmb.U32(b, 8), why);
    static void Grant(byte[] b, uint state) => Check.Equal(state, RawSmb.U32(Context(b), 16), "granted lease state");
    static byte[] Ack(byte[] notification, uint state)
    { var b = RawSmb.Header(18, 36, 0); RawSmb.Put16(b, 64, 36); notification.AsSpan(72, 16).CopyTo(b.AsSpan(72)); RawSmb.Put32(b, 88, state); return b; }
    static async Task<byte[]> Begin(Peer peer, byte[] b)
    { peer.Route(b); peer.Sign(b); await peer.Send(b); return b; }
    static async Task<byte[]> Reply(Peer peer, byte[] request, uint status = 0)
    {
        var b = await peer.Receive(); Check.Equal(RawSmb.U64(request, 24), RawSmb.U64(b, 24), "ordered response MessageId");
        Check.Equal(RawSmb.U16(request, 12), RawSmb.U16(b, 12), "ordered response command"); Status(b, status, "ordered response status");
        // MS-SMB2 3.3.4.1.1 excludes asynchronous interim replies from the
        // signed-response recommendation; final replies still must verify.
        if (status != 0x103 || (RawSmb.U32(b, 16) & 8) != 0) Peer.Signature(b, peer.ChannelKey, peer.Dialect);
        return b;
    }
    static async Task<byte[]> Notice(Peer peer, uint from, uint to, ulong key = 1)
    {
        var b = await peer.Notification(); Check.Equal((ushort)18, RawSmb.U16(b, 12), "lease notification command");
        Check.Equal(ulong.MaxValue, RawSmb.U64(b, 24), "unsolicited MessageId"); Check.Equal((ushort)44, RawSmb.U16(b, 64), "lease notification structure");
        Check.Equal(0ul, RawSmb.U64(b, 40), "notification SessionId"); Check.Equal(0u, RawSmb.U32(b, 36), "notification TreeId");
        Check.Equal(key, RawSmb.U64(b, 72), "notification key"); Check.Equal(from, RawSmb.U32(b, 88), "notification current state");
        Check.Equal(to, RawSmb.U32(b, 92), "notification target state"); Check.Equal(from == 1 ? 0u : 1u, RawSmb.U32(b, 68), "ACK_REQUIRED");
        // MS-SMB2 3.3.4.7 permits unsigned notifications. Signed notifications,
        // when present, must still verify; every solicited response is verified.
        if ((RawSmb.U32(b, 16) & 8) != 0) Peer.Signature(b, peer.ChannelKey, peer.Dialect);
        return b;
    }
    static async Task Shared(ushort dialect, bool durable)
    {
        await using var f = new Fixture(durable); await f.Server.StartAsync(); var client = Guid.NewGuid();
        await using var a = await f.Connect(dialect, client); await using var b = await f.Connect(dialect, client);
        var first = await a.Exchange(Lease(dialect, 1, disposition: 3)); var owner = Id(first); Grant(first, 1);
        var upgraded = await b.Exchange(Lease(dialect, 7)); var member = Id(upgraded); Grant(upgraded, 7);
        await b.Exchange(RawSmb.Close(member, 0, 0, 0));
        Console.WriteLine("TRACE shared: R->RWH member closed; foreign CREATE sent");
        var request = await Begin(b, Lease(dialect, 1, 2)); var pending = await Reply(b, request, 0x103);
        var notice = await Notice(a, 7, 3); Console.WriteLine("TRACE shared: RWH->RH break before foreign CREATE final");
        await a.Exchange(Ack(notice, 7), 0xc00000d0); // Invalid ACK cannot consume the outstanding break.
        var same = await a.Exchange(Lease(dialect, 7)); Grant(same, 7); Check.Equal(2u, RawSmb.U32(Context(same), 20), "invalid ACK preserves BREAK_IN_PROGRESS");
        await a.Exchange(RawSmb.Close(Id(same), 0, 0, 0)); await a.Exchange(Ack(notice, 1));
        var foreign = await Reply(b, request); Grant(foreign, 1); var peerId = Id(foreign);
        Check.Equal(RawSmb.U64(pending, 32), RawSmb.U64(foreign, 32), "final AsyncId");
        var retained = await a.Exchange(Lease(dialect, 0)); Grant(retained, 1); Check.Equal(0u, RawSmb.U32(Context(retained), 20), "subset ACK clears breaking");
        await a.Exchange(RawSmb.Close(Id(retained), 0, 0, 0));
        var bytes = "ordered cross-session data"u8.ToArray(); var write = await Begin(a, RawSmb.Write(owner, bytes, 0, 0, 0, 0));
        await Notice(b, 1, 0, 2); await Reply(a, write); // READ invalidation has no ACK.
        write = await Begin(b, RawSmb.Write(peerId, bytes, 0, 0, 0, 0)); var second = await Notice(a, 1, 0); await Reply(b, write);
        await a.Exchange(Ack(second, 0), 0xc0000001);
        var read = await a.Exchange(RawSmb.Read(owner, (uint)bytes.Length, 0, 0, 0, 0));
        Check.That(bytes.SequenceEqual(RawSmb.Buffer(read, read[66], RawSmb.U32(read, 68))), "coherent bytes after alternating writes");
        await a.Exchange(RawSmb.Close(owner, 0, 0, 0)); await b.Exchange(RawSmb.Close(peerId, 0, 0, 0));
    }
    static async Task Escalation(ushort dialect, bool durable)
    {
        await using var f = new Fixture(durable); await f.Server.StartAsync();
        await using var a = await f.Connect(dialect, Guid.NewGuid()); await using var b = await f.Connect(dialect, Guid.NewGuid());
        await using var c = await f.Connect(dialect, Guid.NewGuid());
        var first = await a.Exchange(Lease(dialect, 7, disposition: 3)); var owner = Id(first); Grant(first, 7);
        var ordinary = await Begin(b, RawSmb.Create("file", false, 0, 0, 0)); await Reply(b, ordinary, 0x103);
        var notice = await Notice(a, 7, 3);
        var overwrite = RawSmb.Create("file", false, 0, 0, 0); RawSmb.Put32(overwrite, 100, 4);
        await Begin(c, overwrite); await Reply(c, overwrite, 0x103);
        var member = await a.Exchange(Lease(dialect, 7)); Grant(member, 7); Check.Equal(2u, RawSmb.U32(Context(member), 20), "queued conflict preserves common breaking state");
        await a.Exchange(RawSmb.Close(Id(member), 0, 0, 0)); await a.Exchange(Ack(notice, 3));
        var second = await Notice(a, 3, 1); if (dialect >= 0x300) Check.Equal((ushort)(RawSmb.U16(notice, 66) + 1), RawSmb.U16(second, 66), "new break increments epoch");
        await a.Exchange(Ack(second, 3), 0xc00000d0); await a.Exchange(Ack(second, 1));
        var third = await Notice(a, 1, 0);
        if (dialect >= 0x300) Check.Equal((ushort)(RawSmb.U16(second, 66) + 1), RawSmb.U16(third, 66), "no-ACK invalidation advances epoch");
        var opened = Id(await Reply(b, ordinary)); var truncated = Id(await Reply(c, overwrite));
        await a.Exchange(RawSmb.Read(owner, 1, 0, 0, 0, 0), 0xc0000011);
        var current = await a.Exchange(Lease(dialect, 0)); Grant(current, 0); Check.Equal(0u, RawSmb.U32(Context(current), 20), "no break remains after both creates");
        await a.Exchange(RawSmb.Close(Id(current), 0, 0, 0)); await a.Exchange(RawSmb.Close(owner, 0, 0, 0));
        await b.Exchange(RawSmb.Close(opened, 0, 0, 0)); await c.Exchange(RawSmb.Close(truncated, 0, 0, 0));
    }
    static async Task Retained(ushort dialect, bool keep = true)
    {
        await using var f = new Fixture(); await f.Server.StartAsync(); var client = Guid.NewGuid(); var guid = Guid.NewGuid();
        await using var a = await f.Connect(dialect, client); await using var b = await f.Connect(dialect, client);
        await using var c = await f.Connect(dialect, Guid.NewGuid());
        var first = await a.Exchange(Lease(dialect, 7, disposition: 3, durable: guid)); var original = Id(first);
        Context(first, dialect < 0x300 ? "DHnQ" : "DH2Q"); var live = await b.Exchange(Lease(dialect, 7)); var member = Id(live); Grant(live, 7);
        await a.Exchange(RawSmb.Write(original, "durable shared bytes"u8.ToArray(), 0, 0, 0, 0)); var oldSession = a.Session; await a.DisposeAsync();
        using (var timeout = new CancellationTokenSource(Check.Timeout))
            while (f.Server.State.SessionGlobalList.ContainsKey(oldSession)) await Task.Delay(1, timeout.Token);
        var foreign = await Begin(c, Lease(dialect, 3, 2)); await Reply(c, foreign, 0x103); var notice = await Notice(b, 7, 3);
        await b.Exchange(Ack(notice, keep ? 3u : 0u)); var other = Id(await Reply(c, foreign));
        await using var recovered = await f.Connect(dialect, client);
        var data = new byte[dialect < 0x300 ? 16 : 36]; RawSmb.Put64(data, 0, original.P); RawSmb.Put64(data, 8, ulong.MaxValue);
        if (dialect >= 0x300) guid.ToByteArray().CopyTo(data, 16);
        var reconnect = P7cTests.Context(Lease(dialect, 3), dialect < 0x300 ? "DHnC" : "DH2C", data);
        if (!keep)
        {
            await recovered.Exchange(reconnect, 0xc0000034);
            var fresh = RawSmb.Create("file", false, 0, 0, 0); RawSmb.Put32(fresh, 96, 0);
            // Closing the live peers leaves no disconnected share reservation.
            await b.Exchange(RawSmb.Close(member, 0, 0, 0)); await c.Exchange(RawSmb.Close(other, 0, 0, 0));
            var exclusive = Id(await recovered.Exchange(fresh)); await recovered.Exchange(RawSmb.Close(exclusive, 0, 0, 0)); return;
        }
        Console.WriteLine("TRACE retained: live member ACKed RH; reconnect retained durable member");
        var restored = await recovered.Exchange(reconnect); var id = Id(restored); Check.Equal(original.P, id.P, "shared grant retained original durable FileId"); Grant(restored, 3);
        var read = await recovered.Exchange(RawSmb.Read(id, (uint)"durable shared bytes"u8.Length, 0, 0, 0, 0)); Check.That("durable shared bytes"u8.SequenceEqual(RawSmb.Buffer(read, read[66], RawSmb.U32(read, 68))), "retained shared bytes");
        await recovered.Exchange(RawSmb.Close(id, 0, 0, 0)); await b.Exchange(RawSmb.Close(member, 0, 0, 0)); await c.Exchange(RawSmb.Close(other, 0, 0, 0));
    }
    static async Task Epoch(ushort dialect)
    {
        await using var f = new Fixture(); await f.Server.StartAsync(); await using var a = await f.Connect(dialect, Guid.NewGuid());
        var first = await a.Exchange(Lease(dialect, 3, disposition: 3)); var initial = Context(first); var same = await a.Exchange(Lease(dialect, 3));
        if (dialect >= 0x300) Check.Equal(RawSmb.U16(initial, 48), RawSmb.U16(Context(same), 48), "unchanged lease does not increment epoch");
        await a.Exchange(RawSmb.Close(Id(same), 0, 0, 0)); await a.Exchange(RawSmb.Close(Id(first), 0, 0, 0));
    }
    sealed class Peer : IAsyncDisposable
    {
        TcpClient client = new(); byte[] preauth = new byte[64]; ulong mid;
        public ulong Session; public uint Tree; public ushort Dialect; public byte[] SessionKey = [], ChannelKey = [];
        readonly Queue<byte[]> notifications = new();
        public Task<byte[]> Notification() => notifications.TryDequeue(out var notice) ? Task.FromResult(notice) : Receive();
        async Task<byte[]> ReceiveReply()
        {
            while (true)
            {
                var response = await Receive();
                // Unsolicited breaks can precede the ACK response that released
                // a queued operation. Preserve them for Notice's full assertions.
                if (RawSmb.U16(response, 12) == 18 && RawSmb.U64(response, 24) == ulong.MaxValue) notifications.Enqueue(response);
                else return response;
            }
        }
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
        public async Task<byte[]> Exchange(byte[] b, uint status = 0, bool sessionSetup = false)
        {
            Route(b, sessionSetup); Sign(b); await Send(b); var response = await ReceiveReply();
            Check.Equal(RawSmb.U64(b, 24), RawSmb.U64(response, 24), "response MessageId");
            Check.Equal(RawSmb.U16(b, 12), RawSmb.U16(response, 12), "response command"); Check.Equal(status, RawSmb.U32(response, 8), "TCP response status"); if (ChannelKey.Length != 0 && status != 0xc0000203) Signature(response, ChannelKey, Dialect); return response;
        }
        public async Task Negotiate(IPEndPoint endpoint, ushort dialect, Guid clientGuid)
        {
            using var timeout = new CancellationTokenSource(Check.Timeout); await client.ConnectAsync(endpoint, timeout.Token); Dialect = dialect;
            var b = RawSmb.Negotiate(); RawSmb.Put16(b, 100, dialect); RawSmb.Put32(b, 72, 8);
            if (dialect == 0x311)
            {
                Array.Resize(ref b, 132); RawSmb.Put32(b, 92, 104); RawSmb.Put16(b, 96, 2);
                RawSmb.Put16(b, 104, 1); RawSmb.Put16(b, 106, 6); RawSmb.Put16(b, 112, 1); RawSmb.Put16(b, 116, 1);
                RawSmb.Put16(b, 120, 8); RawSmb.Put16(b, 122, 4); RawSmb.Put16(b, 128, 1); RawSmb.Put16(b, 130, 1);
            }
            clientGuid.ToByteArray().CopyTo(b, 76); var response = await Exchange(b); Check.Equal(dialect, RawSmb.U16(response, 68), "actual negotiated dialect");
            Check.That((RawSmb.U16(response, 66) & 2) != 0, "required signing retained");
            if (dialect == 0x311) { Append(b); Append(response); }
        }
        void Append(byte[] b) => preauth = SHA512.HashData(preauth.Concat(b).ToArray());
        byte[] Key(NtlmClient ntlm)
        {
            if (Dialect < 0x300) return ntlm.ExportedSessionKey;
            var label = Encoding.ASCII.GetBytes(Dialect == 0x311 ? "SMBSigningKey\0" : "SMB2AESCMAC\0");
            var context = Dialect == 0x311 ? preauth : "SmbSign"u8.ToArray().Concat(new byte[] { 0 }).ToArray();
            var input = new byte[4 + label.Length + 1 + context.Length + 4]; input[3] = 1;
            label.CopyTo(input, 4); context.CopyTo(input, 5 + label.Length); input[^1] = 128;
            return HMACSHA256.HashData(ntlm.ExportedSessionKey, input)[..16];
        }
        public static void Signature(byte[] b, byte[] key, ushort dialect)
        {
            Check.That((RawSmb.U32(b, 16) & 8) != 0, "signed TCP response"); var copy = b.ToArray(); copy.AsSpan(48, 16).Clear();
            Check.That((dialect < 0x300 ? HMACSHA256.HashData(key, copy)[..16] : AesCmac.Compute(key, copy)).SequenceEqual(b.AsSpan(48, 16).ToArray()), "independently derived key verifies signature");
        }
        public async Task Login(IPEndPoint endpoint, ushort dialect, Guid clientGuid, ulong previous = 0, string? user = null)
        {
            await Negotiate(endpoint, dialect, clientGuid); var ntlm = new NtlmClient(HostFixture.Domain, user ?? HostFixture.User, HostFixture.Password);
            var b = RawSmb.SessionSetup(ntlm.BuildNegotiate(), 0); RawSmb.Put64(b, 80, previous); var challenge = await Exchange(b, 0xc0000016, true); Session = RawSmb.U64(challenge, 40);
            if (dialect == 0x311) { Append(b); Append(challenge); }
            b = RawSmb.SessionSetup(ntlm.BuildAuthenticate(RawSmb.Buffer(challenge, RawSmb.U16(challenge, 68), RawSmb.U16(challenge, 70))), 0, Session);
            RawSmb.Put64(b, 80, previous); var success = await Exchange(b, sessionSetup: true); if (dialect == 0x311) Append(b);
            SessionKey = ChannelKey = Key(ntlm); Signature(success, SessionKey, dialect);
            var tree = await Exchange(RawSmb.TreeConnect("\\\\localhost\\P0", 0, Session)); Tree = RawSmb.U32(tree, 36); Signature(tree, ChannelKey, dialect);
        }
        public async Task ReconnectTransport(IPEndPoint endpoint, ushort dialect, Guid clientGuid)
        { client = new TcpClient(); mid = 0; Session = 0; Tree = 0; ChannelKey = []; SessionKey = []; preauth = new byte[64]; await Login(endpoint, dialect, clientGuid); }
        public ValueTask DisposeAsync() { client.Dispose(); Check.Equal(0, notifications.Count, "all buffered notifications were independently checked"); return ValueTask.CompletedTask; }
    }
}
