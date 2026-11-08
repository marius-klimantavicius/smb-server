using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Channels;
using System.Net.Sockets;
using Smb.Auth.Ntlm;
using Smb.Crypto;
using Smb.Protocol.Enums;
using Smb.Server;
using Smb.Server.State;
using Smb.Testing;

// Public SMB contracts derived from Samba lease/oplock/durable workflows and
// current MS-SMB2. No cache, lock, recovery or backend state is seeded or queried.
internal static class UpstreamCacheRepairTests
{
    const uint Ok = 0, Pending = 0x103, Missing = 0xc0000034;
    const uint Access = 0x0013019f;
    static readonly byte[] Bytes = "cache lifetime regression"u8.ToArray();
    public static IEnumerable<(string Name, Func<Task> Run)> Cases()
    {
        foreach (var operation in new[] { "write", "lock" })
            yield return ($"upstream.cache-repair.level-II.self-{operation}", () => LevelII(operation));
        foreach (var v2 in new[] { false, true })
        {
            yield return ($"upstream.cache-repair.lease.cross-session.{v2}", () => CrossSession(v2));
            yield return ($"upstream.cache-repair.lease.pending-member.{v2}", () => PendingMember(v2));
            yield return ($"upstream.cache-repair.lease.last-live-member.{v2}", () => LastLiveMember(v2));
            yield return ($"upstream.cache-repair.lease.replaced-path.{v2}", () => ReplacedPath(v2));
        }
        foreach (var access in new uint[] { 0x80, 0x100, 0x100180 })
            yield return ($"upstream.cache-repair.stat.{access:x}", () => Stat(access));
        foreach (var v1 in new[] { false, true })
            foreach (var leased in new[] { false, true })
                yield return ($"upstream.cache-repair.durable.guid-lock-position.{v1}.{leased}", () => Durable(v1, leased));
        foreach (var high in new[] { false, true })
            yield return ($"upstream.cache-repair.unicode.no-replacement-alias.{high}", () => InvalidUnicodeAlias(high));
        yield return ("upstream.cache-repair.unicode.valid-pair-and-replacement", ValidUnicode);
        yield return ("upstream.cache-repair.ioctl.missing-open", MissingIoctlOpen);
        foreach (var layout in new[] { "packed-64", "empty-offsets", "header-lm", "header-workstation", "short-lm", "odd-workstation" })
            yield return ($"upstream.cache-repair.auth.layout.{layout}", () => AuthenticateLayout(layout));
    }
    sealed class Peer
    {
        public required SmbConnection Connection;
        public required SmbSession Session;
        public required uint Tree;
        public readonly ConcurrentQueue<byte[]> Sent = new();
        readonly Channel<byte[]> inbox = Channel.CreateUnbounded<byte[]>();
        long mid;
        public void Attach()
        {
            Connection.SendRawAsync = (b, _) =>
            {
                var copy = b.ToArray(); Sent.Enqueue(copy); inbox.Writer.TryWrite(copy);
                Connection.ResponseSent(b); return Task.CompletedTask;
            };
        }
        public async Task<byte[]> Receive(Func<byte[], bool> predicate)
        {
            using var timeout = new CancellationTokenSource(Check.Timeout);
            while (await inbox.Reader.WaitToReadAsync(timeout.Token))
                while (inbox.Reader.TryRead(out var b)) if (predicate(b)) return b;
            throw new InvalidOperationException("response channel closed");
        }
        public async Task<byte[]> Send(Fixture f, byte[] b)
        {
            RawSmb.Put64(b, 24, (ulong)Interlocked.Increment(ref mid));
            RawSmb.Put64(b, 40, Session.SessionId); RawSmb.Put32(b, 36, Tree);
            RawSmb.Put32(b, 16, RawSmb.U32(b, 16) | 8);
            Smb2Signer.SignInPlace(SmbSigningAlgorithmId.AesCmac, Session.SigningKey, b, RawSmb.U64(b, 24), false, false);
            var response = await f.D.Dispatcher.ProcessMessageAsync(Connection, b);
            Connection.ResponseSent(response); return response;
        }
        public Task<byte[]> Final(byte[] interim) => Receive(b => RawSmb.U64(b, 24) == RawSmb.U64(interim, 24) &&
            (RawSmb.U32(b, 16) & 2) != 0 && RawSmb.U64(b, 32) == RawSmb.U64(interim, 32) && RawSmb.U32(b, 8) != Pending);
        public async Task<byte[]> Complete(Fixture f, byte[] request)
        {
            var response = await Send(f, request);
            return RawSmb.U32(response, 8) == Pending ? await Final(response) : response;
        }
    }
    sealed class Fixture : IAsyncDisposable
    {
        public readonly P7cTests.Root Root = new();
        public readonly P2Tests.Direct D;
        public readonly Peer A;
        public Fixture(bool durable = false)
        {
            D = new P2Tests.Direct(Root.Store()); D.Options.FeaturePolicy = durable ? SmbFeaturePolicy.Durable : SmbFeaturePolicy.Caching;
            D.Options.OplockBreakTimeout = TimeSpan.FromMinutes(2);
            D.Connection.Dialect = SmbDialect.Smb300; D.Connection.ServerCapabilities |= Smb2Capabilities.Leasing;
            D.Connection.ClientGuid = Guid.NewGuid().ToByteArray();
            D.Session.SigningKey = SHA256.HashData("cache owner"u8)[..16];
            D.Session.TryAttachChannel(new SmbChannel { Connection = D.Connection, SigningKey = D.Session.SigningKey });
            A = new Peer { Connection = D.Connection, Session = D.Session, Tree = 42 }; A.Attach();
        }
        public Peer Other(bool sameClient = true)
        {
            var c = D.Channel(); c.Dialect = SmbDialect.Smb300; c.ServerCapabilities = D.Connection.ServerCapabilities;
            c.ClientGuid = sameClient ? D.Connection.ClientGuid.ToArray() : Guid.NewGuid().ToByteArray();
            var sid = (ulong)D.State.Connections.Count + 1;
            var s = new SmbSession { SessionId = sid, SessionGlobalId = sid, Connection = c, State = SessionState.Valid,
                SigningRequired = true, SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("cache peer " + sid))[..16], SessionKey = new byte[16], Identity = D.Session.Identity };
            c.Sessions.TryAdd(sid, s); D.State.Connections.TryAdd(c.ConnectionId, c); D.State.SessionGlobalList.TryAdd(sid, s);
            s.TryAttachChannel(new SmbChannel { Connection = c, SigningKey = s.SigningKey }); D.Options.Metrics.OnAuthenticationSucceeded();
            s.TreeConnects.TryAdd(43, new SmbTreeConnect { Session = s, TreeId = 43, Share = D.Tree.Share, MaximalAccess = 0x1f01ff }); D.Options.Metrics.OnTreeConnected();
            var peer = new Peer { Connection = c, Session = s, Tree = 43 }; peer.Attach(); return peer;
        }
        public async ValueTask DisposeAsync()
        {
            foreach (var c in D.State.Connections.Values.ToArray()) await D.Dispatcher.OnConnectionClosedAsync(c, Smb2Dispatcher.CloseReason.Shutdown);
            await D.Dispatcher.CloseRetainedHandlesAsync(); Root.Dispose();
        }
    }
    static void Status(byte[] b, uint status, string phase) => Check.Equal(status, RawSmb.U32(b, 8), phase);
    static (ulong P, ulong V) Id(byte[] b) { Status(b, Ok, "CREATE"); return (RawSmb.U64(b, 128), RawSmb.U64(b, 136)); }
    static byte[] Create(uint disposition = 1, uint access = Access, byte level = 0)
    {
        var b = RawSmb.Create("file", false, 0, 0, 0); b[67] = level;
        RawSmb.Put32(b, 88, access); RawSmb.Put32(b, 96, 7); RawSmb.Put32(b, 100, disposition); return b;
    }
    static byte[] Lease(byte[] b, uint state = 7, ulong key = 1, bool v2 = false)
    {
        b[67] = 255; var data = new byte[v2 ? 52 : 32]; RawSmb.Put64(data, 0, key); RawSmb.Put64(data, 8, ~key); RawSmb.Put32(data, 16, state);
        if (v2) RawSmb.Put16(data, 48, 17); return P7cTests.Context(b, "RqLs", data);
    }
    static byte[] LeaseContext(byte[] response)
    {
        Status(response, Ok, "lease CREATE"); var at = (int)RawSmb.U32(response, 144); var end = at + (int)RawSmb.U32(response, 148);
        while (at > 0 && at + 16 <= end && end <= response.Length)
        {
            if (Encoding.ASCII.GetString(response, at + RawSmb.U16(response, at + 4), RawSmb.U16(response, at + 6)) == "RqLs")
                return RawSmb.Buffer(response, at + RawSmb.U16(response, at + 10), RawSmb.U32(response, at + 12));
            var next = (int)RawSmb.U32(response, at); if (next == 0) break; at += next;
        }
        throw new InvalidOperationException("missing lease response");
    }
    static byte[] Ack(byte[] notification, uint? state = null)
    {
        var b = RawSmb.Header(18, 36, 0, 0, 0); RawSmb.Put16(b, 64, 36);
        notification.AsSpan(72, 16).CopyTo(b.AsSpan(72)); RawSmb.Put32(b, 88, state ?? RawSmb.U32(notification, 92)); return b;
    }
    static byte[] Lock((ulong P, ulong V) id, uint flags = 18)
    {
        var b = RawSmb.Header(10, 48, 0, 0, 0); RawSmb.Put16(b, 64, 48); RawSmb.Put16(b, 66, 1);
        RawSmb.Put64(b, 72, id.P); RawSmb.Put64(b, 80, id.V); RawSmb.Put64(b, 88, 0); RawSmb.Put64(b, 96, 1); RawSmb.Put32(b, 104, flags); return b;
    }
    static byte[] Query((ulong P, ulong V) id, byte cls)
    {
        var b = RawSmb.Header(16, 40, 0, 0, 0); RawSmb.Put16(b, 64, 41); b[66] = 1; b[67] = cls; RawSmb.Put32(b, 68, 4096);
        RawSmb.Put64(b, 88, id.P); RawSmb.Put64(b, 96, id.V); return b;
    }
    static async Task Data(Fixture f, Peer p, (ulong P, ulong V) id, byte[] bytes)
    {
        var b = await p.Send(f, RawSmb.Read(id, (uint)bytes.Length, 0, 0, 0, 0));
        if (RawSmb.U32(b, 8) == Pending) b = await p.Final(b);
        Status(b, Ok, "READ");
        Check.That(RawSmb.Buffer(b, b[66], RawSmb.U32(b, 68)).SequenceEqual(bytes), "exact retained wire bytes");
    }
    static async Task LevelII(string operation)
    {
        await using var f = new Fixture(); var a = f.A;
        var first = await a.Send(f, Create(3, level: 1)); var id = Id(first); Check.Equal((byte)1, first[66], "actual level-II grant");
        var second = await a.Send(f, Create(level: 1)); Id(second); Check.Equal((byte)1, second[66], "second actual level-II grant");
        Status(await a.Send(f, operation == "write" ? RawSmb.Write(id, Bytes, 0, 0, 0, 0) : Lock(id)), Ok, "owner mutation requires no ACK");
        var notices = a.Sent.Where(b => RawSmb.U16(b, 12) == 18).ToArray();
        Check.Equal(2, notices.Length, "both level-II grants, including the requesting FileId, are invalidated");
        Check.That(notices.All(b => b[66] == 0), "level-II breaks to NONE");
        Check.That(notices.Any(b => RawSmb.U64(b, 80) == id.V), "owner receives its own invalidation");
        Status(await a.Send(f, P6Tests.Ack(id, OplockLevel.None)), 0xc0000184, "level-II invalidation never creates an ACK obligation");
        if (operation == "write") await Data(f, a, id, Bytes);
        else Status(await a.Send(f, Lock(id, 4)), Ok, "exact range unlock");
    }
    static async Task CrossSession(bool v2)
    {
        await using var f = new Fixture(); var a = f.A; var b = f.Other();
        var initial = await a.Send(f, Lease(Create(3), 1, v2: v2)); var owner = Id(initial);
        var upgrade = await b.Send(f, Lease(Create(), 7, v2: v2)); var member = Id(upgrade);
        Check.Equal(7u, RawSmb.U32(LeaseContext(upgrade), 16), "same client/key promotion spans sessions");
        Status(await b.Send(f, RawSmb.Close(member, 0, 0, 0)), Ok, "closing promoted member preserves common lease");
        var interim = await b.Send(f, Lease(Create(), 1, 2, v2)); Status(interim, Pending, "foreign key waits for shared lease ACK");
        var notice = await a.Receive(n => RawSmb.U16(n, 12) == 18);
        Check.Equal(7u, RawSmb.U32(notice, 88), "original member sees promoted common state");
        Check.That((RawSmb.U32(notice, 68) & 1) != 0, "write/handle caching requires ACK");
        if (v2) Check.Equal((ushort)(RawSmb.U16(LeaseContext(upgrade), 48) + 1), RawSmb.U16(notice, 66), "break increments common epoch");
        Status(await a.Send(f, Ack(notice, 7)), 0xc00000d0, "ACK outside target rejected");
        Check.That(!b.Sent.Any(n => RawSmb.U16(n, 12) == 5), "invalid ACK does not complete CREATE");
        Status(await a.Send(f, Ack(notice)), Ok, "ACK on owning session");
        var peer = Id(await b.Final(interim));
        Status(await b.Send(f, RawSmb.Write(peer, Bytes, 0, 0, 0, 0)), Ok, "cross-session write after ACK");
        await Data(f, a, owner, Bytes);
    }
    static async Task PendingMember(bool v2)
    {
        await using var f = new Fixture(); var a = f.A; var b = f.Other();
        var owner = Id(await a.Send(f, Lease(Create(3), v2: v2)));
        Status(await a.Send(f, RawSmb.Write(owner, Bytes, 0, 0, 0, 0)), Ok, "initial bytes");
        var pending = await b.Send(f, Create(4)); Status(pending, Pending, "overwrite waits for ACK");
        var notice = await a.Receive(n => RawSmb.U16(n, 12) == 18);
        try
        {
            // This must not wait behind the conflicting CREATE's namespace gate.
            var same = await a.Send(f, Lease(Create(), v2: v2)).WaitAsync(Check.Timeout);
            if (RawSmb.U32(same, 8) == Pending) same = await a.Final(same);
            var ctx = LeaseContext(same); var member = Id(same);
            Check.Equal(7u, RawSmb.U32(ctx, 16), "unacknowledged lease state retained");
            Check.Equal(2u, RawSmb.U32(ctx, 20), "same-key response reports BREAK_IN_PROGRESS");
            if (v2) Check.Equal(RawSmb.U16(notice, 66), RawSmb.U16(ctx, 48), "breaking epoch shared with reopened member");
            await Data(f, a, owner, Bytes);
            Status(await a.Send(f, RawSmb.Close(member, 0, 0, 0)), Ok, "closing one member does not release common ACK obligation");
            Check.That(!b.Sent.Any(n => RawSmb.U16(n, 12) == 5), "overwrite still pending after member close");
        }
        finally { Status(await a.Send(f, Ack(notice)), Ok, "release ACK even when probe fails"); await b.Final(pending); }
        var after = await a.Send(f, Lease(Create(), 0, v2: v2));
        Check.Equal(0u, RawSmb.U32(LeaseContext(after), 20), "completed break clears BREAK_IN_PROGRESS");
    }
    static async Task LastLiveMember(bool v2)
    {
        await using var f = new Fixture(); var a = f.A; var b = f.Other();
        var owner = Id(await a.Send(f, Lease(Create(3), v2: v2))); var member = Id(await b.Send(f, Lease(Create(), v2: v2)));
        Status(await a.Send(f, RawSmb.Close(owner, 0, 0, 0)), Ok, "first member closes");
        var pending = await a.Send(f, Create(4)); Status(pending, Pending, "remaining member retains caching obligation");
        var notice = await b.Receive(n => RawSmb.U16(n, 12) == 18); Check.Equal(7u, RawSmb.U32(notice, 88), "live member owns original grant");
        Status(await b.Send(f, Ack(notice)), Ok, "remaining session ACK"); Id(await a.Final(pending));
        Status(await b.Send(f, RawSmb.Write(member, Bytes, 0, 0, 0, 0)), Ok, "remaining FileId usable");
    }
    static async Task Stat(uint access)
    {
        await using var f = new Fixture(); var a = f.A;
        var owner = Id(await a.Send(f, Lease(Create(3))));
        var stat = await a.Send(f, Create(access: access)); Id(stat);
        Check.Equal(0, a.Sent.Count, "attribute-only open preserves lease without break");
        var current = await a.Send(f, Lease(Create(), 0)); Check.Equal(7u, RawSmb.U32(LeaseContext(current), 16), "attribute open preserves current caching grant");
        Status(await a.Send(f, RawSmb.Write(owner, Bytes, 0, 0, 0, 0)), Ok, "owner still usable");
    }
    static async Task ReplacedPath(bool v2)
    {
        await using var f = new Fixture(); var a = f.A; var b = f.Other();
        var owner = Id(await a.Send(f, Lease(Create(3), v2: v2)));
        Status(await a.Send(f, RawSmb.Write(owner, Bytes, 0, 0, 0, 0)), Ok, "old object bytes");
        var pending = await b.Send(f, Create(4)); Status(pending, Pending, "overwrite waits on old object lease");
        var oldBreak = await a.Receive(n => RawSmb.U16(n, 12) == 18);
        Status(await a.Send(f, P6Tests.Rename(owner, "moved")), Ok, "owner renames old object while ACK outstanding");
        var replacement = Id(await a.Send(f, Lease(Create(3), key: 2, v2: v2)));
        var replacementBytes = "replacement cached bytes"u8.ToArray();
        Status(await a.Complete(f, RawSmb.Write(replacement, replacementBytes, 0, 0, 0, 0)), Ok, "replacement object bytes");
        Status(await a.Send(f, Ack(oldBreak)), Ok, "old identity break acknowledged");
        var replacementBreak = await a.Receive(n => RawSmb.U16(n, 12) == 18);
        Check.Equal(2ul, RawSmb.U64(replacementBreak, 72), "resumed CREATE revalidates pathname and breaks replacement lease");
        await Data(f, a, replacement, replacementBytes);
        await Data(f, a, owner, Bytes);
        Check.That(!b.Sent.Any(n => RawSmb.U16(n, 12) == 5), "replacement is not overwritten before its own ACK");
        Status(await a.Send(f, Ack(replacementBreak)), Ok, "replacement identity acknowledged");
        var overwritten = Id(await b.Final(pending));
        Status(await b.Send(f, RawSmb.Read(overwritten, 1, 0, 0, 0, 0)), 0xc0000011, "replacement overwritten after ACK");
        await Data(f, a, owner, Bytes);
    }
    static async Task Durable(bool v1, bool leased)
    {
        await using var f = new Fixture(true); var a = f.A; var guid = Guid.NewGuid();
        var data = new byte[v1 ? 16 : 32]; if (!v1) { RawSmb.Put32(data, 0, 30000); guid.ToByteArray().CopyTo(data, 16); }
        var request = P7cTests.Context(Create(3, level: 9), v1 ? "DHnQ" : "DH2Q", data); if (leased) request = Lease(request, 3);
        var response = await a.Send(f, request); var id = Id(response);
        if (leased) Check.Equal(3u, RawSmb.U32(LeaseContext(response), 16), "RH grant has no WRITE caching");
        Status(await a.Send(f, RawSmb.Write(id, Bytes, 0, 0, 0, 0)), Ok, "write before disconnect");
        Status(await a.Send(f, Lock(id)), Ok, "lock before disconnect");
        var position = new byte[8]; RawSmb.Put64(position, 0, 4096); Status(await a.Send(f, P5Tests.SetPacket(id, 14, position)), Ok, "position before disconnect");
        await f.D.Dispatcher.OnConnectionClosedAsync(a.Connection);
        var b = f.Other(sameClient: !leased); // A classic durable open has no lease-qualified ClientGuid restriction.
        byte[] Reconnect()
        {
            var claim = new byte[v1 ? 16 : 36]; RawSmb.Put64(claim, 0, id.P); RawSmb.Put64(claim, 8, id.V); if (!v1) guid.ToByteArray().CopyTo(claim, 16);
            var r = P7cTests.Context(Create(), v1 ? "DHnC" : "DH2C", claim); return leased ? Lease(r, 3) : r;
        }
        if (leased)
        {
            Status(await b.Send(f, Reconnect()), Missing, "foreign ClientGuid cannot claim leased durable");
            b.Connection.ClientGuid = a.Connection.ClientGuid.ToArray();
        }
        var recovered = Id(await b.Send(f, Reconnect())); Check.Equal(id.P, recovered.P, "persistent identity retained");
        var q = await b.Send(f, Query(recovered, 14)); Status(q, Ok, "position after reconnect");
        Check.Equal(4096ul, RawSmb.U64(q, RawSmb.U16(q, 66)), "open position survives reconnect");
        Status(await b.Send(f, Lock(recovered, 4)), Ok, "RH/no-W reconnect retains lock ownership");
        await Data(f, b, recovered, Bytes); Status(await b.Send(f, Reconnect()), Missing, "claim consumed only once");
    }
    static async Task InvalidUnicodeAlias(bool high)
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); await using var c = await f.ConnectAsync();
        var existing = await c.CreateAsync("\ufffdx"); await c.WriteAsync(existing, Bytes);
        var request = RawSmb.Create("xx", false, c.NextMessageId(), c.Session, c.Tree);
        RawSmb.Put16(request, RawSmb.U16(request, 108), high ? (ushort)0xd800 : (ushort)0xdc00);
        await c.ExchangeAsync(request, 0xc000000d);
        Check.That((await c.ReadAsync(existing, (uint)Bytes.Length)).SequenceEqual(Bytes), "invalid encoding cannot alias a literal replacement-character name");
        await c.CloseAsync(existing);
    }
    static async Task ValidUnicode()
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); await using var c = await f.ConnectAsync();
        const string name = "valid-\U0001f4c1-\ufffd";
        var id = await c.CreateAsync(name); await c.WriteAsync(id, Bytes); await c.CloseAsync(id);
        id = await c.CreateAsync(name); Check.That((await c.ReadAsync(id, (uint)Bytes.Length)).SequenceEqual(Bytes), "valid supplementary pair and literal replacement character round trip");
        var directory = await c.CreateAsync("", true); Check.That((await c.EnumerateAsync(directory)).Contains(name), "wire enumeration preserves exact Unicode filename");
        await c.CloseAsync(directory); await c.CloseAsync(id);
    }
    static async Task MissingIoctlOpen()
    {
        await using var f = new Fixture();
        Status(await f.A.Send(f, P5Tests.Ioctl((ulong.MaxValue, ulong.MaxValue), 0x0009009c, [], 64)), 0xc0000128,
            "ordinary IOCTL requires a live FileId before dispatching its control code");
    }
    static async Task AuthenticateLayout(string layout)
    {
        await using var f = await UpstreamLocalFixture.StartAsync(); using var tcp = new TcpClient();
        using var timeout = new CancellationTokenSource(Check.Timeout); await tcp.ConnectAsync(f.Server.Endpoint.Address, f.Server.Endpoint.Port, timeout.Token);
        ulong mid = 0;
        async Task<byte[]> Exchange(byte[] b, uint status)
        {
            RawSmb.Put64(b, 24, mid++); var frame = new byte[4 + b.Length]; frame[1] = (byte)(b.Length >> 16); frame[2] = (byte)(b.Length >> 8); frame[3] = (byte)b.Length; b.CopyTo(frame, 4);
            await tcp.GetStream().WriteAsync(frame, timeout.Token); var prefix = new byte[4]; await tcp.GetStream().ReadExactlyAsync(prefix, timeout.Token);
            var size = prefix[1] << 16 | prefix[2] << 8 | prefix[3]; Check.That(size is >= 64 and <= 1048576, "bounded authentication response");
            var response = new byte[size]; await tcp.GetStream().ReadExactlyAsync(response, timeout.Token);
            RawSmb.Response(response, RawSmb.U16(b, 12), RawSmb.U64(b, 24), status); return response;
        }
        await Exchange(RawSmb.Negotiate(), Ok); var client = new NtlmClient(HostFixture.Domain, HostFixture.User, HostFixture.Password);
        var challenge = await Exchange(RawSmb.SessionSetup(client.BuildNegotiate(), 0), 0xc0000016); var sid = RawSmb.U64(challenge, 40);
        var token = client.BuildAuthenticate(RawSmb.Buffer(challenge, RawSmb.U16(challenge, 68), RawSmb.U16(challenge, 70)));
        Check.That((RawSmb.U32(token, 60) & 0x02000000) == 0, "control has no declared Version");
        if (layout == "packed-64")
        {
            var packed = new byte[token.Length - 24]; token.AsSpan(0, 64).CopyTo(packed); token.AsSpan(88).CopyTo(packed.AsSpan(64));
            foreach (var field in new[] { 12, 20, 28, 36, 44, 52 }) RawSmb.Put32(packed, field + 4, RawSmb.U32(packed, field + 4) - 24);
            token = packed;
        }
        if (layout == "empty-offsets")
            foreach (var field in new[] { 12, 44 }) { RawSmb.Put16(token, field, 0); RawSmb.Put16(token, field + 2, ushort.MaxValue); RawSmb.Put32(token, field + 4, uint.MaxValue); }
        if (layout.StartsWith("header-"))
        {
            var field = layout == "header-lm" ? 12 : 44; RawSmb.Put16(token, field, 4); RawSmb.Put32(token, field + 4, 10);
        }
        if (layout == "short-lm") RawSmb.Put16(token, 12, 4);
        if (layout == "odd-workstation") RawSmb.Put16(token, 44, 1);
        var valid = layout is "packed-64" or "empty-offsets";
        await Exchange(RawSmb.SessionSetup(token, 0, sid), valid ? Ok : 0xc000000d);
        if (valid)
        {
            var echo = RawSmb.Header(13, 4, mid, sid); RawSmb.Put16(echo, 64, 4); RawSmb.Sign(echo, client.ExportedSessionKey);
            var response = await Exchange(echo, Ok); Check.That((RawSmb.U32(response, 16) & 8) != 0, "layout control establishes a signed session");
        }
    }
}
