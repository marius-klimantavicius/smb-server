using System.Net;
using System.Net.Sockets;
using Smb.Auth.Ntlm;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Protocol.Enums;
using Smb.Testing;

internal static class UpstreamRepairTests
{
    public static IEnumerable<(string Name, Func<Task> Run)> Cases()
    {
        yield return ("upstream.repair.create.concurrent-first-open-if", FirstOpen);
        yield return ("upstream.repair.client-guid.dialect-lifecycle", ClientDialect);
        yield return ("upstream.repair.stream.overwrite-live-generation", StreamGeneration);
        yield return ("upstream.repair.stream.base-delete-sharing", BaseDeleteSharing);
        yield return ("upstream.repair.security.basic-dacl-enforced", BasicDacl);
        yield return ("upstream.repair.security.set-requires-write-dac", SecurityAccess);
        yield return ("upstream.repair.replay.rejected-mid-does-not-commit", ReplayCommit);
    }

    static async Task FirstOpen()
    {
        using var root = new P7cTests.Root(); var store = new FirstOpenStore(root.Store());
        await using var d = new P2Tests.Direct(store);
        var first = d.Send(d.Create("race"));
        await store.CreateGate.Entered.WaitAsync(Check.Timeout);
        var second = d.Send(d.Create("race"));
        try { await store.SecondMissing.Task.WaitAsync(Check.Timeout); }
        finally { store.CreateGate.Release(); }
        var responses = await Task.WhenAll(first, second).WaitAsync(Check.Timeout);
        foreach (var response in responses) Check.Equal(0u, RawSmb.U32(response, 8), "compatible first OPEN_IF requests both succeed without client retry");
        var ids = responses.Select(b => (RawSmb.U64(b, 128), RawSmb.U64(b, 136))).ToArray();
        Check.That(ids[0] != ids[1], "each successful CREATE returns a separate FileId");
        Check.Equal(2u, RawSmb.U32(responses[0], 68), "first creator action");
        Check.Equal(1u, RawSmb.U32(responses[1], 68), "waiting request opens published object");
        Check.Equal(0u, RawSmb.U32(await d.Send(RawSmb.Write(ids[0], [11, 22], 0, 0, 1, 42)), 8), "write through creator");
        var read = await d.Send(RawSmb.Read(ids[1], 2, 0, 0, 1, 42));
        Check.That(read.AsSpan(read[66], (int)RawSmb.U32(read, 68)).SequenceEqual(new byte[] { 11, 22 }), "both opens see same live object");
    }

    sealed class FirstOpenStore(IFileStore inner) : IFileStore, IFileIdentityStore
    {
        public readonly AsyncBarrier CreateGate = new();
        public readonly TaskCompletionSource SecondMissing = new(TaskCreationOptions.RunContinuationsAsynchronously);
        int creates;
        public async ValueTask<FileIdentity?> ResolveIdentityAsync(string path, string stream = "", CancellationToken ct = default)
        {
            var result = await ((IFileIdentityStore)inner).ResolveIdentityAsync(path, stream, ct);
            if (Volatile.Read(ref creates) == 1 && result == null) SecondMissing.TrySetResult();
            return result;
        }
        public async ValueTask<FileStoreResult<FileCreateResult>> CreateAsync(string p, FileAccessIntent a, CreateDispositionIntent d, bool dir, bool non, CancellationToken ct = default)
        {
            if (Interlocked.Increment(ref creates) == 1) await CreateGate.WaitAsync(ct);
            return await inner.CreateAsync(p, a, d, dir, non, ct);
        }
        public ValueTask<FileStoreResult<int>> ReadAsync(IFileHandle h, long o, Memory<byte> b, CancellationToken ct = default) => inner.ReadAsync(h, o, b, ct);
        public ValueTask<FileStoreResult<int>> WriteAsync(IFileHandle h, long o, ReadOnlyMemory<byte> b, CancellationToken ct = default) => inner.WriteAsync(h, o, b, ct);
        public ValueTask<FileStoreResult<IReadOnlyList<FileEntryInfo>>> QueryDirectoryAsync(IFileHandle h, string p, CancellationToken ct = default) => inner.QueryDirectoryAsync(h, p, ct);
        public ValueTask<NtStatus> SetEndOfFileAsync(IFileHandle h, long n, CancellationToken ct = default) => inner.SetEndOfFileAsync(h, n, ct);
        public ValueTask<NtStatus> RenameAsync(IFileHandle h, string p, bool r, CancellationToken ct = default) => inner.RenameAsync(h, p, r, ct);
        public ValueTask<NtStatus> SetDeleteOnCloseAsync(IFileHandle h, bool b, CancellationToken ct = default) => inner.SetDeleteOnCloseAsync(h, b, ct);
        public ValueTask<NtStatus> FlushAsync(IFileHandle h, CancellationToken ct = default) => inner.FlushAsync(h, ct);
    }

    static async Task StreamGeneration()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        var file = await d.Open("base"); var stream = await d.Open("base:one");
        await d.Send(RawSmb.Write(stream, [9, 8], 0, 0, 1, 42));
        var overwrite = d.Create("base"); RawSmb.Put32(overwrite, 100, 5);
        Check.Equal(0u, RawSmb.U32(await d.Send(overwrite), 8), "base overwrite succeeds with compatible opens");
        var read = await d.Send(RawSmb.Read(stream, 2, 0, 0, 1, 42));
        Check.Equal(0u, RawSmb.U32(read, 8), "live stream handle survives base overwrite");
        Check.That(read.AsSpan(read[66], (int)RawSmb.U32(read, 68)).SequenceEqual(new byte[] { 9, 8 }), "old generation retains its bytes");
        var replacement = await d.Open("base:one");
        await d.Send(RawSmb.Write(replacement, [7], 0, 0, 1, 42));
        read = await d.Send(RawSmb.Read(stream, 2, 0, 0, 1, 42));
        Check.That(read.AsSpan(read[66], (int)RawSmb.U32(read, 68)).SequenceEqual(new byte[] { 9, 8 }), "recreated stream has separate storage");
    }

    static async Task ReplayCommit()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        d.Options.FeaturePolicy = Smb.Server.SmbFeaturePolicy.Durable; d.Connection.Dialect = SmbDialect.Smb300; d.CommitResponses = false;
        var context = new byte[32]; RawSmb.Put32(context, 0, 10000); Guid.NewGuid().ToByteArray().CopyTo(context, 16);
        byte[] Request(bool replay) { var b = d.Create("replay"); b[67] = 9; if (replay) RawSmb.Put32(b, 16, 0x20000000); return P7cTests.Context(b, "DH2Q", context); }
        var original = await d.Send(Request(false)); Check.Equal(0u, RawSmb.U32(original, 8), "original CREATE final prepared but unsent");
        var invalid = RawSmb.Header(13, 4, RawSmb.U64(original, 24), 1); RawSmb.Put16(invalid, 64, 4);
        Smb.Crypto.Smb2Signer.SignInPlace(Smb.Crypto.Smb2Signer.ResolveAlgorithm(d.Connection.Dialect, d.Connection.SigningAlgorithmId), d.Session.SigningKey, invalid, 0, false, false);
        var rejected = await d.Dispatcher.ProcessMessageAsync(d.Connection, invalid);
        Check.Equal(0xc000000du, RawSmb.U32(rejected, 8), "used MessageId is rejected"); d.Connection.ResponseSent(rejected);
        var repeated = await d.Send(Request(true)); Check.Equal(0xc0000467u, RawSmb.U32(repeated, 8), "a different response with the same MID cannot commit the original CREATE claim");
        d.Connection.ResponseSent(original);
        repeated = await d.Send(Request(true)); Check.Equal(0u, RawSmb.U32(repeated, 8), "actual CREATE delivery permits replay"); d.Connection.ResponseSent(repeated);
        Check.Equal(RawSmb.U64(original, 136), RawSmb.U64(repeated, 136), "replay returns original FileId");
    }

    static byte[] DenyReadDacl()
    {
        var sd = new byte[48]; sd[0] = 1; RawSmb.Put16(sd, 2, 0x8004); RawSmb.Put32(sd, 16, 20);
        sd[20] = 2; RawSmb.Put16(sd, 22, 28); RawSmb.Put16(sd, 24, 1);
        sd[28] = 1; RawSmb.Put16(sd, 30, 20); RawSmb.Put32(sd, 32, 1);
        sd[36] = 1; sd[37] = 1; sd[43] = 1; return sd; // Everyone, deny READ_DATA
    }
    static byte[] SetDacl((ulong P, ulong V) id)
    {
        var b = P5Tests.SetPacket(id, 0, DenyReadDacl()); b[66] = 3; RawSmb.Put32(b, 76, 4); return b;
    }
    static async Task SecurityAccess()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var id = await d.Open("secure");
        Check.Equal(0xc0000022u, RawSmb.U32(await d.Send(SetDacl(id)), 8), "SET DACL requires WRITE_DAC on this open");
        await d.Open("secure"); // denied change cannot remove peer READ_DATA permission
    }
    static async Task BasicDacl()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var request = d.Create("secure"); RawSmb.Put32(request, 88, 0x1f01ff);
        var b = await d.Send(request); Check.Equal(0u, RawSmb.U32(b, 8), "full access CREATE"); var id = (RawSmb.U64(b, 128), RawSmb.U64(b, 136));
        Check.Equal(0u, RawSmb.U32(await d.Send(SetDacl(id)), 8), "supported basic DACL accepted");
        request = d.Create("secure"); RawSmb.Put32(request, 88, 1);
        Check.Equal(0xc0000022u, RawSmb.U32(await d.Send(request), 8), "new READ open denied by stored DACL");
        Check.Equal(0u, RawSmb.U32(await d.Send(RawSmb.Write(id, [8], 0, 0, 1, 42)), 8), "existing grant survives DACL update");
    }
    static async Task BaseDeleteSharing()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var seed = await d.Open("base"); await d.Send(RawSmb.Close(seed, 0, 1, 42));
        var request = d.Create("base:one"); RawSmb.Put32(request, 96, 3); var stream = await d.Send(request); Check.Equal(0u, RawSmb.U32(stream, 8), "stream open denies DELETE sharing");
        request = d.Create("base"); RawSmb.Put32(request, 88, 0x10000);
        Check.Equal(0xc0000043u, RawSmb.U32(await d.Send(request), 8), "base DELETE access checks live streams");
        await d.Send(RawSmb.Close((RawSmb.U64(stream, 128), RawSmb.U64(stream, 136)), 0, 1, 42));
        Check.Equal(0u, RawSmb.U32(await d.Send(request), 8), "closing stream permits fresh base DELETE open");
    }

    static async Task ClientDialect()
    {
        await using var host = await UpstreamLocalFixture.StartAsync(); var guid = Guid.NewGuid();
        await using (var a = await Peer.Connect(host.Server.Endpoint))
        {
            await a.Login(guid, 0x210, 0);
            await using (var b = await Peer.Connect(host.Server.Endpoint)) await b.Login(guid, 0x210, 0);
            await using (var conflict = await Peer.Connect(host.Server.Endpoint)) await conflict.Login(guid, 0x302, 0xc0000203);
            // Closing another same-GUID connection cannot erase the first one's dialect.
            await using (var conflict = await Peer.Connect(host.Server.Endpoint)) await conflict.Login(guid, 0x302, 0xc0000203);
            var echo = RawSmb.Header(13, 4, 3, a.Session); RawSmb.Put16(echo, 64, 4); RawSmb.Sign(echo, a.Key!);
            Check.Equal(0u, RawSmb.U32(await a.Exchange(echo), 8), "original authenticated session survives rejected client dialect");
        }
        using var timeout = new CancellationTokenSource(Check.Timeout);
        while (!host.Server.State.Connections.IsEmpty) await Task.Delay(1, timeout.Token);
        await using var after = await Peer.Connect(host.Server.Endpoint);
        await after.Login(guid, 0x302, 0); // last transport retirement permits new dialect
    }

    sealed class Peer : IAsyncDisposable
    {
        readonly TcpClient tcp = new();
        public ulong Session;
        public byte[]? Key;
        public static async Task<Peer> Connect(IPEndPoint endpoint)
        {
            var peer = new Peer(); await peer.tcp.ConnectAsync(endpoint); return peer;
        }
        public async Task<byte[]> Exchange(byte[] request)
        {
            using var timeout = new CancellationTokenSource(Check.Timeout); var stream = tcp.GetStream();
            var framed = new byte[request.Length + 4]; framed[1] = (byte)(request.Length >> 16); framed[2] = (byte)(request.Length >> 8); framed[3] = (byte)request.Length; request.CopyTo(framed, 4);
            await stream.WriteAsync(framed, timeout.Token); var prefix = new byte[4]; await stream.ReadExactlyAsync(prefix, timeout.Token);
            var result = new byte[(prefix[1] << 16) | (prefix[2] << 8) | prefix[3]]; await stream.ReadExactlyAsync(result, timeout.Token); return result;
        }
        public async Task Login(Guid guid, ushort dialect, uint expected)
        {
            var negotiate = RawSmb.Negotiate(); RawSmb.Put16(negotiate, 100, dialect); guid.ToByteArray().CopyTo(negotiate, 76);
            Check.Equal(0u, RawSmb.U32(await Exchange(negotiate), 8), "dialect negotiated on fresh transport");
            var ntlm = new NtlmClient(HostFixture.Domain, HostFixture.User, HostFixture.Password);
            var challenge = await Exchange(RawSmb.SessionSetup(ntlm.BuildNegotiate(), 1));
            Check.Equal(0xc0000016u, RawSmb.U32(challenge, 8), "NTLM challenge"); Session = RawSmb.U64(challenge, 40);
            var response = await Exchange(RawSmb.SessionSetup(ntlm.BuildAuthenticate(RawSmb.Buffer(challenge, RawSmb.U16(challenge, 68), RawSmb.U16(challenge, 70))), 2, Session));
            Check.Equal(expected, RawSmb.U32(response, 8), "server-wide client GUID dialect rule at final authentication"); Key = ntlm.ExportedSessionKey;
        }
        public ValueTask DisposeAsync() { tcp.Dispose(); return ValueTask.CompletedTask; }
    }
}
