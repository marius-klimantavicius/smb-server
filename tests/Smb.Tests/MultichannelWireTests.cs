using System.Buffers.Binary;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.Protocol.Enums;
using Smb.Server;
using Smb.Server.State;
using Smb.Testing;

// MS-SMB2 3.3.5.5/.3, 3.3.4.1.1, 3.1.4.1/.2/.3. These peers negotiate and
// authenticate distinct TCP connections. KDF, SHA512, CMAC/GMAC and AEAD oracles
// deliberately do not call Smb.Crypto or inspect server keys.
internal static class MultichannelWireTests
{
    const uint More = 0xc0000016, Denied = 0xc0000022, Invalid = 0xc000000d, Deleted = 0xc0000203;
    public static IEnumerable<(string Name, Func<Task> Run)> Cases()
    {
        yield return ("channel-wire.crypto.literal-oracles", Oracles);
        yield return ("channel-wire.policy.311", Advertise);
        foreach (ushort cipher in new ushort[] { 3, 4 })
            yield return ($"channel-wire.crypto.full-key.{cipher}", () => FullKey(cipher));
        foreach (ushort d in new ushort[] { 0x300, 0x302, 0x311 })
        {
            yield return ($"channel-wire.workflow.{d:x}", () => Workflow(d, 0, 1));
            yield return ($"channel-wire.optional-signing.{d:x}", () => OptionalSigning(d));
            foreach (var mode in new[] { "signature", "unsigned", "guid", "dialect", "owner", "auth-failure", "duplicate", "wrong-channel-key", "client-capability" })
                yield return ($"channel-wire.binding.{mode}.{d:x}", () => Reject(d, mode));
        }
        foreach (var mode in new[] { "optional-signature", "pending-loss", "pending-logoff", "limit", "mixed-signing", "mixed-cipher", "transcript", "survivor", "close-race", "cancel", "logoff", "shutdown", "last-loss" })
            foreach (ushort d in new ushort[] { 0x300, 0x302, 0x311 })
                yield return ($"channel-wire.lifecycle.{mode}.{d:x}", () => Lifecycle(d, mode));
        foreach (var mode in new[] { "logoff", "last-loss", "shutdown", "limit" })
            foreach (ushort d in new ushort[] { 0x300, 0x302, 0x311 })
                yield return ($"channel-wire.bind-race.{mode}.{d:x}", () => BindRace(d, mode));
        foreach (ushort d in new ushort[] { 0x300, 0x302, 0x311 })
            foreach (bool lease in new[] { false, true })
                foreach (bool fail in new[] { false, true })
                    foreach (bool encrypted in new[] { false, true })
                        yield return ($"channel-wire.break-survivor.{d:x}.{lease}.{fail}.{encrypted}", () => BreakSurvivor(d, lease, fail, encrypted));
        yield return ("channel-wire.crypto-boundary.key-width", () => CryptoBoundary(false));
        yield return ("channel-wire.crypto-boundary.encryption-capability", () => CryptoBoundary(true));
        foreach (ushort d in new ushort[] { 0x300, 0x302, 0x311 })
            yield return ($"channel-wire.encrypted-logoff.{d:x}", () => EncryptedLogoff(d));
        foreach (ushort d in new ushort[] { 0x300, 0x302, 0x311 })
            foreach (bool encrypted in new[] { false, true })
                foreach (bool v2 in new[] { false, true })
                {
                    foreach (var cache in new[] { "batch", "lease-v1", "lease-v2" })
                        yield return ($"channel-composition.durable.{d:x}.{encrypted}.v{(v2 ? 2 : 1)}.{cache}", () => DurableComposition(d, encrypted, v2, cache));
                    foreach (var race in new[] { "claim-race", "teardown" })
                        yield return ($"channel-composition.durable.{d:x}.{encrypted}.v{(v2 ? 2 : 1)}.{race}", () => DurableContention(d, encrypted, v2, race));
                }
        foreach (ushort cipher in new ushort[] { 1, 2, 3, 4 })
            foreach (ushort signing in new ushort[] { 0, 1, 2 })
                yield return ($"channel-wire.encryption.311.{cipher}.{signing}", () => Workflow(0x311, cipher, signing));
        foreach (ushort d in new ushort[] { 0x300, 0x302 })
            yield return ($"channel-wire.encryption.{d:x}", () => Workflow(d, 1, 1));
    }
    static HostFixture Host(bool signing = true)
    {
        var h = new HostFixture(); var o = h.Server.State.Options;
        o.FeaturePolicy = SmbFeaturePolicy.MultichannelOnly; o.EnableMultichannel = true; o.RequireMessageSigning = signing;
        o.SpnegoNegotiator = new NtlmSpnegoNegotiator(new InMemoryIdentityBackend()
            .AddUser(HostFixture.Domain, HostFixture.User, HostFixture.Password).AddUser(HostFixture.Domain, "other", HostFixture.Password));
        return h;
    }
    static void Status(byte[] b, uint expected) => Check.Equal(expected, RawSmb.U32(b, 8), "wire status");
    static Task Oracles()
    {
        // RFC4493 examples 1/2, AES-CMAC, independent ECB implementation below.
        var key = Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c");
        Check.That(Cmac(key, []).SequenceEqual(Convert.FromHexString("bb1d6929e95937287fa37d129b756746")), "RFC4493 empty CMAC");
        Check.That(Cmac(key, Convert.FromHexString("6bc1bee22e409f96e93d7e117393172a")).SequenceEqual(Convert.FromHexString("070a16b46b4d4144f79bdd9dd04a287c")), "RFC4493 block CMAC");
        return Task.CompletedTask;
    }
    static Task FullKey(ushort cipher)
    {
        // 3.3.5.5.3 step 11 uses FullSessionKey for AES256; signing remains
        // based on the 16-byte SessionKey. NTLM TCP controls have equal inputs,
        // so this deliberately distinct-input oracle is supplementary coverage.
        var full = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
        var session = full[..16]; var transcript = Enumerable.Range(33, 64).Select(i => (byte)i).ToArray();
        var actual = Smb.Crypto.Smb3KeyDerivation.Derive(SmbDialect.Smb311, (SmbCipherId)cipher, session, full, transcript);
        Check.That(actual.EncryptionKey.SequenceEqual(Kdf(full, "SMBS2CCipherKey", transcript, 32)), "AES256 S2C uses full authentication key");
        Check.That(actual.DecryptionKey.SequenceEqual(Kdf(full, "SMBC2SCipherKey", transcript, 32)), "AES256 C2S uses full authentication key");
        Check.That(actual.SigningKey.SequenceEqual(Kdf(session, "SMBSigningKey", transcript)), "AES256 does not alter 128-bit signing-key input");
        return Task.CompletedTask;
    }
    static async Task Advertise()
    {
        await using var h = Host(); await h.StartAsync(); await using var p = new Peer(); await p.Negotiate(h, 0x311);
        Check.That((p.ServerCapabilities & 8) != 0, "SMB311 opt-in advertises multichannel");
    }
    static async Task OptionalSigning(ushort d)
    {
        await using var h = Host(false); await h.StartAsync(); await using var p = new Peer(); await p.Login(h, d);
        // Final SESSION_SETUP MUST be signed even when subsequent signing is optional.
        var id = await p.Open("optional"); await p.Exchange(RawSmb.Close(id, 0, 0, 0));
    }
    static byte[] Rename((ulong P, ulong V) id, string name)
    {
        var text = Encoding.Unicode.GetBytes(name); var info = new byte[20 + text.Length]; RawSmb.Put32(info, 16, (uint)text.Length); text.CopyTo(info, 20);
        var b = RawSmb.Header(17, 32 + info.Length, 0); RawSmb.Put16(b, 64, 33); b[66] = 1; b[67] = 10;
        RawSmb.Put32(b, 68, (uint)info.Length); RawSmb.Put16(b, 72, 96); RawSmb.Put64(b, 80, id.P); RawSmb.Put64(b, 88, id.V); info.CopyTo(b, 96); return b;
    }
    static byte[] Lock((ulong P, ulong V) id, uint flags, uint sequence = 0)
    {
        var b = RawSmb.Header(10, 48, 0); RawSmb.Put16(b, 64, 48); RawSmb.Put16(b, 66, 1); RawSmb.Put32(b, 68, sequence);
        RawSmb.Put64(b, 72, id.P); RawSmb.Put64(b, 80, id.V); RawSmb.Put64(b, 96, 1); RawSmb.Put32(b, 104, flags); return b;
    }
    static async Task Workflow(ushort d, ushort cipher, ushort signing)
    {
        await using var h = Host(); await h.StartAsync(); await using var a = new Peer(); await a.Login(h, d, cipher, signing);
        await using var b = new Peer(); await b.Bind(h, a);
        Check.That(!a.Key.SequenceEqual(b.Key), "separate authentication produces distinct channel signing key");
        Check.Equal(2, h.Server.State.SessionGlobalList[a.Session].Channels.Count, "two actual TCP channels");
        var ids = await Task.WhenAll(a.Open("first"), b.Open("second")); Check.That(ids[0].V != ids[1].V, "session-wide unique FileIds");
        var session = h.Server.State.SessionGlobalList[a.Session]; var primary = session.Connection;
        var credit = primary.Credits.AvailableCount;
        var data = Enumerable.Range(0, 100).Select(i => (byte)i).ToArray();
        await b.Exchange(RawSmb.Write(ids[0], data, 0, 0, 0, 0), encrypt: cipher != 0);
        Check.Equal(credit, primary.Credits.AvailableCount, "secondary consumes/grants only secondary credits");
        var read = await a.Exchange(RawSmb.Read(ids[0], 100, 0, 0, 0, 0), encrypt: cipher != 0);
        Check.That(RawSmb.Buffer(read, read[66], RawSmb.U32(read, 68)).SequenceEqual(data), "cross-channel exact bytes");
        await b.Exchange(Rename(ids[0], "renamed"), encrypt: cipher != 0);
        await a.Exchange(Lock(ids[0], 0x12), encrypt: cipher != 0);
        await b.Exchange(RawSmb.Write(ids[0], [99], 0, 0, 0, 0), encrypt: cipher != 0);
        await b.Exchange(Lock(ids[0], 4), encrypt: cipher != 0);
        await b.Exchange(RawSmb.Close(ids[0], 0, 0, 0), encrypt: cipher != 0);
        await a.Exchange(RawSmb.Close(ids[1], 0, 0, 0), encrypt: cipher != 0);
        Check.Equal(0, h.Store.ActiveHandles, "all backend handles released once");
        Check.That(h.Store.Handles.All(x => x.DisposeCalls == 1), "no duplicate disposal");
    }
    static async Task Reject(ushort d, string mode)
    {
        await using var h = Host(); await h.StartAsync(); await using var a = new Peer(); await a.Login(h, d);
        var authFailureOpen = mode == "auth-failure" ? await a.Open("auth-failure-open") : (0UL, 0UL);
        await using var b = new Peer();
        if (mode == "duplicate")
        {
            await b.Bind(h, a); var duplicate = b.Setup(new NtlmClient(HostFixture.Domain, HostFixture.User, HostFixture.Password).BuildNegotiate());
            await b.Exchange(duplicate, 0xc00000d0, setup: true, signingKey: a.Key); return;
        }
        await b.Negotiate(h, mode == "dialect" ? (ushort)(d == 0x300 ? 0x302 : 0x300) : d,
            guid: mode == "guid" ? Guid.NewGuid().ToByteArray() : a.Guid, caps: mode == "client-capability" ? 0u : 8u);
        b.Session = a.Session; b.Tree = a.Tree; b.OriginalKey = a.Key; b.Key = a.Key;
        var ntlm = new NtlmClient(HostFixture.Domain, mode == "owner" ? "other" : HostFixture.User, mode == "auth-failure" ? "bad" : HostFixture.Password);
        var req = b.Setup(ntlm.BuildNegotiate()); b.Route(req, true); b.Sign(req, a.Key);
        uint expected = More;
        if (mode == "unsigned") { RawSmb.Put32(req, 16, 0); req.AsSpan(48, 16).Clear(); expected = Invalid; }
        if (mode == "signature") { req[48] ^= 1; expected = Denied; }
        if (mode == "guid") expected = Deleted; // 3.3.5.5 explicit MAY choice.
        if (mode == "dialect") expected = Invalid;
        b.Hash(req); await b.Send(req); var challenge = await b.Receive(); Status(challenge, expected);
        if (expected == More)
        {
            b.Verify(challenge, a.Key);
            req = b.Setup(ntlm.BuildAuthenticate(RawSmb.Buffer(challenge, RawSmb.U16(challenge, 68), RawSmb.U16(challenge, 70))));
            var status = mode == "owner" ? 0xc00000bbu : mode == "auth-failure" ? 0xc000006du : 0u;
            b.Route(req, true); b.Sign(req, a.Key); b.Hash(req); await b.Send(req); var final = await b.Receive(); Status(final, status);
            if (status == 0)
            {
                b.Key = b.SigningKey(ntlm.ExportedSessionKey); b.Verify(final, b.Key);
                if (mode == "wrong-channel-key")
                {
                    var wrong = RawSmb.Header(13, 4, 0); RawSmb.Put16(wrong, 64, 4);
                    await b.Exchange(wrong, Denied, signingKey: a.Key);
                    await b.Exchange(RawSmb.TreeConnect("\\\\localhost\\P0", 0, 0));
                }
            }
            else b.Verify(final, a.Key);
        }
        if (mode == "auth-failure")
        {
            // 3.3.5.5.3's terminal GSS error teardown also applies to a binding
            // carrying a valid established-session signature. A bad signature is
            // rejected before GSS and is covered separately by preservation tests.
            Check.That(!h.Server.State.SessionGlobalList.ContainsKey(a.Session), "terminal binding GSS failure retires established session");
            Check.Equal(0, h.Store.ActiveHandles, "terminal binding failure closes all opens");
            await a.Exchange(RawSmb.Close(authFailureOpen, 0, 0, 0), Deleted); return;
        }
        var id = await a.Open("preserved"); await a.Exchange(RawSmb.Close(id, 0, 0, 0));
        Check.Equal(0, b.Connection(h)?.PendingBindings.Count ?? 0, "terminal/rejected binding releases preauth/auth state");
    }
    static byte[] DurableRequest(bool v2, Guid guid, string cache, (ulong P, ulong V)? id = null, ulong leaseKey = 11)
    {
        var request = RawSmb.Create("composed", false, 0, 0, 0); request[67] = 9;
        var data = new byte[id != null ? (v2 ? 36 : 16) : (v2 ? 32 : 16)];
        if (id is { } file) { RawSmb.Put64(data, 0, file.P); RawSmb.Put64(data, 8, file.V); }
        else if (v2) RawSmb.Put32(data, 0, 30000);
        if (v2) guid.ToByteArray().CopyTo(data, 16);
        request = P7cTests.Context(request, id != null ? (v2 ? "DH2C" : "DHnC") : (v2 ? "DH2Q" : "DHnQ"), data);
        if (cache != "batch")
        {
            var lease = new byte[cache == "lease-v2" ? 52 : 32]; RawSmb.Put64(lease, 0, leaseKey); RawSmb.Put64(lease, 8, 19); RawSmb.Put32(lease, 16, 7);
            request[67] = 255; request = P7cTests.Context(request, "RqLs", lease);
        }
        return request;
    }
    static byte[]? DurableContext(byte[] b, string name)
    {
        var at = (int)RawSmb.U32(b, 144); var end = checked(at + (int)RawSmb.U32(b, 148));
        while (at != 0 && at < end)
        {
            Check.That(at >= 152 && at + 16 <= end && end <= b.Length, "bounded durable contexts");
            if (Encoding.ASCII.GetString(b, at + RawSmb.U16(b, at + 4), RawSmb.U16(b, at + 6)) == name)
                return RawSmb.Buffer(b, at + RawSmb.U16(b, at + 10), RawSmb.U32(b, at + 12));
            var next = (int)RawSmb.U32(b, at); if (next == 0) break;
            Check.That(next >= 16 && next % 8 == 0, "context progress/alignment"); at += next;
        }
        return null;
    }
    static (ulong P, ulong V) DurableId(byte[] b) => (RawSmb.U64(b, 128), RawSmb.U64(b, 136));
    static async Task DurableComposition(ushort d, bool encrypted, bool v2, string cache)
    {
        using var root = new P6Tests.Root(); await using var h = Host(); var o = h.Server.State.Options;
        o.FeaturePolicy = SmbFeaturePolicy.DurableWithMultichannel; o.RequireEncryption = encrypted;
        o.Shares.Add(new Smb.FileSystem.Share { Name = "P0", FileStore = P6Tests.Local(root.Path) });
        await h.StartAsync(); await using var a = new Peer(); await a.Login(h, d, encrypted ? (ushort)1 : (ushort)0);
        await using var b = new Peer(); await b.Bind(h, a);
        var guid = Guid.NewGuid(); var request = DurableRequest(v2, guid, cache); var first = await a.Exchange(request);
        Check.Equal(cache == "batch" ? (byte)9 : (byte)255, first[66], "actual composed caching grant");
        Check.That(DurableContext(first, v2 ? "DH2Q" : "DHnQ") != null, "actual durable grant");
        if (cache != "batch")
        { var lease = DurableContext(first, "RqLs")!; Check.Equal(cache == "lease-v2" ? 52 : 32, lease.Length, "lease wire version"); Check.Equal(7u, RawSmb.U32(lease, 16), "full requested file lease grant"); }
        var id = DurableId(first);
        if (v2)
        {
            // A primary-channel ECHO orders the replay after the original
            // response-send callback; this tests completed rather than pending CREATE.
            var echo = RawSmb.Header(13, 4, 0); RawSmb.Put16(echo, 64, 4); await a.Exchange(echo);
            var replay = request.ToArray(); RawSmb.Put32(replay, 16, 0x20000000);
            var repeated = await b.Exchange(replay); Check.Equal(id, DurableId(repeated), "bound channel CREATE replay returns same open");
            Check.Equal(RawSmb.U32(first, 68), RawSmb.U32(repeated, 68), "replay preserves CREATE action");
        }
        var bytes = "durable multichannel exact bytes"u8.ToArray(); await a.Exchange(RawSmb.Write(id, bytes, 0, 0, 0, 0));
        await a.Exchange(Lock(id, 0x12, 0x11));
        var primary = a.Connection(h)!; a.FinishSending(); await Until(() => !h.Server.State.Connections.ContainsKey(primary.ConnectionId));
        var live = await b.Exchange(RawSmb.Read(id, (uint)bytes.Length, 0, 0, 0, 0));
        Check.That(RawSmb.Buffer(live, live[66], RawSmb.U32(live, 68)).SequenceEqual(bytes), "same durable FileId usable after one channel loss");
        await b.Exchange(Lock(id, 4, 0x12)); await b.Exchange(Lock(id, 0x12, 0x13));
        b.FinishSending(); await Until(() => !h.Server.State.SessionGlobalList.ContainsKey(a.Session));
        await using var bad = new Peer { Guid = a.Guid }; await bad.Login(h, d, encrypted ? (ushort)1 : (ushort)0, user: "other");
        await bad.Exchange(DurableRequest(v2, guid, cache, id), Denied);
        await using var c = new Peer { Guid = a.Guid }; await c.Login(h, d, encrypted ? (ushort)1 : (ushort)0);
        if (v2) await c.Exchange(DurableRequest(v2, Guid.NewGuid(), cache, id), 0xc0000034);
        if (cache != "batch") await c.Exchange(DurableRequest(v2, guid, cache, id, 12), 0xc0000034);
        var response = await c.Exchange(DurableRequest(v2, guid, cache, id)); var restored = DurableId(response);
        Check.Equal(id.P, restored.P, "persistent identity survives final loss and failed claims"); Check.That(id.V != restored.V, "recovery allocates a new volatile ID");
        Check.That(DurableContext(response, "DH2Q") == null && DurableContext(response, "DHnQ") == null, "reconnect resumes original promise without renewed context");
        if (cache != "batch") Check.Equal(7u, RawSmb.U32(DurableContext(response, "RqLs")!, 16), "reconnect retains lease rights");
        var retained = await c.Exchange(RawSmb.Read(restored, (uint)bytes.Length, 0, 0, 0, 0));
        Check.That(RawSmb.Buffer(retained, retained[66], RawSmb.U32(retained, 68)).SequenceEqual(bytes), "recovered backend object retains exact bytes");
        await c.Exchange(Lock(restored, 0x12, 0x13)); // Retained sequence must deduplicate the grant.
        await c.Exchange(Lock(restored, 4, 0x14)); await c.Exchange(Lock(restored, 4, 0x14));
        await c.Exchange(Lock(restored, 4, 0x15), 0xc000007e); // Exact single release, independently observed.
        await using var e = new Peer(); await e.Bind(h, c);
        await e.Exchange(RawSmb.Write(restored, [17], 0, 0, 0, 0)); await e.Exchange(RawSmb.Close(restored, 0, 0, 0));
        await c.Exchange(DurableRequest(v2, guid, cache, restored), 0xc0000034);
        Check.Equal(0, ((Smb.Server.Locking.InMemoryLockManager)o.LockManager).ActiveLockCount, "composed recovery releases locks");
        Check.Equal(0, o.CacheCoordinator.GrantCount, "composed recovery releases cache grants");
    }
    sealed class ReconnectGate(Smb.FileSystem.IFileHandle inner, AsyncBarrier gate) : Smb.FileSystem.IFileHandle
    {
        public Smb.FileSystem.FileIdentity? Identity => inner.Identity; public string Path => inner.Path; public bool IsDirectory => inner.IsDirectory;
        public string? PhysicalPath => inner.PhysicalPath; public bool DeletePending => inner.DeletePending;
        public Smb.FileSystem.FileEntryInfo GetInfo() => inner.GetInfo();
        public async ValueTask<Smb.FileSystem.FileEntryInfo> GetInfoAsync(CancellationToken ct = default) { await gate.WaitAsync(ct); return await inner.GetInfoAsync(ct); }
        public void Dispose() => inner.Dispose(); public ValueTask DisposeAsync() => inner.DisposeAsync(); public ValueTask<NtStatus> CloseAsync() => inner.CloseAsync();
    }
    sealed class ReplyGateMetrics : Smb.Server.Diagnostics.SmbServerMetrics
    {
        int armed;
        readonly ManualResetEventSlim released = new(false);
        public readonly TaskCompletionSource Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public void Arm() => Volatile.Write(ref armed, 1);
        public void Release() => released.Set();
        public override Smb.Server.Diagnostics.ISmbCommandTrace? BeginCommand(SmbCommand command)
            => command == SmbCommand.Create && Interlocked.Exchange(ref armed, 0) == 1 ? new Trace(this) : null;
        sealed class Trace(ReplyGateMetrics owner) : Smb.Server.Diagnostics.ISmbCommandTrace
        {
            public void SetStatus(NtStatus status) { owner.Entered.TrySetResult(); Check.That(owner.released.Wait(Check.Timeout), "controlled reply assembly barrier released"); }
            public void Dispose() { }
        }
    }
    static async Task DurableContention(ushort d, bool encrypted, bool v2, string mode)
    {
        using var root = new P6Tests.Root(); await using var h = Host(); var o = h.Server.State.Options;
        o.FeaturePolicy = SmbFeaturePolicy.DurableWithMultichannel; o.RequireEncryption = encrypted;
        o.Shares.Add(new Smb.FileSystem.Share { Name = "P0", FileStore = P6Tests.Local(root.Path) });
        await h.StartAsync(); await using var a = new Peer(); await a.Login(h, d, encrypted ? (ushort)1 : (ushort)0);
        await using var b = new Peer(); await b.Bind(h, a); var guid = Guid.NewGuid();
        var id = DurableId(await a.Exchange(DurableRequest(v2, guid, "batch"))); var open = h.Server.State.SessionGlobalList[a.Session].Opens[id];
        await b.Exchange(RawSmb.Write(id, [4, 5, 6], 0, 0, 0, 0));
        a.FinishSending(); b.FinishSending(); await Until(() => !h.Server.State.SessionGlobalList.ContainsKey(a.Session));
        await using var c = new Peer { Guid = a.Guid }; await c.Login(h, d, encrypted ? (ushort)1 : (ushort)0);
        await using var e = new Peer { Guid = a.Guid }; await e.Login(h, d, encrypted ? (ushort)1 : (ushort)0);
        await using var claimant = new Peer();
        if (mode == "teardown") await claimant.Bind(h, c);
        var requestPeer = mode == "teardown" ? claimant : c;
        var inner = open.LocalOpen!; var gate = new AsyncBarrier(); open.LocalOpen = new ReconnectGate(inner, gate);
        var replies = new ReplyGateMetrics(); o.Metrics = replies; if (mode == "teardown") replies.Arm();
        var first = requestPeer.Exchange(DurableRequest(v2, guid, "batch", id), mode == "teardown" ? 0xc0000034u : 0u);
        await gate.Entered.WaitAsync(Check.Timeout);
        Task<byte[]>? second = null;
        try
        {
            if (mode == "claim-race")
            {
                second = e.Exchange(DurableRequest(v2, guid, "batch", id), 0xc0000034);
                await Until(() => !e.Connection(h)!.OrdinaryRequests.IsEmpty || second.IsCompleted);
                Check.That(!first.IsCompleted && !second.IsCompleted, "second reconnect waits behind controlled first metadata preparation");
            }
            else
            {
                // The claim uses a separately authenticated channel key. Retire
                // it via primary LOGOFF while physical metadata is suspended.
                second = c.Exchange(Logoff());
                await Until(() => h.Server.State.SessionGlobalList[c.Session].Lifetime.State != OpenState.Active);
                Check.That(!first.IsCompleted, "reconnect remains physically suspended after session retirement");
                gate.Release(); await replies.Entered.Task.WaitAsync(Check.Timeout);
                await second.WaitAsync(Check.Timeout); second = null;
                Check.That(!h.Server.State.SessionGlobalList.ContainsKey(c.Session), "retirement completes before reconnect response assembly");
                replies.Release();
            }
        }
        finally { gate.Release(); replies.Release(); }
        var result = await first.WaitAsync(Check.Timeout); if (second != null) await second.WaitAsync(Check.Timeout);
        open.LocalOpen = inner;
        var owner = mode == "teardown" ? e : c;
        if (mode == "teardown") result = await e.Exchange(DurableRequest(v2, guid, "batch", id));
        var recovered = DurableId(result); Check.Equal(id.P, recovered.P, "one legitimate claim retains original identity");
        var read = await owner.Exchange(RawSmb.Read(recovered, 3, 0, 0, 0, 0));
        Check.That(RawSmb.Buffer(read, read[66], RawSmb.U32(read, 68)).SequenceEqual(new byte[] { 4, 5, 6 }), "contended reconnect retains exact bytes");
        await using var last = new Peer(); await last.Bind(h, owner); await last.Exchange(RawSmb.Close(recovered, 0, 0, 0));
        Check.Equal(0, o.CacheCoordinator.GrantCount, "contended reconnect releases cache grant");
    }
    static async Task EncryptedLogoff(ushort d)
    {
        await using var h = Host(); h.Server.State.Options.RequireEncryption = true; await h.StartAsync();
        await using var a = new Peer(); await a.Login(h, d, 1);
        await using var b = new Peer(); await b.Bind(h, a); await b.Open("encrypted-retirement");
        await b.Exchange(Logoff());
        Check.Equal(0, h.Store.ActiveHandles, "encrypted LOGOFF retires backend resources");
    }
    static async Task BreakSurvivor(ushort d, bool lease, bool sendFailure, bool encrypted)
    {
        using var root = new P6Tests.Root(); var store = P6Tests.Local(root.Path);
        await using var h = Host(); var o = h.Server.State.Options;
        o.FeaturePolicy = SmbFeaturePolicy.MultichannelWithCaching; o.RequireEncryption = encrypted;
        o.Shares.Add(new Smb.FileSystem.Share { Name = "P0", FileStore = store });
        File.WriteAllBytes(Path.Combine(root.Path, "cached"), [1, 2, 3]);
        await h.StartAsync(); await using var a = new Peer(); await a.Login(h, d, encrypted ? (ushort)1 : (ushort)0, signing: d == 0x311 ? (ushort)2 : (ushort)1);
        await using var b = new Peer(); await b.Bind(h, a);
        var request = RawSmb.Create("cached", false, 0, 0, 0); request[67] = 9;
        var leaseKey = new Smb.Protocol.Messages.LeaseKey(11, 19);
        if (lease) request = P6AdvancedTests.LeaseCreate(request, leaseKey, Smb.Protocol.Enums.LeaseState.ReadWriteHandle);
        var opened = await a.Exchange(request); Check.Equal(lease ? (byte)255 : (byte)9, opened[66], "actual TCP cache grant");
        var id = (RawSmb.U64(opened, 128), RawSmb.U64(opened, 136));
        var connection = a.Connection(h)!; var delivered = 0; var failed = 0;
        var secondary = b.Connection(h)!; var sender = secondary.SendRawAsync!;
        secondary.SendRawAsync = async (bytes, encrypt) => { if (RawSmb.U16(bytes, 12) == 18 && RawSmb.U64(bytes, 24) == ulong.MaxValue) Interlocked.Increment(ref delivered); await sender(bytes, encrypt); };
        var encryptedSender = secondary.SendEncryptedRawAsync!;
        secondary.SendEncryptedRawAsync = async (bytes, owner) => { if (RawSmb.U16(bytes, 12) == 18 && RawSmb.U64(bytes, 24) == ulong.MaxValue) Interlocked.Increment(ref delivered); await encryptedSender(bytes, owner); };
        if (sendFailure)
        {
            var primarySend = connection.SendRawAsync!;
            var primaryEncryptedSend = connection.SendEncryptedRawAsync!;
            connection.SendEncryptedRawAsync = (bytes, owner) =>
            {
                if (RawSmb.U16(bytes, 12) == 18) { Interlocked.Increment(ref failed); throw new IOException("controlled encrypted primary break send failure"); }
                return primaryEncryptedSend(bytes, owner);
            };
            connection.SendRawAsync = (bytes, encrypt) =>
            {
                if (RawSmb.U16(bytes, 12) == 18) { Interlocked.Increment(ref failed); throw new IOException("controlled primary break send failure"); }
                return primarySend(bytes, encrypt);
            };
        }
        else { a.FinishSending(); await Until(() => !h.Server.State.Connections.ContainsKey(connection.ConnectionId)); }
        Check.Equal(1, o.CacheCoordinator.GrantCount, "one-channel loss preserves cache promise");
        await using var other = new Peer(); await other.Login(h, d, encrypted ? (ushort)1 : (ushort)0);
        var overwrite = RawSmb.Create("cached", false, 0, 0, 0); RawSmb.Put32(overwrite, 100, 5); await other.SendRequest(overwrite);
        var notification = await b.Receive(); Check.Equal((ushort)18, RawSmb.U16(notification, 12), "surviving bound channel receives break");
        Check.Equal(ulong.MaxValue, RawSmb.U64(notification, 24), "unsolicited break MID");
        Check.Equal(encrypted, b.LastEncrypted, "notification retains applicable session encryption");
        // MS-SMB2 3.3.4.6/.7 SHOULD NOT sign these unsolicited notifications.
        Check.Equal(0u, RawSmb.U32(notification, 16) & 8, "unsolicited notification is unsigned");
        Check.That(notification.AsSpan(48, 16).SequenceEqual(new byte[16]), "unsolicited signature bytes are zero");
        Check.Equal(1, delivered, "exactly one delivered break"); Check.Equal(sendFailure ? 1 : 0, failed, "controlled failed-send count");
        Check.That(File.ReadAllBytes(Path.Combine(root.Path, "cached")).SequenceEqual(new byte[] { 1, 2, 3 }), "no pre-ACK overwrite");
        if (!encrypted)
        {
            var badAck = lease ? P6Tests.LeaseAck(leaseKey) : P6Tests.Ack(id, OplockLevel.None);
            b.Route(badAck); b.Sign(badAck); badAck[48] ^= 1; await b.Send(badAck); var denied = await b.Receive(); Status(denied, Denied); b.Verify(denied);
            Check.Equal(1, o.CacheCoordinator.BreakingCount, "invalid ACK signature cannot finish a break");
        }
        await b.Exchange(lease ? P6Tests.LeaseAck(leaseKey) : P6Tests.Ack(id, OplockLevel.None));
        var final = await other.Receive(); if (RawSmb.U32(final, 8) == 0x103) final = await other.Receive();
        Status(final, 0); if (encrypted) Check.That(other.LastEncrypted, "overwrite completion retains encryption"); else other.Verify(final); Check.Equal(RawSmb.U64(overwrite, 24), RawSmb.U64(final, 24), "single overwrite completion MID");
        Check.Equal(0L, new FileInfo(Path.Combine(root.Path, "cached")).Length, "overwrite only after ACK");
        await other.Exchange(RawSmb.Close((RawSmb.U64(final, 128), RawSmb.U64(final, 136)), 0, 0, 0));
        await b.Exchange(RawSmb.Close(id, 0, 0, 0));
        Check.Equal(0, o.CacheCoordinator.GrantCount, "all grants released"); Check.Equal(0, o.CacheCoordinator.BreakingCount, "no pending breaks");
        Check.Equal(0, o.CacheCoordinator.PhysicalScopeCount, "no physical I/O scope leaks");
        Check.Equal(1, delivered, "no duplicate break after completion and cleanup");
    }
    sealed class GatedAuth(ISpnegoNegotiator inner) : ISpnegoNegotiator
    {
        int remaining;
        readonly ManualResetEventSlim release = new(false);
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public void Arm(int count = 1) => remaining = count;
        public void Release() => release.Set();
        public byte[] CreateInitialServerToken() => inner.CreateInitialServerToken();
        public ISpnegoServerContext CreateServerContext() => new Context(this, inner.CreateServerContext());
        sealed class Context(GatedAuth owner, ISpnegoServerContext inner) : ISpnegoServerContext
        {
            public GssResult Accept(ReadOnlySpan<byte> token)
            {
                var result = inner.Accept(token);
                if (result.IsSuccess && Volatile.Read(ref owner.remaining) > 0)
                {
                    if (Interlocked.Decrement(ref owner.remaining) == 0) owner.Entered.TrySetResult();
                    if (!owner.release.Wait(Check.Timeout)) throw new TimeoutException("controlled authentication release");
                }
                return result;
            }
        }
    }
    static async Task BindRace(ushort d, string mode)
    {
        await using var h = Host(); var o = h.Server.State.Options; var auth = new GatedAuth(o.SpnegoNegotiator!); o.SpnegoNegotiator = auth;
        if (mode == "limit") o.MaxChannelsPerSession = 2;
        await h.StartAsync(); await using var a = new Peer(); await a.Login(h, d);
        var session = h.Server.State.SessionGlobalList[a.Session];
        await using var b = new Peer(); await using var c = new Peer();
        auth.Arm(mode == "limit" ? 2 : 1);
        async Task<uint> Bind(Peer peer)
        {
            try { await peer.Bind(h, a); return 0; }
            catch (InvalidOperationException) when (peer.LastStatus == (mode == "limit" ? 0xc000009au : 0xc00000d0u)) { return peer.LastStatus; }
        }
        var bind = Bind(b); var other = mode == "limit" ? Bind(c) : Task.FromResult(0u);
        await auth.Entered.Task.WaitAsync(Check.Timeout);
        Task? retire = null;
        try
        {
            if (mode == "logoff") retire = a.Exchange(Logoff());
            else if (mode == "last-loss") a.FinishSending();
            else if (mode == "shutdown") retire = h.Server.StopAsync(TimeSpan.FromSeconds(1));
            if (mode != "limit") await Until(() => session.Lifetime.State != OpenState.Active);
        }
        finally { auth.Release(); }
        if (mode == "limit")
        {
            var statuses = await Task.WhenAll(bind, other).WaitAsync(Check.Timeout);
            Check.Equal(1, statuses.Count(x => x == 0), "exactly one concurrent final obtains last channel slot");
            Check.Equal(1, statuses.Count(x => x == 0xc000009a), "losing final reports channel resource exhaustion");
            Check.Equal(2, session.Channels.Count, "channel limit publication is atomic");
        }
        else
        {
            Check.Equal(0xc00000d0u, await bind.WaitAsync(Check.Timeout), "retirement rejects in-flight authenticated binder");
            if (retire != null) await retire.WaitAsync(Check.Timeout);
            await Until(() => !h.Server.State.SessionGlobalList.ContainsKey(a.Session));
            Check.That(session.Channels.IsEmpty, "retired session cannot be revived by late authentication");
        }
        Check.That(h.Server.State.Connections.Values.All(x => x.PendingBindings.IsEmpty), "race leaves no pending authentication entries");
        Check.Equal(0, h.Store.ActiveHandles, "race leaves no backend resources");
    }
    static async Task CryptoBoundary(bool required)
    {
        await using var h = Host(); h.Server.State.Options.RequireEncryption = required; await h.StartAsync();
        await using var a = new Peer(); await a.Login(h, 0x311, 1);
        await using var b = new Peer(); await b.Negotiate(h, 0x311, required ? (ushort)0 : (ushort)4, guid: a.Guid);
        b.Session = a.Session; b.Key = a.Key;
        // The session's cipher keys are immutable. A channel cannot use a different
        // key width or omit encryption when the session requires it. NOT_SUPPORTED
        // is the bounded profile's width-mismatch rejection, not a spec-mandated code.
        await b.Exchange(b.Setup(new NtlmClient(HostFixture.Domain, HostFixture.User, HostFixture.Password).BuildNegotiate()), required ? Denied : 0xc00000bb, setup: true);
        var id = await a.Open("crypto-preserved"); await a.Exchange(RawSmb.Close(id, 0, 0, 0));
        Check.Equal(1, h.Server.State.SessionGlobalList[a.Session].Channels.Count, "unusable cryptographic channel never attached");
    }
    static async Task Until(Func<bool> condition)
    {
        using var c = new CancellationTokenSource(Check.Timeout);
        while (!condition()) await Task.Delay(10, c.Token);
    }
    static async Task Lifecycle(ushort d, string mode)
    {
        await using var h = Host(mode != "optional-signature"); await h.StartAsync();
        await using var a = new Peer(); await a.Login(h, d, mode == "mixed-cipher" ? (ushort)1 : (ushort)0);
        var session = h.Server.State.SessionGlobalList[a.Session];
        if (mode == "limit")
        {
            var peers = new List<Peer>();
            try
            {
                for (var i = 1; i < 32; i++) { var peer = new Peer(); peers.Add(peer); await peer.Bind(h, a); }
                await using var extra = new Peer();
                await extra.Negotiate(h, d, guid: a.Guid); extra.Session = a.Session; extra.Key = a.Key;
                await extra.Exchange(extra.Setup(new NtlmClient(HostFixture.Domain, HostFixture.User, HostFixture.Password).BuildNegotiate()), 0xc000009a, setup: true);
                Check.Equal(32, session.Channels.Count, "bounded channel admission");
            }
            finally { foreach (var peer in peers) await peer.DisposeAsync(); }
            return;
        }
        await using var b = new Peer();
        if (mode is "pending-loss" or "pending-logoff")
        {
            await b.Negotiate(h, d, guid: a.Guid); b.Session = a.Session; b.Key = a.Key;
            await b.Exchange(b.Setup(new NtlmClient(HostFixture.Domain, HostFixture.User, HostFixture.Password).BuildNegotiate()), More, setup: true);
            var connection = b.Connection(h)!; Check.Equal(1, connection.PendingBindings.Count, "real binding pending");
            if (mode == "pending-loss") { b.FinishSending(); await Until(() => !h.Server.State.Connections.ContainsKey(connection.ConnectionId)); }
            else { await a.Exchange(Logoff()); }
            Check.Equal(0, connection.PendingBindings.Count, "connection/session retirement clears incomplete bindings");
            if (mode == "pending-loss") { var live = await a.Open("live"); await a.Exchange(RawSmb.Close(live, 0, 0, 0)); }
            return;
        }
        await b.Bind(h, a, mode == "mixed-signing" && d == 0x311 ? (ushort)2 : null,
            mode == "mixed-cipher" && d == 0x311 ? (ushort)2 : null);
        if (mode is "mixed-signing" or "mixed-cipher")
        {
            var live = await a.Open("mixed"); await b.Exchange(RawSmb.Write(live, [2, 4, 6], 0, 0, 0, 0), encrypt: mode == "mixed-cipher");
            await b.Exchange(RawSmb.Close(live, 0, 0, 0), encrypt: mode == "mixed-cipher"); return;
        }
        var id = await a.Open("life"); await a.Exchange(RawSmb.Write(id, [1, 2, 3], 0, 0, 0, 0));
        if (mode == "optional-signature")
        {
            var bad = RawSmb.Write(id, [9], 0, 0, 0, 0); b.Route(bad); b.Sign(bad); bad[48] ^= 1;
            await b.Send(bad); Status(await b.Receive(), Denied);
            Check.That(h.Store.Contents("life").SequenceEqual(new byte[] { 1, 2, 3 }), "invalid signed packet cannot mutate optional-signing session");
        }
        else if (mode == "transcript")
        {
            // A third connection uses a transcript with a corrupted challenge signature
            // only in its local KDF. Authentication packets themselves remain valid.
            await using var c = new Peer(); await c.Bind(h, b);
            var good = c.Key; c.Key = d == 0x311 ? c.BadTranscriptKey : Kdf(good, "SMB2AESCMAC", "SmbSign\0"u8.ToArray());
            Check.That(!good.SequenceEqual(c.Key), "a changed challenge byte produces a different transcript key");
            await c.Exchange(RawSmb.Write(id, [9], 0, 0, 0, 0), Denied, responseKey: good);
            c.Key = good; await c.Exchange(RawSmb.Write(id, [4], 0, 0, 0, 0));
        }
        else if (mode is "logoff" or "shutdown" or "last-loss")
        {
            if (mode == "logoff") { await b.Exchange(Logoff()); await a.Exchange(RawSmb.Close(id, 0, 0, 0), Deleted); }
            else if (mode == "last-loss") { a.FinishSending(); b.FinishSending(); await Until(() => !h.Server.State.SessionGlobalList.ContainsKey(a.Session)); await Until(() => h.Store.ActiveHandles == 0); }
            else await h.Server.StopAsync(TimeSpan.FromSeconds(1)).WaitAsync(Check.Timeout);
            Check.Equal(0, h.Store.ActiveHandles, "session retirement releases all opens");
            Check.That(session.Channels.IsEmpty && session.Opens.IsEmpty, "session retirement leaves no channels/opens"); return;
        }
        else if (mode is "close-race" or "cancel")
        {
            var barrier = new AsyncBarrier(); h.Store.Control.Enqueue("Read", new OperationStep(Barrier: barrier, IgnoreCancellation: true));
            var read = RawSmb.Read(id, 3, 0, 0, 0, 0); a.Route(read); a.Sign(read); await a.Send(read); await barrier.Entered.WaitAsync(Check.Timeout);
            try
            {
                if (mode == "close-race")
                {
                    var close = b.Exchange(RawSmb.Close(id, 0, 0, 0));
                    await Until(() => session.Opens.Values.Single().Lifetime.State != OpenState.Active);
                    Check.That(!close.IsCompleted, "cross-channel CLOSE waits for physical READ");
                    barrier.Release(); await a.Receive(); await close.WaitAsync(Check.Timeout); return;
                }
                var cancel = RawSmb.Header(12, 4, RawSmb.U64(read, 24), a.Session, a.Tree); RawSmb.Put16(cancel, 64, 4); a.Sign(cancel); await a.Send(cancel);
                Status(await a.Receive(), 0xc0000120); Check.Equal(1, h.Store.ActiveHandles, "cancellation keeps physical handle alive");
            }
            finally { barrier.Release(); }
        }
        else if (mode == "survivor")
        {
            var connection = a.Connection(h)!; a.FinishSending(); await Until(() => !h.Server.State.Connections.ContainsKey(connection.ConnectionId));
            Check.Equal(1, session.Channels.Count, "one channel loss preserves survivor");
            await using var c = new Peer(); await c.Bind(h, b); await c.Exchange(RawSmb.Write(id, [8], 0, 0, 0, 0));
        }
        await b.Exchange(RawSmb.Close(id, 0, 0, 0));
        Check.Equal(0, h.Store.ActiveHandles, "lifecycle returns backend handles");
    }
    static byte[] Logoff() { var b = RawSmb.Header(2, 4, 0); RawSmb.Put16(b, 64, 4); return b; }
    internal static byte[] Kdf(byte[] key, string label, byte[] context, int length = 16)
    {
        var l = Encoding.ASCII.GetBytes(label + "\0"); var input = new byte[4 + l.Length + 1 + context.Length + 4];
        BinaryPrimitives.WriteUInt32BigEndian(input, 1); l.CopyTo(input, 4); context.CopyTo(input, 5 + l.Length);
        BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(input.Length - 4), (uint)(length * 8));
        return HMACSHA256.HashData(key, input)[..length];
    }
    static byte[] Cmac(byte[] key, byte[] data)
    {
        using var aes = Aes.Create(); aes.Key = key;
        byte[] Double(byte[] x) { var r = new byte[16]; for (int i = 15, carry = 0; i >= 0; i--) { r[i] = (byte)((x[i] << 1) | carry); carry = x[i] >> 7; } if ((x[0] & 128) != 0) r[15] ^= 0x87; return r; }
        var k1 = Double(aes.EncryptEcb(new byte[16], PaddingMode.None)); var k2 = Double(k1);
        var count = Math.Max(1, (data.Length + 15) / 16); var state = new byte[16];
        for (var i = 0; i < count; i++)
        {
            var block = new byte[16]; var n = Math.Min(16, data.Length - i * 16); data.AsSpan(i * 16, n).CopyTo(block);
            if (i == count - 1) { var sub = n == 16 ? k1 : k2; if (n != 16) block[n] = 128; for (var j = 0; j < 16; j++) block[j] ^= sub[j]; }
            for (var j = 0; j < 16; j++) block[j] ^= state[j]; state = aes.EncryptEcb(block, PaddingMode.None);
        }
        return state;
    }
    internal sealed class Peer : IAsyncDisposable
    {
        readonly TcpClient socket = new(); ulong mid; ulong nonce;
        byte[] hash = new byte[64], badHash = new byte[64]; public byte[] BadTranscriptKey = []; public byte[] Guid = System.Guid.NewGuid().ToByteArray();
        public ulong Session; public uint Tree, ServerCapabilities, LastStatus; public ushort Dialect, Cipher, Algorithm = 1;
        public bool EncryptAll, LastEncrypted;
        public byte[] Key = [], OriginalKey = [], EncryptKey = [], DecryptKey = [];
        public void Hash(byte[] b)
        {
            if (Dialect != 0x311) return;
            hash = SHA512.HashData(hash.Concat(b).ToArray());
            var altered = b.ToArray();
            if (RawSmb.U16(b, 12) == 1 && RawSmb.U32(b, 8) == More && (RawSmb.U32(b, 16) & 8) != 0) altered[48] ^= 1;
            badHash = SHA512.HashData(badHash.Concat(altered).ToArray());
        }
        public byte[] SigningKey(byte[] auth) => Kdf(auth, Dialect == 0x311 ? "SMBSigningKey" : "SMB2AESCMAC", Dialect == 0x311 ? hash : "SmbSign\0"u8.ToArray());
        public void Route(byte[] b, bool setup = false) { RawSmb.Put64(b, 24, mid++); RawSmb.Put64(b, 40, Session); RawSmb.Put32(b, 36, setup ? 0 : Tree); }
        byte[] Signature(byte[] b, byte[] key)
        {
            var copy = b.ToArray(); copy.AsSpan(48, 16).Clear();
            if (Algorithm == 0) return HMACSHA256.HashData(key, copy)[..16];
            if (Algorithm == 1) return Cmac(key, copy);
            var iv = new byte[12]; BinaryPrimitives.WriteUInt64LittleEndian(iv, RawSmb.U64(b, 24));
            RawSmb.Put32(iv, 8, (RawSmb.U32(b, 16) & 1) | (RawSmb.U16(b, 12) == 12 ? 2u : 0));
            using var aes = new AesGcm(key, 16); var tag = new byte[16]; aes.Encrypt(iv.AsSpan(), ReadOnlySpan<byte>.Empty, Span<byte>.Empty, tag, copy); return tag;
        }
        public void Sign(byte[] b, byte[]? key = null) { key ??= Key; if (key.Length == 0) return; RawSmb.Put32(b, 16, RawSmb.U32(b, 16) | 8); Signature(b, key).CopyTo(b, 48); }
        public void Verify(byte[] b, byte[]? key = null) { Check.That((RawSmb.U32(b, 16) & 8) != 0, "response signature is present"); Check.That(Signature(b, key ?? Key).SequenceEqual(b.AsSpan(48, 16).ToArray()), "independent response signature"); }
        public async Task Send(byte[] b)
        {
            using var c = new CancellationTokenSource(Check.Timeout); var frame = new byte[b.Length + 4]; frame[1] = (byte)(b.Length >> 16); frame[2] = (byte)(b.Length >> 8); frame[3] = (byte)b.Length; b.CopyTo(frame, 4);
            await socket.GetStream().WriteAsync(frame, c.Token);
        }
        public async Task<byte[]> Receive()
        {
            using var c = new CancellationTokenSource(Check.Timeout); var head = new byte[4]; await socket.GetStream().ReadExactlyAsync(head, c.Token);
            var n = head[1] << 16 | head[2] << 8 | head[3]; Check.That(head[0] == 0 && n is >= 52 and <= 1048576, "TCP frame bound");
            var b = new byte[n]; await socket.GetStream().ReadExactlyAsync(b, c.Token);
            LastEncrypted = b[0] == 0xfd;
            if (LastEncrypted) return Crypt(b, false);
            HashResponse(b); return b;
        }
        void HashResponse(byte[] b) { if (RawSmb.U16(b, 12) == 0 || RawSmb.U16(b, 12) == 1 && RawSmb.U32(b, 8) == More) Hash(b); }
        byte[] Crypt(byte[] b, bool encrypt)
        {
            var gcm = Cipher is 2 or 4; var nonceLength = gcm ? 12 : 11;
            var frame = encrypt ? new byte[52 + b.Length] : b; var plain = encrypt ? b : new byte[b.Length - 52];
            if (encrypt) { frame[0] = 0xfd; frame[1] = 0x53; frame[2] = 0x4d; frame[3] = 0x42; RandomNumberGenerator.Fill(frame.AsSpan(20, nonceLength)); BinaryPrimitives.WriteUInt64LittleEndian(frame.AsSpan(20), ++nonce); RawSmb.Put32(frame, 36, (uint)b.Length); RawSmb.Put16(frame, 42, 1); RawSmb.Put64(frame, 44, Session); }
            else { Check.Equal(Session, RawSmb.U64(frame, 44), "transform session"); Check.Equal((uint)plain.Length, RawSmb.U32(frame, 36), "transform size"); Check.Equal((ushort)1, RawSmb.U16(frame, 42), "transform flags"); }
            var key = encrypt ? EncryptKey : DecryptKey;
            if (gcm) { using var aes = new AesGcm(key, 16); if (encrypt) aes.Encrypt(frame.AsSpan(20, nonceLength), plain, frame.AsSpan(52), frame.AsSpan(4, 16), frame.AsSpan(20, 32)); else aes.Decrypt(frame.AsSpan(20, nonceLength), frame.AsSpan(52), frame.AsSpan(4, 16), plain, frame.AsSpan(20, 32)); }
            else { using var aes = new AesCcm(key); if (encrypt) aes.Encrypt(frame.AsSpan(20, nonceLength), plain, frame.AsSpan(52), frame.AsSpan(4, 16), frame.AsSpan(20, 32)); else aes.Decrypt(frame.AsSpan(20, nonceLength), frame.AsSpan(52), frame.AsSpan(4, 16), plain, frame.AsSpan(20, 32)); }
            return encrypt ? frame : plain;
        }
        public async Task SendRequest(byte[] b)
        {
            Route(b); Sign(b); await Send(EncryptAll ? Crypt(b, true) : b);
        }
        public async Task<byte[]> Exchange(byte[] b, uint status = 0, bool setup = false, bool encrypt = false, byte[]? signingKey = null, byte[]? responseKey = null)
        {
            encrypt |= EncryptAll && !setup && RawSmb.U16(b, 12) != 0;
            Route(b, setup); Sign(b, signingKey); Hash(b); await Send(encrypt ? Crypt(b, true) : b); var response = await Receive();
            if (encrypt) Check.That(LastEncrypted, "encrypted request receives authenticated encrypted response");
            Check.Equal(RawSmb.U64(b, 24), RawSmb.U64(response, 24), "TCP response MID"); LastStatus = RawSmb.U32(response, 8); Status(response, status);
            if (!setup && Key.Length != 0 && !encrypt && status != Deleted) Verify(response, responseKey); return response;
        }
        public async Task Negotiate(HostFixture h, ushort d, ushort cipher = 0, ushort signing = 1, byte[]? guid = null, uint caps = 8)
        {
            using var c = new CancellationTokenSource(Check.Timeout); await socket.ConnectAsync(h.Server.Endpoint, c.Token); Dialect = d; Cipher = cipher; Algorithm = d == 0x311 ? signing : (ushort)1; Guid = guid ?? Guid;
            var b = RawSmb.Negotiate(); RawSmb.Put16(b, 100, d); RawSmb.Put16(b, 68, 1); RawSmb.Put32(b, 72, caps | (cipher != 0 ? 64u : 0)); Guid.CopyTo(b, 76);
            if (d == 0x311)
            {
                Array.Resize(ref b, cipher != 0 ? 148 : 132); RawSmb.Put32(b, 92, 104); RawSmb.Put16(b, 96, cipher != 0 ? (ushort)3 : (ushort)2);
                RawSmb.Put16(b, 104, 1); RawSmb.Put16(b, 106, 6); RawSmb.Put16(b, 112, 1); RawSmb.Put16(b, 116, 1);
                RawSmb.Put16(b, 120, 8); RawSmb.Put16(b, 122, 4); RawSmb.Put16(b, 128, 1); RawSmb.Put16(b, 130, signing);
                if (cipher != 0) { RawSmb.Put16(b, 136, 2); RawSmb.Put16(b, 138, 4); RawSmb.Put16(b, 144, 1); RawSmb.Put16(b, 146, cipher); }
            }
            var r = await Exchange(b); Check.Equal(d, RawSmb.U16(r, 68), "negotiated dialect"); ServerCapabilities = RawSmb.U32(r, 88);
        }
        public byte[] Setup(byte[] token) { var b = RawSmb.SessionSetup(token, 0, Session); b[66] = 1; return b; }
        public async Task Login(HostFixture h, ushort d, ushort cipher = 0, ushort signing = 1, string user = HostFixture.User)
        {
            await Negotiate(h, d, cipher, signing); var ntlm = new NtlmClient(HostFixture.Domain, user, HostFixture.Password);
            var r = await Exchange(RawSmb.SessionSetup(ntlm.BuildNegotiate(), 0), More, true); Session = RawSmb.U64(r, 40);
            r = await Exchange(RawSmb.SessionSetup(ntlm.BuildAuthenticate(RawSmb.Buffer(r, RawSmb.U16(r, 68), RawSmb.U16(r, 70))), 0, Session), setup: true);
            OriginalKey = Key = SigningKey(ntlm.ExportedSessionKey); Verify(r); EncryptAll = (RawSmb.U16(r, 66) & 4) != 0;
            if (cipher != 0) { var auth = ntlm.ExportedSessionKey; var size = cipher >= 3 ? 32 : 16; EncryptKey = Kdf(auth, d == 0x311 ? "SMBC2SCipherKey" : "SMB2AESCCM", d == 0x311 ? hash : "ServerIn \0"u8.ToArray(), size); DecryptKey = Kdf(auth, d == 0x311 ? "SMBS2CCipherKey" : "SMB2AESCCM", d == 0x311 ? hash : "ServerOut\0"u8.ToArray(), size); }
            r = await Exchange(RawSmb.TreeConnect("\\\\localhost\\P0", 0, Session)); Tree = RawSmb.U32(r, 36);
        }
        public async Task Bind(HostFixture h, Peer a, ushort? signing = null, ushort? cipher = null)
        {
            await Negotiate(h, a.Dialect, cipher ?? a.Cipher, signing ?? a.Algorithm, a.Guid); Session = a.Session; Tree = a.Tree; OriginalKey = a.OriginalKey; Key = OriginalKey; EncryptKey = a.EncryptKey; DecryptKey = a.DecryptKey; EncryptAll = a.EncryptAll;
            var ntlm = new NtlmClient(HostFixture.Domain, HostFixture.User, HostFixture.Password);
            var r = await Exchange(Setup(ntlm.BuildNegotiate()), More, true); Verify(r, OriginalKey);
            r = await Exchange(Setup(ntlm.BuildAuthenticate(RawSmb.Buffer(r, RawSmb.U16(r, 68), RawSmb.U16(r, 70)))), setup: true, signingKey: OriginalKey);
            Key = SigningKey(ntlm.ExportedSessionKey); Verify(r);
            BadTranscriptKey = Kdf(ntlm.ExportedSessionKey, "SMBSigningKey", badHash);
        }
        public SmbConnection? Connection(HostFixture h) => h.Server.State.Connections.Values.SingleOrDefault(x => x.ClientAddress?.EndsWith(((System.Net.IPEndPoint)socket.Client.LocalEndPoint!).Port.ToString()) == true);
        public async Task<(ulong P, ulong V)> Open(string name, bool directory = false) { var request = RawSmb.Create(name, directory, 0, 0, 0); RawSmb.Put32(request, 88, directory ? 3u : 0x10003u); var b = await Exchange(request); return (RawSmb.U64(b, 128), RawSmb.U64(b, 136)); }
        public void FinishSending() => socket.Client.Shutdown(SocketShutdown.Send);
        public ValueTask DisposeAsync() { socket.Dispose(); return ValueTask.CompletedTask; }
    }
}
