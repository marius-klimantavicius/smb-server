using System.Net;
using System.Diagnostics;
using System.Reflection;
using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.FileSystem;
using Smb.FileSystem.Sqlite;
using Smb.Host;
using Smb.Persistence.Sqlite;
using Smb.Server;
using Smb.Server.Recovery;
using Smb.Testing;

internal static partial class DurableRecoveryTcpTests
{
    public static IEnumerable<(string Name, Func<Task> Run)> PersistenceCases()
    {
        yield return ("recovery.tcp.active-shutdown", ActiveShutdown);
        yield return ("recovery.tcp.duplicate-create-guid", DuplicateCreateGuid);
        yield return ("recovery.tcp.expiry-pending", ExpiryPending);
        yield return ("recovery.tcp.delete-pending", DeletePendingRestart);
        yield return ("recovery.startup.backend-mismatch", BackendMismatch);
        yield return ("recovery.tcp.failed-cache-invalidation", FailedCacheInvalidation);
        yield return ("recovery.tcp.failed-close", FailedClose);
        yield return ("recovery.tcp.process-kill.batch", () => ProcessKill(0));
        yield return ("recovery.tcp.process-kill.lease", () => ProcessKill(7));
        foreach (var dialect in new ushort[] { 0x202, 0x210, 0x300, 0x302, 0x311 })
        {
            var d = dialect;
            yield return ($"recovery.tcp.restart.{d:x}.batch", () => Restart(d, 0));
            if (d >= 0x210) yield return ($"recovery.tcp.restart.{d:x}.lease", () => Restart(d, 7));
        }
    }
    sealed class RestartServer : IAsyncDisposable
    {
        internal readonly SqliteFileStore Files;
        internal readonly SqliteServerRecoveryStore Journal;
        internal readonly SmbServer Server;
        internal readonly FailingRecoveryStore Adapter;
        internal RestartServer(RecoveryPersistenceTests.Root root, TimeProvider? clock = null) : this(root.Path, clock) { }
        internal RestartServer(string directory, TimeProvider? clock = null)
        {
            Files = new(System.IO.Path.Combine(directory, "files.db")); Journal = new(System.IO.Path.Combine(directory, "recovery.db"));
            Adapter = new FailingRecoveryStore(Journal);
            Server = SmbServerBuilder.Create().WithEndpoint(IPAddress.Loopback, 0)
                .UseAuthentication(new NtlmSpnegoNegotiator(new InMemoryIdentityBackend()
                    .AddUser(HostFixture.Domain, HostFixture.User, HostFixture.Password)
                    .AddUser(HostFixture.Domain, "foreign", HostFixture.Password)))
                .AddShare(new Share { Name = "P0", FileStore = Files })
                .Configure(o => { o.FeaturePolicy = SmbFeaturePolicy.Durable; o.DurableHandleTimeout = TimeSpan.FromSeconds(60); o.TimeProvider = clock ?? TimeProvider.System; })
                .UseServerRecoveryStore(Adapter).Build();
        }
        public async ValueTask DisposeAsync()
        { await Server.StopAsync(TimeSpan.Zero).WaitAsync(Check.Timeout); await Server.DisposeAsync(); Journal.Dispose(); Files.Dispose(); }
    }
    static async Task Restart(ushort dialect, uint lease)
    {
        using var root = new RecoveryPersistenceTests.Root(); var client = Guid.NewGuid(); var create = Guid.NewGuid(); var v1 = dialect < 0x300;
        (ulong P, ulong V) id; ulong oldSession; Guid serverIdentity;
        await using (var first = new RestartServer(root))
        {
            await first.Server.StartAsync(); await using var peer = new Peer(); await peer.Login(first.Server.Endpoint, dialect, client);
            var request = Request(v1, create, lease);
            id = Id(await peer.Exchange(request)); oldSession = peer.Session;
            await peer.Exchange(RawSmb.Write(id, Payload, 0, 0, 0, 0));
            await peer.Exchange(Lock(id, 0x10, 0x12)); serverIdentity = first.Journal.ServerGuid;
        }
        await using (var second = new RestartServer(root))
        {
            await second.Server.StartAsync(); Check.Equal(serverIdentity, second.Journal.ServerGuid, "stable server identity");
            var retained = second.Journal.LoadHandles().Single();
            var identity = new FileIdentity(retained.ObjectId, retained.StreamId).Key;
            var probe = new Smb.Server.State.SmbOpen { VolatileFileId = 123, ShareModeKey = identity };
            Check.That(!second.Server.State.Options.LockManager.IsRangeAccessible(probe, 0, 1, false), "recovered lock protects bytes before reconnect");
            Check.That(!second.Server.State.Options.ShareModeManager.TryOpen(identity, probe, FileAccessIntent.ReadWrite, Smb.Server.Sharing.FileShareMode.None), "sharing reservation restored before reconnect");
            await using var foreign = new Peer(); await foreign.Login(second.Server.Endpoint, dialect, client, user: "foreign");
            await foreign.Exchange(Reconnect(id, create, v1, lease), 0xc0000022);
            await using var owner = new Peer(); await owner.Login(second.Server.Endpoint, dialect, client);
            Check.That(oldSession != owner.Session, "fresh authentication uses a new session ID");
            var restored = Id(await owner.Exchange(Reconnect(id, create, v1, lease)));
            Check.Equal(id.P, restored.P, "durable persistent part retained");
            var response = await owner.Exchange(RawSmb.Read(restored, (uint)Payload.Length, 0, 0, 0, 0));
            Check.That(Payload.SequenceEqual(RawSmb.Buffer(response, response[66], RawSmb.U32(response, 68))), "bytes after restart");
            await owner.Exchange(Lock(restored, 0x10, 0x12), dialect == 0x202 ? 0xc0000055u : 0u); // SMB202 has no lock-sequence replay
            await owner.Exchange(Lock(restored, 0x11, 4));
            await owner.Exchange(RawSmb.Close(restored, 0, 0, 0));
            Check.Equal(0, second.Journal.LoadHandles().Count, "explicit CLOSE removes restart record");
        }
    }
    sealed class FailingRecoveryStore(IServerRecoveryStore inner) : IServerRecoveryStore
    {
        internal bool FailRemove;
        public Guid ServerGuid => inner.ServerGuid;
        public ulong AllocateId(RecoveryIdKind kind) => inner.AllocateId(kind);
        public void SaveSession(RecoverySessionRecord s) => inner.SaveSession(s);
        public void RetireSession(ulong s) => inner.RetireSession(s);
        public void SaveHandle(RecoveryHandleRecord h) => inner.SaveHandle(h);
        public void RemoveHandle(ulong p) { if (FailRemove) throw new IOException("injected journal removal failure"); inner.RemoveHandle(p); }
        public IReadOnlyList<RecoveryHandleRecord> LoadHandles() => inner.LoadHandles();
    }
    static async Task ActiveShutdown()
    {
        using var root = new RecoveryPersistenceTests.Root(); var client = Guid.NewGuid(); var create = Guid.NewGuid(); (ulong P, ulong V) id;
        await using (var first = new RestartServer(root))
        {
            await first.Server.StartAsync(); await using var owner = new Peer(); await owner.Login(first.Server.Endpoint, 0x311, client);
            id = Id(await owner.Exchange(Request(false, create))); await owner.Exchange(RawSmb.Write(id, Payload, 0, 0, 0, 0));
            var receive = owner.Receive(); await first.Server.StopAsync(TimeSpan.Zero).WaitAsync(Check.Timeout);
            var disconnected = false;
            try { await receive; } catch (IOException) { disconnected = true; }
            Check.That(disconnected, "recoverable shutdown retains caching promise and closes transport without a break");
        }
        await using (var second = new RestartServer(root))
        {
            await second.Server.StartAsync(); await using var owner = new Peer(); await owner.Login(second.Server.Endpoint, 0x311, client);
            var restored = Id(await owner.Exchange(Reconnect(id, create, false))); await owner.Exchange(RawSmb.Close(restored, 0, 0, 0));
        }
    }
    static async Task DuplicateCreateGuid()
    {
        using var root = new RecoveryPersistenceTests.Root(); var client = Guid.NewGuid(); var create = Guid.NewGuid(); (ulong P, ulong V) id;
        await using (var first = new RestartServer(root))
        {
            await first.Server.StartAsync(); await using var peer = new Peer(); await peer.Login(first.Server.Endpoint, 0x311, client);
            id = Id(await peer.Exchange(Request(false, create))); var session = peer.Session; await peer.DisposeAsync();
            await Eventually(() => !first.Server.State.SessionGlobalList.ContainsKey(session), "replay owner detached");
        }
        await using (var second = new RestartServer(root))
        {
            await second.Server.StartAsync(); await using var peer = new Peer(); await peer.Login(second.Server.Endpoint, 0x311, client);
            await peer.Exchange(Request(false, create), 0xc000022a);
            var replay = Request(false, create); RawSmb.Put32(replay, 16, RawSmb.U32(replay, 16) | 0x20000000);
            await peer.Exchange(replay, 0xc000022a);
            var restored = Id(await peer.Exchange(Reconnect(id, create, false))); await peer.Exchange(RawSmb.Close(restored, 0, 0, 0));
        }
    }
    static async Task FailedCacheInvalidation()
    {
        using var root = new RecoveryPersistenceTests.Root(); await using var host = new RestartServer(root);
        await host.Server.StartAsync(); await using var owner = new Peer(); await owner.Login(host.Server.Endpoint, 0x311, Guid.NewGuid());
        var id = Id(await owner.Exchange(Request(false, Guid.NewGuid())));
        await owner.Exchange(RawSmb.Write(id, Payload, 0, 0, 0, 0)); host.Adapter.FailRemove = true;
        await using var peer = new Peer(); await peer.Login(host.Server.Endpoint, 0x311, Guid.NewGuid());
        var overwrite = RawSmb.Create("file", false, 0, 0, 0); RawSmb.Put32(overwrite, 100, 4);
        await peer.Exchange(overwrite, 0xc000000d);
        Check.Equal(1, host.Journal.LoadHandles().Count, "failed invalidation preserves original promise");
        host.Adapter.FailRemove = false;
        var read = await owner.Exchange(RawSmb.Read(id, (uint)Payload.Length, 0, 0, 0, 0));
        Check.That(Payload.SequenceEqual(RawSmb.Buffer(read, read[66], RawSmb.U32(read, 68))), "journal failure prevents destructive mutation");
        await owner.Exchange(RawSmb.Close(id, 0, 0, 0));
    }
    static async Task FailedClose()
    {
        using var root = new RecoveryPersistenceTests.Root(); await using var host = new RestartServer(root);
        await host.Server.StartAsync(); await using var peer = new Peer(); await peer.Login(host.Server.Endpoint, 0x311, Guid.NewGuid());
        var id = Id(await peer.Exchange(Request(false, Guid.NewGuid()))); host.Adapter.FailRemove = true;
        await peer.Exchange(RawSmb.Close(id, 0, 0, 0), 0xc000000d);
        Check.Equal(1, host.Journal.LoadHandles().Count, "failed journal close cannot acknowledge retirement");
        host.Adapter.FailRemove = false; await peer.Exchange(RawSmb.Close(id, 0, 0, 0));
        Check.Equal(0, host.Journal.LoadHandles().Count, "retry removes journal record");
    }
    static async Task ExpiryPending()
    {
        using var root = new RecoveryPersistenceTests.Root(); var clock = new ManualClock(); var client = Guid.NewGuid(); var create = Guid.NewGuid(); (ulong P, ulong V) id;
        await using (var first = new RestartServer(root, clock))
        {
            await first.Server.StartAsync(); await using var peer = new Peer(); await peer.Login(first.Server.Endpoint, 0x311, client);
            var request = Request(false, create); RawSmb.Put32(request, 88, 0x10003);
            id = Id(await peer.Exchange(request));
            await peer.Exchange(Set(id, 13, new byte[] { 1 }));
            var session = peer.Session; await peer.DisposeAsync();
            await Eventually(() => !first.Server.State.SessionGlobalList.ContainsKey(session), "pending session detached");
        }
        clock.Advance(TimeSpan.FromSeconds(3));
        await using (var second = new RestartServer(root, clock))
        {
            await second.Server.StartAsync(); Check.Equal(0, second.Journal.LoadHandles().Count, "expired record removed before admission");
            Check.Equal(0, second.Files.GetRecoveryTokens().Count, "expired retention released");
            Check.That(await second.Files.ResolveIdentityAsync("file") is null, "expired delete-pending object finalized");
            await using var peer = new Peer(); await peer.Login(second.Server.Endpoint, 0x311, client);
            await peer.Exchange(Reconnect(id, create, false), Missing);
        }
    }
    static async Task DeletePendingRestart()
    {
        using var root = new RecoveryPersistenceTests.Root(); var client = Guid.NewGuid(); var create = Guid.NewGuid(); (ulong P, ulong V) id;
        await using (var first = new RestartServer(root))
        {
            await first.Server.StartAsync(); await using var peer = new Peer(); await peer.Login(first.Server.Endpoint, 0x311, client);
            var request = Request(false, create); RawSmb.Put32(request, 88, 0x10003);
            id = Id(await peer.Exchange(request)); await peer.Exchange(RawSmb.Write(id, Payload, 0, 0, 0, 0));
            await peer.Exchange(Set(id, 13, new byte[] { 1 }));
            var session = peer.Session; await peer.DisposeAsync(); await Eventually(() => !first.Server.State.SessionGlobalList.ContainsKey(session), "pending owner detached");
        }
        await using (var second = new RestartServer(root))
        {
            await second.Server.StartAsync(); await using var peer = new Peer(); await peer.Login(second.Server.Endpoint, 0x311, client);
            var restored = Id(await peer.Exchange(Reconnect(id, create, false))); await peer.Exchange(RawSmb.Close(restored, 0, 0, 0));
            Check.That(await second.Files.ResolveIdentityAsync("file") is null, "recovered pending file deletes at explicit close");
            Check.Equal(0, second.Files.GetRecoveryTokens().Count, "pending retention released");
        }
    }
    static async Task BackendMismatch()
    {
        using var original = new RecoveryPersistenceTests.Root(); var client = Guid.NewGuid();
        await using (var first = new RestartServer(original))
        {
            await first.Server.StartAsync(); await using var peer = new Peer(); await peer.Login(first.Server.Endpoint, 0x311, client);
            await peer.Exchange(Request(false, Guid.NewGuid())); var session = peer.Session; await peer.DisposeAsync();
            await Eventually(() => !first.Server.State.SessionGlobalList.ContainsKey(session), "owner detached for mismatch");
        }
        using var changed = new RecoveryPersistenceTests.Root(); File.Copy(original.Journal, changed.Journal);
        await using var replacement = new RestartServer(changed); var rejected = false;
        try { await replacement.Server.StartAsync(); } catch (InvalidDataException) { rejected = true; }
        Check.That(rejected, "different backend rejects startup before listening"); Check.Equal(1, replacement.Journal.LoadHandles().Count, "routing rejection preserves recovery record");
    }

    public static async Task<int> RecoveryChild(string directory)
    {
        await using var host = new RestartServer(directory); await host.Server.StartAsync();
        Console.WriteLine("READY " + host.Server.Endpoint.Port); Console.Out.Flush();
        await Console.In.ReadLineAsync(); return 0;
    }
    sealed class RecoveryProcess : IAsyncDisposable
    {
        internal readonly Process Process;
        internal readonly Task<string> Errors;
        internal IPEndPoint Endpoint = null!;
        internal RecoveryProcess(string directory)
        {
            var executable = Environment.ProcessPath!;
            var info = new ProcessStartInfo(executable) { RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
            if (System.IO.Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase)) info.ArgumentList.Add(Assembly.GetExecutingAssembly().Location);
            info.ArgumentList.Add("--recovery-server"); info.ArgumentList.Add(directory);
            Process = Process.Start(info)!; Errors = Process.StandardError.ReadToEndAsync();
        }
        internal async Task Ready()
        {
            var line = await Process.StandardOutput.ReadLineAsync().WaitAsync(Check.Timeout);
            Check.That(line?.StartsWith("READY ") == true, "child endpoint: " + line);
            Endpoint = new(IPAddress.Loopback, int.Parse(line![6..]));
        }
        internal async Task Kill()
        { Process.Kill(entireProcessTree: true); await Process.WaitForExitAsync().WaitAsync(Check.Timeout); }
        public async ValueTask DisposeAsync()
        {
            if (!Process.HasExited)
            {
                await Process.StandardInput.WriteLineAsync("stop"); await Process.StandardInput.FlushAsync();
                try { await Process.WaitForExitAsync().WaitAsync(Check.Timeout); }
                catch { await Kill(); throw; }
                Check.Equal(0, Process.ExitCode, "child clean shutdown: " + await Errors);
            }
            Process.Dispose();
        }
    }
    static async Task ProcessKill(uint lease)
    {
        using var root = new RecoveryPersistenceTests.Root(); var client = Guid.NewGuid(); var create = Guid.NewGuid(); (ulong P, ulong V) id; ulong oldSession;
        await using (var child = new RecoveryProcess(root.Path))
        {
            await child.Ready(); await using var owner = new Peer(); await owner.Login(child.Endpoint, 0x311, client);
            id = Id(await owner.Exchange(Request(false, create, lease))); oldSession = owner.Session;
            await owner.Exchange(RawSmb.Write(id, Payload, 0, 0, 0, 0));
            await owner.Exchange(Lock(id, 0x10, 0x12));
            await child.Kill(); // ACKs above, no disconnect/snapshot/shutdown callback in the killed process.
        }
        await using (var child = new RecoveryProcess(root.Path))
        {
            await child.Ready(); await using var owner = new Peer(); await owner.Login(child.Endpoint, 0x311, client);
            Check.That(owner.Session != oldSession, "killed session not resurrected");
            var restored = Id(await owner.Exchange(Reconnect(id, create, false, lease)));
            var response = await owner.Exchange(RawSmb.Read(restored, (uint)Payload.Length, 0, 0, 0, 0));
            Check.That(Payload.SequenceEqual(RawSmb.Buffer(response, response[66], RawSmb.U32(response, 68))), "kill/restart bytes");
            await owner.Exchange(Lock(restored, 0x10, 0x12)); await owner.Exchange(Lock(restored, 0x11, 4));
            await owner.Exchange(RawSmb.Close(restored, 0, 0, 0));
        }
        using var journal = new SqliteServerRecoveryStore(root.Journal);
        Check.Equal(0, journal.LoadHandles().Count, "closed record absent after killed-process recovery");
    }

}
