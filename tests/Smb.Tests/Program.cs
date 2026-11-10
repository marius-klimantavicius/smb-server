using Smb.Testing;
using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Server.Notification;

if (args is ["--sqlite-engine-proof"]) { SqliteEngineProof.Print(Console.Out); return 0; }

if (args is ["--recovery-server", var recoveryDirectory]) return await DurableRecoveryTcpTests.RecoveryChild(recoveryDirectory);

if (args is ["--sqlite-child", var sqliteMode, var sqliteDatabase]) return await SqliteProcessTests.Child(sqliteMode, sqliteDatabase);

if (args is ["--p7b-311-probe"]) { await P7bTests.Probe311(); return 0; }

if (args.Length == 3 && args[0] == "--p5-metadata-child") { await P5Tests.MetadataChild(args[1], args[2]); return 0; }

var tests = new (string Name, Func<Task> Run)[]
{
    ("infra.faults-and-barriers", FaultsAsync),
    ("infra.cancellation", CancellationAsync),
    ("infra.recording-transport", TransportAsync),
    ("infra.watcher", WatcherAsync),
    ("infra.clock", ClockAsync),
    ("infra.raw-fixture-layout", RawLayoutAsync),
    ("wire.negotiate-session-tree", async () => { await using var h = new HostFixture(); await h.StartAsync(); await using var c = await h.ConnectAsync(); }),
    ("wire.create-close", async () => {
        await using var h = new HostFixture(); await h.StartAsync(); await using var c = await h.ConnectAsync();
        var id = await c.CreateAsync("new.txt"); Check.Equal(1, h.Store.ActiveHandles, "CREATE acquires handle");
        await c.CloseAsync(id); Check.Equal(0, h.Store.ActiveHandles, "CLOSE disposes handle");
        Check.Equal(1, h.Store.Handles.Single().DisposeCalls, "one disposal"); }),
    ("wire.read-write", async () => {
        await using var h = new HostFixture(); await h.StartAsync(); await using var c = await h.ConnectAsync();
        var id = await c.CreateAsync("io.txt"); var data = "independent expected bytes"u8.ToArray();
        await c.WriteAsync(id, data); Check.That(data.SequenceEqual(h.Store.Contents("io.txt")), "WRITE reaches backend");
        var read = await c.ReadAsync(id, (uint)data.Length); Check.That(data.SequenceEqual(read), "READ payload");
        await c.CloseAsync(id); Check.Equal(1, h.Store.Control.Count("Read"), "read counter"); Check.Equal(1, h.Store.Control.Count("Write"), "write counter"); }),
    ("wire.io-status-fault", async () => {
        await using var h = new HostFixture(); await h.StartAsync(); await using var c = await h.ConnectAsync();
        var id = await c.CreateAsync("fault.txt"); h.Store.Control.Enqueue("Write", new OperationStep(Status: NtStatus.DiskFull));
        await c.ExchangeAsync(RawSmb.Write(id, [1], 0, c.NextMessageId(), c.Session, c.Tree), (uint)NtStatus.DiskFull, 9);
        Check.Equal(0, h.Store.Contents("fault.txt").Length, "failed wire write leaves contents"); await c.CloseAsync(id); }),
    ("wire.async-backend", async () => {
        await using var h = new HostFixture(); h.Store.Seed("park.txt", [42]);
        await h.StartAsync(); await using var c = await h.ConnectAsync(); var id = await c.CreateAsync("park.txt");
        var gate = new AsyncBarrier(); h.Store.Control.Enqueue("Read", new OperationStep(Barrier: gate));
        var read = c.ReadAsync(id, 1); await gate.Entered;
        try { Check.That(!read.IsCompleted, "wire operation waits for controlled backend"); } finally { gate.Release(); }
        Check.Equal((byte)42, (await read.WaitAsync(Check.Timeout))[0], "released I/O result"); await c.CloseAsync(id); }),
    ("wire.enumeration", async () => {
        await using var h = new HostFixture(); h.Store.Seed("alpha.txt", []); h.Store.Seed("beta.txt", []);
        await h.StartAsync(); await using var c = await h.ConnectAsync(); var id = await c.CreateAsync("", true);
        var names = await c.EnumerateAsync(id); Check.That(names.SequenceEqual(new[] { "alpha.txt", "beta.txt" }), "independent enumeration names");
        await c.CloseAsync(id); }),
    ("wire.tree-disconnect", async () => {
        await using var h = new HostFixture(); await h.StartAsync(); await using var c = await h.ConnectAsync();
        await c.DisconnectTreeAsync(); Check.That(h.Server.State.SessionGlobalList.Values.All(s => s.TreeConnects.IsEmpty), "tree removed"); }),
    ("wire.normal", () => HostFixture.NormalAsync(Console.WriteLine)),
    // Genuine baseline assertion, deliberately fails until P2 repairs F08. No expected-failure pass conversion.
    ("baseline.F08-tree-disconnect-closes-opens", async () => {
        await using var h = new HostFixture(); await h.StartAsync(); await using var c = await h.ConnectAsync();
        await c.CreateAsync("still-open.txt"); await c.DisconnectTreeAsync();
        Check.Equal(0, h.Store.ActiveHandles, "MS-SMB2 3.3.5.8 requires closing tree opens before disconnect"); }),
};
tests = tests.Concat(P1Tests.Cases()).Concat(P2Tests.Cases()).Concat(P3Tests.Cases()).Concat(P4Tests.Cases()).Concat(P5Tests.Cases()).Concat(P6Tests.Cases()).Concat(P6AdvancedTests.Cases()).Concat(P6WorkflowTests.Cases()).Concat(P6FinalTests.Cases()).Concat(P6NamespaceTests.Cases()).Concat(P6RaceTests.Cases()).Concat(P7aTests.Cases()).Concat(P7bTests.Cases()).Concat(P7cTests.Cases()).Concat(P8Tests.Cases()).Concat(P8Profiles.Cases()).Concat(PlatformTests.Cases()).ToArray();
tests = tests.Concat(UpstreamCreateTests.Cases()).Concat(UpstreamProtocolTests.Cases()).Concat(UpstreamStateTests.Cases()).ToArray();
tests = tests.Concat(UpstreamMicrosoftTests.Cases()).ToArray();
tests = tests.Concat(UpstreamSambaTests.Cases()).ToArray();
tests = tests.Concat(UpstreamGoTests.Cases()).ToArray();
tests = tests.Concat(UpstreamSambaMoreTests.Cases()).ToArray();
tests = tests.Concat(UpstreamRepairTests.Cases()).ToArray();
tests = tests.Concat(UpstreamDescriptorRepairTests.Cases()).ToArray();
tests = tests.Concat(UpstreamCreateAuthorizationTests.Cases()).ToArray();
tests = tests.Concat(UpstreamGrantRepairTests.Cases()).ToArray();
tests = tests.Concat(UpstreamCacheRepairTests.Cases()).ToArray();
tests = tests.Concat(UpstreamInventoryTests.Cases()).ToArray();
tests = tests.Concat(UpstreamFinalProtocolTests.Cases()).ToArray();
tests = tests.Concat(DurableRecoveryTcpTests.Cases()).ToArray();
tests = tests.Concat(MultichannelWireTests.Cases()).ToArray();
tests = tests.Concat(CacheSequenceRecoveryTests.Cases()).ToArray();
tests = tests.Concat(NotifyBoundaryRepairTests.Cases()).ToArray();
tests = tests.Concat(DurableRecoveryTcpTests.InheritanceNameCases()).ToArray();
tests = tests.Concat(RecoveryPersistenceTests.Cases()).Concat(DurableRecoveryTcpTests.PersistenceCases()).ToArray();
tests = tests.Concat(SqliteProviderTests.Cases()).Concat(SqliteEngineTests.Cases()).ToArray();
tests = tests.Append(("sqlite.host-workflow", () => SqliteWorkload.RunAsync())).ToArray();
tests = tests.Concat(SqliteProcessTests.Cases()).Concat(DurableRecoveryTcpTests.SqliteCases()).ToArray();
if (args is ["--list"]) { foreach (var test in tests) Console.WriteLine(test.Name); return 0; }
var filter = args switch { [] => "", ["--filter", var value] => value, _ => throw new ArgumentException("Usage: [--list | --filter <case-insensitive-substring>]") };
var selected = tests.Where(t => t.Name.Contains(filter, StringComparison.OrdinalIgnoreCase)).ToArray();
if (selected.Length == 0) { Console.Error.WriteLine($"No tests match '{filter}'"); return 2; }
BuildIdentity.Print(Console.Out);
var failed = 0;
foreach (var test in selected)
{
    try { await test.Run().WaitAsync(TimeSpan.FromSeconds(60)); Console.WriteLine($"PASS {test.Name}"); }
    catch (Exception e) { failed++; Console.WriteLine($"FAIL {test.Name}: {e}"); }
}
Console.WriteLine($"RESULT total={selected.Length} passed={selected.Length - failed} failed={failed}");
return failed == 0 ? 0 : 1;

static async Task FaultsAsync()
{
    var store = new FakeFileStore();
    var gate = new AsyncBarrier(); store.Control.Enqueue("Create", new OperationStep(Barrier: gate));
    var pending = store.CreateAsync("a", FileAccessIntent.ReadWrite, CreateDispositionIntent.OpenIf, false, true).AsTask();
    await gate.Entered; Check.That(!pending.IsCompleted, "backend operation parked"); Check.Equal(1, store.Control.Count("Create"), "entered counter");
    gate.Release(); var result = await pending.WaitAsync(Check.Timeout); var handle = result.Value.Handle;
    store.Control.Enqueue("Write", new OperationStep(Status: NtStatus.DiskFull));
    Check.Equal(NtStatus.DiskFull, (await store.WriteAsync(handle, 0, new byte[] { 1 })).Status, "status fault");
    Check.Equal(0, store.Contents("a").Length, "failed write leaves content");
    store.Control.Enqueue("Read", new OperationStep(Error: new IOException("injected read failure")));
    try { await store.ReadAsync(handle, 0, new byte[1]); throw new InvalidOperationException("missing I/O exception"); }
    catch (IOException e) { Check.Equal("injected read failure", e.Message, "exception fault"); }
    await handle.DisposeAsync(); Check.Equal(0, store.ActiveHandles, "disposed fake");
    Check.Equal(1, store.Control.Count("Dispose"), "async disposal count");
}
static async Task CancellationAsync()
{
    var control = new OperationControl(); var barrier = new AsyncBarrier(); control.Enqueue("Read", new OperationStep(Barrier: barrier));
    using var cts = new CancellationTokenSource(); var task = control.BeforeAsync("Read", cts.Token).AsTask();
    await barrier.Entered; await cts.CancelAsync();
    try { await task.WaitAsync(Check.Timeout); throw new InvalidOperationException("missing cancellation"); } catch (OperationCanceledException) { }
    Check.Equal(1, control.Count("Read"), "cancelled invocation counted once");
}
static async Task TransportAsync()
{
    var transport = new RecordingTransport(); var barrier = new AsyncBarrier(); transport.Control.Enqueue("Send", new OperationStep(Barrier: barrier));
    byte[] bytes = [1, 2]; var send = transport.SendAsync(bytes, false); await barrier.Entered;
    Check.Equal(0, transport.Sends.Length, "no send committed while blocked"); barrier.Release(); await send.WaitAsync(Check.Timeout);
    await transport.WaitForSendAsync(); bytes[0] = 3; Check.Equal((byte)1, transport.Sends[0].Message[0], "transport takes snapshot");
    transport.Control.Enqueue("Send", new OperationStep(Error: new IOException("transport lost")));
    try { await transport.SendAsync([], false); throw new InvalidOperationException("missing transport failure"); } catch (IOException) { }
    Check.Equal(1, transport.Sends.Length, "failed send uncommitted");
}
static Task WatcherAsync()
{
    var watcher = new FakeWatcher(); var calls = 0;
    watcher.OnWatch = s => s.Emit(new FileNotifyEvent(FileNotifyAction.Added, "first"));
    using var subscription = watcher.Watch("/fake", false, ChangeNotifyFilter.FileName, _ => calls++);
    Check.Equal(1, calls, "synchronous watch completion"); Check.Equal(1, watcher.ActiveCount, "active watcher");
    subscription.Dispose(); watcher.Subscriptions[0].Emit(new FileNotifyEvent(FileNotifyAction.Added, "late"));
    Check.Equal(1, calls, "no event after dispose"); Check.Equal(0, watcher.ActiveCount, "watcher released"); return Task.CompletedTask;
}
static async Task ClockAsync()
{
    var clock = new ManualClock(); var start = clock.GetUtcNow(); var task = Task.Delay(TimeSpan.FromMinutes(2), clock);
    clock.Advance(TimeSpan.FromMinutes(1)); Check.That(!task.IsCompleted, "virtual delay pending");
    clock.Advance(TimeSpan.FromMinutes(1)); await task.WaitAsync(Check.Timeout);
    Check.Equal(start.AddMinutes(2), clock.GetUtcNow(), "virtual UTC time"); Check.Equal(0, clock.ActiveTimers, "delay timer disposed");
}
static Task RawLayoutAsync()
{
    var negotiate = RawSmb.Negotiate(); Check.Equal(102, negotiate.Length, "36-byte negotiate plus one dialect");
    Check.Equal((ushort)0x202, RawSmb.U16(negotiate, 100), "dialect literal");
    var write = RawSmb.Write((7, 9), [0x41, 0x42], 123, 2, 3, 4);
    Check.Equal((ushort)112, RawSmb.U16(write, 66), "WRITE DataOffset"); Check.Equal(0u, RawSmb.U32(write, 108), "WRITE Flags");
    Check.That(write.AsSpan(112).SequenceEqual(new byte[] { 0x41, 0x42 }), "WRITE data literal");
    return Task.CompletedTask;
}
