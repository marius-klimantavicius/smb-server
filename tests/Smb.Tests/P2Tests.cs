using System.Text;
using System.Collections.Concurrent;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Protocol.Enums;
using Smb.Server;
using Smb.Server.State;
using Smb.Server.Locking;
using Smb.Server.Sharing;
using Smb.Server.Diagnostics;
using Smb.Testing;

static class P2Tests
{
	public static IEnumerable<(string Name, Func<Task> Run)> Cases()
	{
		yield return ("p2.ids.shared-session", SharedSession);
        yield return ("p2.admission.closing-tree-rejects-io",ClosingTreeAdmission);
        yield return ("p2.notify.teardown-status",NotifyCleanupStatus);
		yield return ("p2.stress.bounded-lifecycle", Stress);
		yield return ("p2.close.invalid-tree", CloseInvalidTree);
		yield return ("p2.counts.connection-loss-sessions", ConnectionSessionCount);
		yield return ("p2.cancel.cleanup-callback-fault", PendingCancelFault);
		yield return ("p2.fdio.read-original-object", () => OriginalIo(false));
		yield return ("p2.fdio.write-original-object", () => OriginalIo(true));
		yield return ("p2.fdio.pipe-counts", PipeCounts);
		yield return ("p2.send.concurrent-create-send-failure", ConcurrentSendFailure);

		yield return ("p2.final.wire-shared-pending-metadata", WirePendingMetadata);
		yield return ("p2.final.legacy-delete-declined", LegacyDeleteDeclined);
		yield return ("p2.final.rename-ea-identity", RenameEa);
		yield return ("p2.final.snapshot-object-identity", SnapshotIdentity);
		yield return ("p2.final.close-query-drain", QueryDrain);
		yield return ("p2.coverage.concurrent-id-allocation", ConcurrentIds);
		yield return ("p2.coverage.timeout-cleanup", TimeoutCleanup);
		yield return ("p2.coverage.shutdown-cleanup", ShutdownCleanup);
		yield return ("p2.coverage.cleanup-manager-fault", ManagerFault);
		yield return ("p2.coverage.rename-unlock", RenameUnlock);
		yield return ("p2.coverage.hardlink-share-before-overwrite", AliasShare);
		yield return ("p2.coverage.rename-pending-destination", ReplacePending);
		yield return ("p2.coverage.close-close-race", CloseClose);
		yield return ("p2.coverage.no-global-backend-lock", NoGlobalLock);
		yield return ("p2.coverage.getsecurity-fault", GetSecurityFault);

		foreach (var mode in new[] { "last", "clear", "pending" }) { var m = mode; yield return ($"p2.extra.stream-delete-{m}", () => StreamDelete(m)); }
		yield return ("p2.extra.rename-server-metadata", RenameServerMetadata);
		yield return ("p2.extra.rename-share-conflict", RenameShareConflict);
		yield return ("p2.extra.legacy-destructive-reservation", LegacyReservation);
		yield return ("p2.extra.create-cap-race", CreateCapRace);
		yield return ("p2.extra.connection-id-exhaustion", ConnectionExhaustion);
		yield return ("p2.coverage.session-id-boundaries", SessionBoundaries);
		yield return ("p2.coverage.close-admission", CloseAdmission);
		yield return ("p2.coverage.notify-tree-cleanup", NotifyTree);
		yield return ("p2.coverage.send-failure", SendFailure);
		yield return ("p2.coverage.logoff-drains", LogoffDrain);
		yield return ("p2.coverage.publication-fault", PublicationFault);
		foreach (var stage in new[] { "Create", "GetInfo", "Metrics", "Publish" }) { var s = stage; yield return ($"p2.create.rollback-{s}", () => Rollback(s)); }
		yield return ("p2.create.not-published-during-preparation", Preparation);
		yield return ("p2.tree.invalid", InvalidTree);
		yield return ("p2.tree.cleanup-counters-pending", TreeCleanup);
		yield return ("p2.cleanup.continues-after-dispose-fault", CleanupFault);
		foreach (var op in new[] { "Read", "Write", "Rename" }) { var o = op; yield return ($"p2.close.drains-{o}", () => Drain(o, false)); }
		yield return ("p2.tree.drains-read", () => Drain("Read", true));
		yield return ("p2.create.tree-race", CreateTreeRace);
		yield return ("p2.delete.last-open", () => Deletion("last"));
		yield return ("p2.delete.blocks-new-open", () => Deletion("pending"));
		yield return ("p2.delete.clear-from-other-open", () => Deletion("clear"));
		yield return ("p2.rename.all-handles", RenameHandles);
		yield return ("p2.rename.lock-survives", RenameLocks);
		yield return ("p2.rename.destination-open", ReplaceOpen);
		yield return ("p2.alias.hardlink-lock", HardlinkLock);
		yield return ("p2.alias.hardlink-delete-pending", HardlinkDelete);
		yield return ("p2.stream.independent-locks", StreamLocks);
		yield return ("p2.stream.rename-preserves-content", StreamRename);
		yield return ("p2.wire.delete-pending", WireDelete);
	}

	static async Task StreamDelete(string mode)
	{
		using var r = new Root(); var s = new LocalFileStore(r.Path, false); using var file = await Open(s, "a");
		var a = (await s.OpenNamedStreamAsync("a", "s", FileAccessIntent.ReadWrite, CreateDispositionIntent.OpenIf)).Value.Handle;
		var b = (await s.OpenNamedStreamAsync("a", "s", FileAccessIntent.ReadWrite, CreateDispositionIntent.Open)).Value.Handle;
		try
		{
			await s.SetDeleteOnCloseAsync(a, true);
			if (mode == "pending") { var x = await s.OpenNamedStreamAsync("a", "s", FileAccessIntent.Read, CreateDispositionIntent.Open); if (x.IsSuccess) x.Value.Handle.Dispose(); Check.Equal((NtStatus)0xc0000056, x.Status, "named stream new open blocked by pending"); }
			if (mode == "clear") await s.SetDeleteOnCloseAsync(b, false);
			await a.CloseAsync(); await a.DisposeAsync(); var bytes = new byte[1];
			Check.Equal(NtStatus.Success, (await s.ReadAsync(b, 0, bytes)).Status, "first stream close retains stream for other open");
			await b.CloseAsync(); await b.DisposeAsync();
			var c = await s.OpenNamedStreamAsync("a", "s", FileAccessIntent.Read, CreateDispositionIntent.Open); if (c.IsSuccess) c.Value.Handle.Dispose();
			Check.Equal(mode == "clear" ? NtStatus.Success : NtStatus.ObjectNameNotFound, c.Status, "stream final close honors shared disposition");
			Check.That(File.Exists(r.Path + "/a"), "stream deletion preserves base");
		}
		finally { a.Dispose(); b.Dispose(); }
	}
	static async Task RenameServerMetadata() { await using var d = new Direct(); var a = await d.Open(); var b = await d.Open(); var response = await d.Send(RenamePacket(a, "b")); Check.Equal(0u, RawSmb.U32(response, 8), "server rename success"); Check.Equal("b", d.Session.Opens[b].PathName, "all server opens project current backend name"); }
	static async Task RenameShareConflict() { await using var d = new Direct(); var req = d.Create(); RawSmb.Put32(req, 88, 3); RawSmb.Put32(req, 96, 3); Check.Equal(0u, RawSmb.U32(await d.Send(req), 8), "open denies delete sharing"); var response = await d.Send(d.Create()); Check.Equal(0xc0000043u, RawSmb.U32(response, 8), "delete-capable rename handle cannot bypass existing share reservation"); }

	sealed class Legacy(IFileStore inner) : IFileStore
	{
		public ValueTask<FileStoreResult<FileCreateResult>> CreateAsync(string p, FileAccessIntent a, CreateDispositionIntent d, bool dir, bool non, CancellationToken ct = default) => inner.CreateAsync(p, a, d, dir, non, ct);
		public ValueTask<FileStoreResult<int>> ReadAsync(IFileHandle h, long o, Memory<byte> b, CancellationToken ct = default) => inner.ReadAsync(h, o, b, ct);
		public ValueTask<FileStoreResult<int>> WriteAsync(IFileHandle h, long o, ReadOnlyMemory<byte> b, CancellationToken ct = default) => inner.WriteAsync(h, o, b, ct);
		public ValueTask<FileStoreResult<IReadOnlyList<FileEntryInfo>>> QueryDirectoryAsync(IFileHandle h, string p, CancellationToken ct = default) => inner.QueryDirectoryAsync(h, p, ct);
		public ValueTask<NtStatus> SetEndOfFileAsync(IFileHandle h, long n, CancellationToken ct = default) => inner.SetEndOfFileAsync(h, n, ct);
		public ValueTask<NtStatus> RenameAsync(IFileHandle h, string p, bool r, CancellationToken ct = default) => inner.RenameAsync(h, p, r, ct);
		public ValueTask<NtStatus> SetDeleteOnCloseAsync(IFileHandle h, bool b, CancellationToken ct = default) => inner.SetDeleteOnCloseAsync(h, b, ct);
		public ValueTask<NtStatus> FlushAsync(IFileHandle h, CancellationToken ct = default) => inner.FlushAsync(h, ct);
	}
	static async Task LegacyReservation() { using var r = new Root(); File.WriteAllText(r.Path + "/a", "keep"); await using var d = new Direct(new Legacy(new LocalFileStore(r.Path, false))); var req = d.Create(); RawSmb.Put32(req, 96, 0); Check.Equal(0u, RawSmb.U32(await d.Send(req), 8), "legacy exclusive open"); req = d.Create(); RawSmb.Put32(req, 100, 4); Check.Equal(0xc0000043u, RawSmb.U32(await d.Send(req), 8), "legacy conflicting overwrite refused"); Check.Equal("keep", NativeHost.ReadAllText(r.Path + "/a"), "legacy reservation prevents backend truncation"); }
	static async Task CreateCapRace() { await using var d = new Direct(); d.Options.MaxOpenHandlesPerSession = 1; var gate = new AsyncBarrier(); d.Store.Control.Enqueue("Create", new OperationStep(Barrier: gate)); var first = d.Send(d.Create()); await gate.Entered; var second = d.Send(d.Create("b")); gate.Release(); var result = await Task.WhenAll(first, second); Check.Equal(1, d.Store.ActiveHandles, "session open limit includes provisional creates"); Check.That(result.Any(x => RawSmb.U32(x, 8) == 0xc000009a), "second provisional CREATE rejected with INSUFFICIENT_RESOURCES"); }
	static Task ConnectionExhaustion() { var c = new SmbConnection(); typeof(SmbConnection).GetField("_treeIdCounter", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!.SetValue(c, (long)uint.MaxValue - 1); var exhausted = false; try { c.AllocateTreeId(); } catch (InvalidOperationException) { exhausted = true; } Check.That(exhausted, "legacy allocator cannot emit reserved/wide TreeId"); return Task.CompletedTask; }
	static Task SessionBoundaries()
	{
		using var ignore = new CancellationTokenSource(); var c = new SmbConnection(); var s = new SmbSession { SessionId = 1, SessionGlobalId = 1, Connection = c };
		var tree = typeof(SmbSession).GetField("_treeIdCounter", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!; tree.SetValue(s, (ulong)uint.MaxValue - 2); Check.Equal((ulong)uint.MaxValue - 1, s.AllocateTreeId(), "last valid tree ID"); var exhausted = false; try { s.AllocateTreeId(); } catch (InvalidOperationException) { exhausted = true; }
		Check.That(exhausted, "tree namespace exhaustion");
		var file = typeof(SmbSession).GetField("_fileIdCounter", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!; file.SetValue(s, ulong.MaxValue - 2); Check.Equal(ulong.MaxValue - 1, s.AllocateFileId(), "last valid volatile ID"); exhausted = false; try { s.AllocateFileId(); } catch (InvalidOperationException) { exhausted = true; }
		Check.That(exhausted, "volatile namespace exhaustion"); return Task.CompletedTask;
	}
	static async Task CloseAdmission() { await using var d = new Direct(); var id = await d.Open(); var gate = new AsyncBarrier(); d.Store.Control.Enqueue("Read", new OperationStep(Barrier: gate)); var read = d.Send(RawSmb.Read(id, 1, 0, 0, 1, 42)); await gate.Entered; var close = d.Send(RawSmb.Close(id, 0, 1, 42)); try { var late = await d.Send(RawSmb.Write(id, [1], 0, 0, 1, 42)); Check.Equal(0xc0000128u, RawSmb.U32(late, 8), "closing open rejects new operations"); } finally { gate.Release(); await Task.WhenAll(read, close); } }
	static async Task NotifyTree() { await using var d = new Direct(); var watcher = new Smb.Testing.FakeWatcher(); d.Options.DirectoryWatcher = watcher; var req = RawSmb.Create("", true, 0, 1, 42); var response = await d.Send(req); var id = (RawSmb.U64(response, 128), RawSmb.U64(response, 136)); var n = RawSmb.Header(15, 32, 0, 1, 42); RawSmb.Put16(n, 64, 32); RawSmb.Put32(n, 68, 100); RawSmb.Put64(n, 72, id.Item1); RawSmb.Put64(n, 80, id.Item2); RawSmb.Put32(n, 88, 1); await d.Send(n); Check.Equal(1, watcher.ActiveCount, "watcher acquired"); await d.Send(RawSmb.TreeDisconnect(0, 1, 42)); Check.Equal(0, watcher.ActiveCount, "tree releases watcher"); Check.That(d.Connection.PendingRequests.IsEmpty, "tree releases notify pending slot"); }
	static async Task SendFailure() { await using var d = new Direct(); var transport = new RecordingTransport(); transport.Control.Enqueue("Send", new OperationStep(Error: new IOException("lost response"))); var response = await d.Send(d.Create()); try { await transport.SendAsync(response, false); } catch (IOException) { await d.Dispatcher.OnConnectionClosedAsync(d.Connection); } Check.Equal(0, d.Store.ActiveHandles, "lost CREATE response connection teardown closes ordinary open"); Check.Equal(0L, d.Options.Metrics.OpenHandles, "send failure balances counters"); }
	static async Task LogoffDrain() { await using var d = new Direct(); var id = await d.Open(); var gate = new AsyncBarrier(); d.Store.Control.Enqueue("Write", new OperationStep(Barrier: gate, IgnoreCancellation: true)); var write = d.Send(RawSmb.Write(id, [1], 0, 0, 1, 42)); await gate.Entered; var b = RawSmb.Header(2, 4, 0, 1); RawSmb.Put16(b, 64, 4); var logoff = d.Send(b); try { Check.That(!logoff.IsCompleted, "logoff drains active backend operation"); } finally { gate.Release(); await Task.WhenAll(logoff, write); } Check.Equal(0, d.Store.ActiveHandles, "logoff closes handles"); }
	sealed class PublishMetrics(Action collision) : SmbServerMetrics { public override void OnHandleOpened() { base.OnHandleOpened(); collision(); } }
	static async Task PublicationFault() { await using var d = new Direct(); var foreign = new SmbOpen { VolatileFileId = 1 }; d.Options.Metrics = new PublishMetrics(() => d.Session.Opens.TryAdd((0, 1), foreign)); var b = await d.Send(d.Create()); Check.Equal(0xc000009au, RawSmb.U32(b, 8), "publication collision fails CREATE"); Check.That(ReferenceEquals(foreign, d.Session.Opens[(0, 1)]), "rollback preserves foreign entry"); Check.Equal(0, d.Store.ActiveHandles, "publication failure releases backend"); Check.Equal(0L, d.Options.Metrics.OpenHandles, "publication failure balances metrics"); }

	static async Task QueryDrain() { await using var d = new Direct(); var id = await d.Open(); var gate = new AsyncBarrier(); d.Store.Control.Enqueue("GetInfo", new OperationStep(Barrier: gate)); var q = RawSmb.Header(16, 40, 0, 1, 42); RawSmb.Put16(q, 64, 41); q[66] = 1; q[67] = 5; RawSmb.Put32(q, 68, 100); RawSmb.Put64(q, 88, id.P); RawSmb.Put64(q, 96, id.V); var query = d.Send(q); await gate.Entered; var close = d.Send(RawSmb.Close(id, 0, 1, 42)); try { Check.That(!close.IsCompleted, "close drains QUERY_INFO metadata operation"); } finally { gate.Release(); await Task.WhenAll(query, close); } }
	static async Task WirePendingMetadata()
	{
		using var r = new Root(); await using var d = new Direct(new LocalFileStore(r.Path, false)); var a = await d.Open(); var b = await d.Open();
		var set = RawSmb.Header(17, 33, 0, 1, 42); RawSmb.Put16(set, 64, 33); set[66] = 1; set[67] = 13; RawSmb.Put32(set, 68, 1); RawSmb.Put16(set, 72, 96); RawSmb.Put64(set, 80, a.P); RawSmb.Put64(set, 88, a.V); set[96] = 1; Check.Equal(0u, RawSmb.U32(await d.Send(set), 8), "mark disposition");
		var q = RawSmb.Header(16, 40, 0, 1, 42); RawSmb.Put16(q, 64, 41); q[66] = 1; q[67] = 5; RawSmb.Put32(q, 68, 100); RawSmb.Put64(q, 88, b.P); RawSmb.Put64(q, 96, b.V);
		var response = await d.Send(q); Check.Equal(0u, RawSmb.U32(response, 8), "standard info status"); var data = RawSmb.Buffer(response, RawSmb.U16(response, 66), RawSmb.U32(response, 68)); Check.Equal((byte)1, data[20], "other handle queries shared DeletePending");
	}
	static async Task LegacyDeleteDeclined() { await using var d = new Direct(); var b = d.Create(); RawSmb.Put32(b, 104, 0x1040); var r = await d.Send(b); Check.Equal(0xc00000bbu, RawSmb.U32(r, 8), "legacy store without shared-delete contract declines delete-on-close"); Check.Equal(0, d.Store.ActiveHandles, "declined delete releases provisional handle"); }
	static async Task RenameEa() { using var r = new Root(); var s = new LocalFileStore(r.Path, false); using var a = await Open(s, "a"); await s.SetExtendedAttributesAsync(a, [new ExtendedAttribute("p2", new byte[] { 42 }, 0)]); await s.RenameAsync(a, "b", false); using var b = await Open(s, "b"); Check.Equal(1, (await s.GetExtendedAttributesAsync(b)).Value!.Count, "EA follows backend object across rename"); }
	static async Task SnapshotIdentity()
	{
		using var r = new Root(); var local = new LocalFileStore(r.Path, false); using var a = await Open(local, "a"); var store = new Smb.FileSystem.Versioning.VersioningFileStore(local); var create = await store.CreateAsync("a", FileAccessIntent.Read, CreateDispositionIntent.Open, false, false); using var h = create.Value.Handle; // Live wrappers must expose a stable identity through the handle.
		Check.That(h.Identity != null, "versioning live handle retains object identity");
		using var overwritten = (await store.CreateAsync("a", FileAccessIntent.ReadWrite, CreateDispositionIntent.Overwrite, false, false)).Value.Handle;
		var path = Smb.FileSystem.Versioning.GmtToken.Format(store.GetSnapshots("a").Single()) + "/a";
		using var snapshot = (await store.CreateAsync(path, FileAccessIntent.Read, CreateDispositionIntent.Open, false, false)).Value.Handle;
		Check.That(snapshot.Identity != null, "snapshot has backend object identity independent of path");
		using var same = (await store.CreateAsync(path, FileAccessIntent.Read, CreateDispositionIntent.Open, false, false)).Value.Handle;
		Check.Equal(snapshot.Identity!.Value, same.Identity!.Value, "same version shares snapshot identity");

	}
	static Task ConcurrentIds() { var c = new SmbConnection(); var s = new SmbSession { SessionId = 1, SessionGlobalId = 1, Connection = c }; var files = new ConcurrentBag<ulong>(); var trees = new ConcurrentBag<ulong>(); Parallel.For(0, 512, _ => { files.Add(s.AllocateFileId()); trees.Add(s.AllocateTreeId()); }); Check.Equal(512, files.Distinct().Count(), "concurrent volatile IDs"); Check.Equal(512, trees.Distinct().Count(), "concurrent tree IDs"); Check.That(files.All(x => x != 0 && x != ulong.MaxValue) && trees.All(x => x != 0 && x < uint.MaxValue), "reserved IDs excluded"); return Task.CompletedTask; }
	static async Task TimeoutCleanup() { await using var d = new Direct(); await d.Open(); var clock = new ManualClock(); d.Options.TimeProvider = clock; d.Options.SessionIdleTimeout = TimeSpan.FromSeconds(1); d.Session.LastActivityTicks = clock.GetUtcNow().AddSeconds(-2).Ticks; d.Dispatcher.SweepIdleTimeouts(); Check.Equal(0, d.Store.ActiveHandles, "timeout centralized cleanup"); Check.Equal(0, d.Tree.OpenCount, "timeout tree count"); Check.Equal(0L, d.Options.Metrics.OpenHandles, "timeout metrics"); }
	static async Task ShutdownCleanup() { await using var h = new HostFixture(); await h.StartAsync(); await using var c = await h.ConnectAsync(); await c.CreateAsync("shutdown"); await h.Server.StopAsync(TimeSpan.FromSeconds(1)); Check.Equal(0, h.Store.ActiveHandles, "shutdown cleans ordinary open"); Check.Equal(0L, h.Server.State.Options.Metrics.OpenHandles, "shutdown counters"); }
	sealed class FaultSharing : IShareModeManager { readonly InMemoryShareModeManager inner = new InMemoryShareModeManager(); public bool TryOpen(string k, object o, FileAccessIntent a, FileShareMode s) => inner.TryOpen(k, o, a, s); public void Close(string k, object o) { inner.Close(k, o); throw new IOException("share cleanup fault"); } }
	static async Task ManagerFault() { await using var d = new Direct(); d.Options.ShareModeManager = new FaultSharing(); await d.Open("a"); await d.Open("b"); await d.Send(RawSmb.TreeDisconnect(0, 1, 42)); Check.Equal(0, d.Store.ActiveHandles, "cleanup continues after manager exception"); Check.Equal(0, d.Tree.OpenCount, "manager error balances counters"); }
	static async Task RenameUnlock() { using var r = new Root(); var s = new LocalFileStore(r.Path, false); using var a = await Open(s, "a"); var o = Owner(a, 1); var l = new InMemoryLockManager(); await l.ApplyAsync(o, [new LockElement(0, 10, true, false)], true, default); await s.RenameAsync(a, "b", false); Check.Equal(LockOutcome.Granted, await l.ApplyAsync(o, [new LockElement(0, 10, false, true)], true, default), "unlock uses stable identity after rename"); }
	static async Task AliasShare() { using var r = new Root(); File.WriteAllText(r.Path + "/a", "keep"); Link(r.Path + "/a", r.Path + "/alias"); await using var d = new Direct(new LocalFileStore(r.Path, false)); var b = d.Create(); RawSmb.Put32(b, 96, 0); await d.Send(b); b = d.Create("alias"); RawSmb.Put32(b, 100, 4); Check.Equal(0xc0000043u, RawSmb.U32(await d.Send(b), 8), "alias sharing conflict precedes destructive acquisition"); Check.Equal("keep", NativeHost.ReadAllText(r.Path + "/a"), "alias overwrite did not truncate"); }
	static async Task ReplacePending() { using var r = new Root(); var s = new LocalFileStore(r.Path, false); using var a = await Open(s, "a"); using var b = await Open(s, "b"); await s.SetDeleteOnCloseAsync(b, true); Check.Equal((NtStatus)0xc0000056, await s.RenameAsync(a, "b", true), "rename cannot replace delete-pending target"); }
	static async Task CloseClose() { await using var d = new Direct(); var id = await d.Open(); var gate = new AsyncBarrier(); d.Store.Control.Enqueue("Dispose", new OperationStep(Barrier: gate)); var first = d.Send(RawSmb.Close(id, 0, 1, 42)); await gate.Entered; var second = d.Send(RawSmb.Close(id, 0, 1, 42)); gate.Release(); await Task.WhenAll(first, second); Check.Equal(1, d.Store.Control.Count("Dispose"), "simultaneous close has one disposer"); Check.Equal(0, d.Tree.OpenCount, "simultaneous close balances counters"); }
	static async Task NoGlobalLock() { using var r = new Root(); var fake = new FakeFileStore(); await using var d = new Direct(); var other = new SmbTreeConnect { TreeId = 43, Session = d.Session, Share = new Share { Name = "other", FileStore = fake }, MaximalAccess = 0x1f01ff }; d.Session.TreeConnects.TryAdd(43, other); d.Options.Metrics.OnTreeConnected(); var gate = new AsyncBarrier(); d.Store.Control.Enqueue("Create", new OperationStep(Barrier: gate)); var first = d.Send(d.Create()); await gate.Entered; try { var req = d.Create(); RawSmb.Put32(req, 36, 43); Check.Equal(0u, RawSmb.U32(await d.Send(req).WaitAsync(Check.Timeout), 8), "unrelated backend progresses while first CREATE blocked"); } finally { gate.Release(); await first; } }
	static async Task GetSecurityFault() { await using var d = new Direct(); d.Store.Control.Enqueue("GetSecurity", new OperationStep(Error: new IOException("metadata acquisition fault"))); var b = await d.Send(d.Create()); Check.That(RawSmb.U32(b, 8) != 0, "GetSecurity fault returns error"); Check.Equal(0, d.Store.ActiveHandles, "post-acquisition metadata fault disposes handle"); Check.That(d.Session.Opens.IsEmpty, "post-acquisition metadata fault leaves no open"); }

	static async Task OriginalIo(bool write) { using var r = new Root(); File.WriteAllBytes(r.Path + "/a", [1]); var s = new LocalFileStore(r.Path, false); using var h = await Open(s, "a"); File.Move(r.Path + "/a", r.Path + "/moved"); File.WriteAllBytes(r.Path + "/a", [2]); if (write) { await s.WriteAsync(h, 0, new byte[] { 3 }); Check.Equal((byte)2, NativeHost.ReadAllBytes(r.Path + "/a")[0], "write stays on acquired object after pathname replacement"); Check.Equal((byte)3, NativeHost.ReadAllBytes(r.Path + "/moved")[0], "write reached original object"); } else { var b = new byte[1]; await s.ReadAsync(h, 0, b); Check.Equal((byte)1, b[0], "read stays on acquired object after pathname replacement"); } }
	static async Task PipeCounts() { await using var d = new Direct(); var tree = new SmbTreeConnect { TreeId = 43, Session = d.Session, Share = new Share { Name = "IPC$", Type = ShareType.Pipe }, MaximalAccess = 0x1f01ff }; d.Session.TreeConnects.TryAdd(43, tree); d.Options.Metrics.OnTreeConnected(); var req = d.Create("srvsvc"); RawSmb.Put32(req, 36, 43); var response = await d.Send(req); Check.Equal(0u, RawSmb.U32(response, 8), "pipe create status"); Check.Equal(1L, d.Options.Metrics.OpenHandles, "pipe open included in metrics"); await d.Send(RawSmb.TreeDisconnect(0, 1, 43)); Check.Equal(0L, d.Options.Metrics.OpenHandles, "pipe cleanup balances metrics"); Check.Equal(0, tree.OpenCount, "pipe tree count quiescent"); }

	sealed class FailedStream : MemoryStream { public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) => ValueTask.FromException(new IOException("injected response write failure")); }
	static async Task ConcurrentSendFailure() { await using var d = new Direct(); d.Options.ConcurrentMetadataOps = true; var closed = false; d.Connection.RequestClose = () => closed = true; var handler = new Smb.Host.SmbConnectionHandler(d.State, null); var req = d.Create(); RawSmb.Put64(req, 24, 1); RawSmb.Sign(req, d.Session.SigningKey); Check.That(d.Dispatcher.TryBeginConcurrentFrame(d.Connection, req, false, out var frame), "CREATE concurrent scheduling enabled in fixture"); await handler.ConcurrentOperations!.WaitAsync(); await handler.RunConcurrentFrameAsync(new FailedStream(), d.Connection, frame, default); Check.That(closed, "failed concurrent CREATE response requests transport teardown"); await d.Dispatcher.OnConnectionClosedAsync(d.Connection); Check.Equal(0, d.Store.ActiveHandles, "failed concurrent CREATE response leaves no ordinary open"); }
	static async Task PendingCancelFault() { await using var d = new Direct(); var a = new PendingAsyncRequest { MessageId = 1, AsyncId = 1 }; var b = new PendingAsyncRequest { MessageId = 2, AsyncId = 2 }; a.Token.Register(() => throw new IOException("cancel callback fault")); d.Connection.PendingRequests.TryAdd(1, a); d.Connection.PendingRequests.TryAdd(2, b); Exception? failure = null; try { await d.Dispatcher.OnConnectionClosedAsync(d.Connection); } catch (Exception ex) { failure = ex; } Check.That(failure == null, "connection cleanup tolerates fallible pending callback"); Check.That(b.Token.IsCancellationRequested && d.Connection.PendingRequests.IsEmpty, "connection cleanup cancels/releases every orphan pending request"); }
	static async Task ConnectionSessionCount() { await using var h = new HostFixture(); await h.StartAsync(); await using var c = await h.ConnectAsync(); await c.CreateAsync("session-count"); await h.Server.StopAsync(TimeSpan.FromSeconds(1)); Check.Equal(0L, h.Server.State.Options.Metrics.ActiveSessions, "connection teardown balances active session metrics"); Check.Equal(0L, h.Server.State.Options.Metrics.ActiveTreeConnects, "connection teardown balances tree metrics"); }
	static async Task CloseInvalidTree() { await using var d = new Direct(); var id = await d.Open(); var response = await d.Send(RawSmb.Close(id, 0, 1, 999)); Check.Equal(0xc00000c9u, RawSmb.U32(response, 8), "CLOSE verifies tree before resolving open"); Check.Equal(1, d.Store.ActiveHandles, "invalid tree does not consume valid open"); }
	static async Task Stress()
	{
		for (var iteration = 0; iteration < 32; iteration++)
		{
			await using var d = new Direct(); var locks = (InMemoryLockManager)d.Options.LockManager; var sharing = (InMemoryShareModeManager)d.Options.ShareModeManager;
			var ids = new List<(ulong P, ulong V)>(); for (var i = 0; i < 4; i++) ids.Add(await d.Open("f" + i));
			foreach (var id in ids) { await d.Send(RawSmb.Write(id, new byte[] { 42 }, 0, 0, 1, 42)); await locks.ApplyAsync(d.Session.Opens[id], [new LockElement(0, 1, true, false)], true, default); }
			await d.Send(RawSmb.TreeDisconnect(0, 1, 42));
			Check.Equal(0, d.Store.ActiveHandles, "stress backend handles"); Check.That(d.Store.Handles.All(h => h.DisposeCalls == 1), "stress exactly-once disposal");
			Check.Equal(0, locks.ActiveLockCount, "stress locks"); Check.Equal(0, locks.PendingLockCount, "stress lock waiters"); Check.Equal(0, sharing.ReservationCount, "stress share reservations");
			Check.Equal(0, d.Session.ProvisionalOpenCount, "stress provisional admissions"); Check.Equal(0, Smb2Dispatcher.ActiveNamespaceCount, "stress namespace keys");
			Check.Equal(0L, d.Options.Metrics.OpenHandles, "stress metrics"); Check.That(d.Session.Opens.IsEmpty && d.Session.TreeConnects.IsEmpty && d.Connection.PendingRequests.IsEmpty, "stress tables quiescent");
		}
		using var root = new Root(); var local = new LocalFileStore(root.Path, false);
		for (var i = 0; i < 32; i++) { var a = await Open(local, "a"); var b = await Open(local, "a"); await local.RenameAsync(a, "b", false); await local.SetDeleteOnCloseAsync(a, true); a.Dispose(); Check.That(File.Exists(root.Path + "/b"), "stress last-open preservation"); b.Dispose(); Check.That(!File.Exists(root.Path + "/b"), "stress final deletion"); }
	}
    static async Task NotifyCleanupStatus() {
        await using var d=new Direct();var watcher=new FakeWatcher();d.Options.DirectoryWatcher=watcher;
        var transport=new RecordingTransport();d.Connection.SendRawAsync=transport.SendAsync;
        var response=await d.Send(RawSmb.Create("",true,0,1,42));var id=(RawSmb.U64(response,128),RawSmb.U64(response,136));
        var req=RawSmb.Header(15,32,0,1,42);RawSmb.Put16(req,64,32);RawSmb.Put32(req,68,100);RawSmb.Put64(req,72,id.Item1);RawSmb.Put64(req,80,id.Item2);RawSmb.Put32(req,88,1);
        await d.Send(req);await d.Send(RawSmb.TreeDisconnect(0,1,42));await transport.WaitForSendAsync();
        Check.Equal(0x10bu,RawSmb.U32(transport.Sends.Single().Message,8),"close completes existing notification with STATUS_NOTIFY_CLEANUP");Check.Equal(0,watcher.ActiveCount,"notification cleanup releases watcher");
    }

    static async Task ClosingTreeAdmission() {
        await using var d=new Direct();var id=await d.Open();var gate=new AsyncBarrier();d.Store.Control.Enqueue("GetInfo",new OperationStep(Barrier:gate));var create=d.Send(d.Create("b"));await gate.Entered;
        var disconnect=d.Send(RawSmb.TreeDisconnect(0,1,42));
        try {var response=await d.Send(RawSmb.Write(id,new byte[]{1},0,0,1,42));Check.Equal(0xc00000c9u,RawSmb.U32(response,8),"tree closing rejects new I/O while draining provisional CREATE");Check.Equal(0,d.Store.Control.Count("Write"),"no late backend write admitted");}
        finally {gate.Release();await Task.WhenAll(create,disconnect);}
    }

	internal sealed class Direct : IAsyncDisposable
	{
		public FakeFileStore Store = new FakeFileStore();
		public SmbServerOptions Options = new SmbServerOptions();
		public SmbServerState State;
		public Smb2Dispatcher Dispatcher;
		public SmbConnection Connection;
		public SmbSession Session;
		public SmbTreeConnect Tree;
		public bool CommitResponses = true;
        readonly ConcurrentDictionary<SmbConnection, ulong> mids = new ConcurrentDictionary<SmbConnection, ulong>();
		public Direct(IFileStore? store = null)
		{
			State = new SmbServerState(Options); Dispatcher = new Smb2Dispatcher(State); Connection = Channel();
			Session = new SmbSession { SessionId = 1, SessionGlobalId = 1, Connection = Connection, State = SessionState.Valid, SigningRequired = true, SigningKey = new byte[16], SessionKey = new byte[16] };
			Options.Metrics.OnAuthenticationSucceeded(); Connection.Sessions.TryAdd(1, Session); State.Connections.TryAdd(Connection.ConnectionId, Connection); State.SessionGlobalList.TryAdd(1, Session);
			Tree = new SmbTreeConnect { TreeId = 42, Session = Session, Share = new Share { Name = "P0", FileStore = store ?? Store }, MaximalAccess = 0x1f01ff };
			Options.Shares.Add(Tree.Share); Session.TreeConnects.TryAdd(42, Tree); Options.Metrics.OnTreeConnected();
		}
		public SmbConnection Channel()
        {
            var c = new SmbConnection();
            Options.SpnegoNegotiator ??= new Smb.Auth.Ntlm.NtlmSpnegoNegotiator(new Smb.Auth.InMemoryIdentityBackend().AddUser("P0", "user", "password"));
            var response = Dispatcher.ProcessMessage(c, RawSmb.Negotiate());
            Check.Equal(0u, RawSmb.U32(response, 8), "direct channel negotiation");
            return c;
        }
		public async Task<byte[]> Send(byte[] b, SmbConnection? c = null) { RawSmb.Put64(b, 24, mids.AddOrUpdate(c ?? Connection, 1, (_, old) => old + 1)); RawSmb.Sign(b, Session.SigningKey); Smb.Crypto.Smb2Signer.SignInPlace(Smb.Crypto.Smb2Signer.ResolveAlgorithm((c ?? Connection).Dialect, (c ?? Connection).SigningAlgorithmId), Session.SigningKey, b, 0, false, false); var response = await Dispatcher.ProcessMessageAsync(c ?? Connection, b); if (CommitResponses) (c ?? Connection).ResponseSent(response); return response; }
		public byte[] Create(string path = "a") { var b = RawSmb.Create(path, false, 0, 1, 42); RawSmb.Put32(b, 88, 0x10003); return b; }
		public async Task<(ulong P, ulong V)> Open(string path = "a") { var b = await Send(Create(path)); Check.Equal(0u, RawSmb.U32(b, 8), "CREATE status"); return (RawSmb.U64(b, 128), RawSmb.U64(b, 136)); }
		public async ValueTask DisposeAsync() => await Dispatcher.OnConnectionClosedAsync(Connection);
	}
	static async Task SharedSession()
	{
		await using var d = new Direct(); var c = d.Channel(); c.Sessions.TryAdd(1, d.Session);
		var a = await d.Open("a"); var b = await d.Send(d.Create("b"), c);
		var v = RawSmb.U64(b, 136); Check.That(a.V != v, "shared-session volatile IDs unique across connections");
		var connects = await Task.WhenAll(Enumerable.Range(0, 32).Select(i => d.Send(RawSmb.TreeConnect("\\\\host\\P0", 0, 1), i % 2 == 0 ? c : d.Connection)));
		Check.Equal(32, connects.Select(x => RawSmb.U32(x, 36)).Distinct().Count(), "shared-session TreeIds unique");
		Check.Equal(2, d.Session.Opens.Count, "no live open overwritten");
	}
	sealed class FaultMetrics : SmbServerMetrics { public override void OnHandleOpened() => throw new IOException("response preparation fault"); }
	static async Task Rollback(string stage)
	{
		await using var d = new Direct();
		if (stage == "Metrics") d.Options.Metrics = new FaultMetrics();
		else if (stage == "Publish")
		{
			// Deliberately occupy next ID: publication must not overwrite the live owner.
			d.Session.Opens.TryAdd((0, 1), new SmbOpen { VolatileFileId = 1, Session = d.Session, TreeConnect = d.Tree });
		}
		else d.Store.Control.Enqueue(stage, new OperationStep(Error: new IOException("injected " + stage)));
		var b = await d.Send(d.Create());
		if (stage == "Publish") Check.That(d.Session.Opens.Values.Any(x => x.LocalOpen == null), "publication never replaces live dictionary entry");
		else
		{
			Check.That(RawSmb.U32(b, 8) != 0, "injected CREATE failure returned");
			Check.Equal(0, d.Store.ActiveHandles, "failed CREATE releases backend handle");
			Check.Equal(0, d.Session.Opens.Count, "failed CREATE removes published/provisional entry");
			Check.Equal(0, d.Tree.OpenCount, "failed CREATE balances tree count");
			d.Options.Metrics = new SmbServerMetrics(); var retry = d.Create(); RawSmb.Put32(retry, 96, 0);
			var r = await d.Send(retry); Check.Equal(0u, RawSmb.U32(r, 8), "failed CREATE releases reservation for incompatible retry");
		}
	}
	static async Task Preparation()
	{
		await using var d = new Direct(); var gate = new AsyncBarrier(); d.Store.Control.Enqueue("GetInfo", new OperationStep(Barrier: gate));
		var create = d.Send(d.Create()); await gate.Entered;
		try { Check.Equal(0, d.Session.Opens.Count, "CREATE stays provisional until response metadata prepared"); } finally { gate.Release(); await create; }
	}
	static async Task InvalidTree() { await using var d = new Direct(); var b = await d.Send(RawSmb.TreeDisconnect(0, 1, 999)); Check.Equal(0xc00000c9u, RawSmb.U32(b, 8), "invalid tree status NETWORK_NAME_DELETED"); }
	static async Task TreeCleanup()
	{
		await using var d = new Direct(); var id = await d.Open(); var open = d.Session.Opens[id];
		var pending = new PendingAsyncRequest { MessageId = 88, AsyncId = 9, Owner = open }; d.Connection.RegisterPending(pending); pending.Attach(pending.Token.Register(() => pending.Complete(NtStatus.Cancelled, [], () => Task.CompletedTask))); pending.CommitInterim();
		var b = await d.Send(RawSmb.TreeDisconnect(0, 1, 42)); Check.Equal(0u, RawSmb.U32(b, 8), "disconnect status");
		Check.Equal(0, d.Store.ActiveHandles, "tree closes backend handles"); Check.Equal(0, d.Session.Opens.Count, "tree removes opens");
		Check.Equal(0, d.Tree.OpenCount, "tree count balanced"); Check.Equal(0L, d.Options.Metrics.OpenHandles, "metrics balanced");
		Check.That(pending.Token.IsCancellationRequested && d.Connection.PendingRequests.IsEmpty, "tree cancels/removes pending");
	}
	static async Task CleanupFault()
	{
		await using var d = new Direct(); await d.Open("a"); await d.Open("b"); d.Store.Control.Enqueue("Dispose", new OperationStep(Error: new IOException("dispose fault")));
		await d.Send(RawSmb.TreeDisconnect(0, 1, 42)); Check.Equal(2, d.Store.Control.Count("Dispose"), "cleanup continues to second handle after first disposal throws");
		Check.That(d.Session.Opens.IsEmpty, "faulted cleanup removes all opens"); Check.Equal(0, d.Tree.OpenCount, "faulted cleanup balances counts");
	}
	static async Task Drain(string op, bool tree)
	{
		await using var d = new Direct(); var id = await d.Open(); var gate = new AsyncBarrier(); d.Store.Control.Enqueue(op, new OperationStep(Barrier: gate, IgnoreCancellation: true));
		var req = op switch { "Read" => RawSmb.Read(id, 1, 0, 0, 1, 42), "Write" => RawSmb.Write(id, [1], 0, 0, 1, 42), _ => RenamePacket(id, "b") };
		var work = d.Send(req); await gate.Entered; var close = d.Send(tree ? RawSmb.TreeDisconnect(0, 1, 42) : RawSmb.Close(id, 0, 1, 42));
		try { Check.That(!close.IsCompleted, "close waits for controlled in-flight " + op); Check.Equal(1, d.Store.ActiveHandles, "backend alive during operation"); }
		finally { gate.Release(); await work; await close; }
		Check.Equal(0, d.Store.ActiveHandles, "drained operation disposed"); Check.Equal(1, d.Store.Handles.Single().DisposeCalls, "exactly one disposal");
	}
	static async Task CreateTreeRace()
	{
		await using var d = new Direct(); var gate = new AsyncBarrier(); d.Store.Control.Enqueue("Create", new OperationStep(Barrier: gate)); var create = d.Send(d.Create()); await gate.Entered;
		var close = d.Send(RawSmb.TreeDisconnect(0, 1, 42)); gate.Release(); await Task.WhenAll(create, close);
		Check.Equal(0, d.Store.ActiveHandles, "tree teardown leaves no racing CREATE handle"); Check.That(d.Session.Opens.IsEmpty, "no publication into removed tree");
	}
	internal sealed class Root : IDisposable { public string Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "smb-p2-" + Guid.NewGuid()); public Root() { Directory.CreateDirectory(Path); } public void Dispose() => Directory.Delete(Path, true); }
	static async Task<IFileHandle> Open(LocalFileStore s, string p) => (await s.CreateAsync(p, FileAccessIntent.ReadWrite | FileAccessIntent.Delete, CreateDispositionIntent.OpenIf, false, false)).Value.Handle;
	static async Task Deletion(string mode)
	{
		using var root = new Root(); var s = new LocalFileStore(root.Path, false); var a = await Open(s, "a"); var b = await Open(s, "a");
		try
		{
			Check.Equal(NtStatus.Success, await s.SetDeleteOnCloseAsync(a, true), "mark shared deletion");
			if (mode == "pending") { var r = await s.CreateAsync("a", FileAccessIntent.Read, CreateDispositionIntent.Open, false, false); if (r.IsSuccess) r.Value.Handle.Dispose(); Check.Equal((NtStatus)0xc0000056, r.Status, "new opens observe shared delete pending"); }
			if (mode == "clear") Check.Equal(NtStatus.Success, await s.SetDeleteOnCloseAsync(b, false), "other open clears shared disposition");
			await a.CloseAsync(); await a.DisposeAsync(); Check.That(File.Exists(root.Path + "/a"), "first close preserves object held by another open");
			await b.CloseAsync(); await b.DisposeAsync(); Check.Equal(mode == "clear", File.Exists(root.Path + "/a"), "final close applies current shared disposition");
		}
		finally { a.Dispose(); b.Dispose(); }
	}
	static async Task RenameHandles() { using var r = new Root(); var s = new LocalFileStore(r.Path, false); using var a = await Open(s, "a"); using var b = await Open(s, "a"); Check.Equal(NtStatus.Success, await s.RenameAsync(a, "b", false), "rename"); Check.Equal("b", b.Path, "all opens relocate"); Check.Equal("b", b.GetInfo().Name, "metadata follows rename"); }
	static SmbOpen Owner(IFileHandle h, ulong id) => new SmbOpen { VolatileFileId = id, LocalOpen = h, PathName = h.Path };
	static async Task RenameLocks() { using var r = new Root(); var s = new LocalFileStore(r.Path, false); using var a = await Open(s, "a"); var locks = new InMemoryLockManager(); var o = Owner(a, 1); await locks.ApplyAsync(o, [new LockElement(0, 10, true, false)], true, default); await s.RenameAsync(a, "b", false); using var b = await Open(s, "b"); Check.That(!locks.IsRangeAccessible(Owner(b, 2), 0, 1, true), "rename preserves conflicting lock"); locks.ReleaseOwner(o); Check.That(locks.IsRangeAccessible(Owner(b, 2), 0, 1, true), "close releases lock after rename"); }
	static async Task ReplaceOpen() { using var r = new Root(); var s = new LocalFileStore(r.Path, false); using var a = await Open(s, "a"); using var b = await Open(s, "b"); Check.Equal(NtStatus.AccessDenied, await s.RenameAsync(a, "b", true), "replacement of open destination rejected by supported local constraint"); }
	static void Link(string a, string b) => NativeHost.HardLink(a, b);
	static async Task HardlinkLock() { using var r = new Root(); var s = new LocalFileStore(r.Path, false); using var a = await Open(s, "a"); Link(r.Path + "/a", r.Path + "/alias"); using var b = await Open(s, "alias"); var l = new InMemoryLockManager(); await l.ApplyAsync(Owner(a, 1), [new LockElement(0, 10, true, false)], true, default); Check.That(!l.IsRangeAccessible(Owner(b, 2), 0, 1, true), "hardlink shares range-lock identity"); }
	static async Task HardlinkDelete() { using var r = new Root(); var s = new LocalFileStore(r.Path, false); using var a = await Open(s, "a"); Link(r.Path + "/a", r.Path + "/alias"); await s.SetDeleteOnCloseAsync(a, true); var b = await s.CreateAsync("alias", FileAccessIntent.Read, CreateDispositionIntent.Open, false, false); if (b.IsSuccess) b.Value.Handle.Dispose(); Check.Equal((NtStatus)0xc0000056, b.Status, "hardlink observes pending object"); }
	static async Task StreamLocks() { using var r = new Root(); var s = new LocalFileStore(r.Path, false); using var a = await Open(s, "a"); using var b = (await s.OpenNamedStreamAsync("a", "one", FileAccessIntent.ReadWrite, CreateDispositionIntent.OpenIf)).Value.Handle; var l = new InMemoryLockManager(); await l.ApplyAsync(Owner(a, 1), [new LockElement(0, 10, true, false)], true, default); Check.That(l.IsRangeAccessible(Owner(b, 2), 0, 1, true), "named stream lock identity distinct from unnamed stream"); }
	static async Task StreamRename() { using var r = new Root(); var s = new LocalFileStore(r.Path, false); using var a = await Open(s, "a"); using var b = (await s.OpenNamedStreamAsync("a", "one", FileAccessIntent.ReadWrite, CreateDispositionIntent.OpenIf)).Value.Handle; await s.WriteAsync(b, 0, new byte[] { 42 }); await s.RenameAsync(a, "b", false); var result = await s.OpenNamedStreamAsync("b", "one", FileAccessIntent.ReadWrite, CreateDispositionIntent.Open); Check.Equal(NtStatus.Success, result.Status, "renamed base retains named stream"); using var c = result.Value.Handle; var bytes = new byte[1]; Check.Equal(1, (await s.ReadAsync(c, 0, bytes)).Value, "named stream remains accessible after base rename"); Check.Equal((byte)42, bytes[0], "named stream content preserved"); }
	static byte[] RenamePacket((ulong P, ulong V) id, string name) { var n = Encoding.Unicode.GetBytes(name); var length = Math.Max(24, 20 + n.Length); var b = RawSmb.Header(17, 32 + length, 0, 1, 42); RawSmb.Put16(b, 64, 33); b[66] = 1; b[67] = 10; RawSmb.Put32(b, 68, (uint)length); RawSmb.Put16(b, 72, 96); RawSmb.Put64(b, 80, id.P); RawSmb.Put64(b, 88, id.V); RawSmb.Put32(b, 112, (uint)n.Length); n.CopyTo(b, 116); return b; }
	internal static byte[] Disposition((ulong P, ulong V) id, WireClient c, bool delete) { var b = RawSmb.Header(17, 33, c.NextMessageId(), c.Session, c.Tree); RawSmb.Put16(b, 64, 33); b[66] = 1; b[67] = 13; RawSmb.Put32(b, 68, 1); RawSmb.Put16(b, 72, 96); RawSmb.Put64(b, 80, id.P); RawSmb.Put64(b, 88, id.V); b[96] = (byte)(delete ? 1 : 0); return b; }
	static async Task WireDelete() { using var r = new Root(); await using var h = Smb.Host.SmbServerBuilder.Create().WithEndpoint(System.Net.IPAddress.Loopback, 0).UseAuthentication(new Smb.Auth.Ntlm.NtlmSpnegoNegotiator(new Smb.Auth.InMemoryIdentityBackend().AddUser(HostFixture.Domain, HostFixture.User, HostFixture.Password))).AddShare(new Share { Name = "P0", FileStore = new LocalFileStore(r.Path, false) }).Build(); await h.StartAsync(); await using var c = new WireClient(); await c.ConnectAsync(h.Endpoint, HostFixture.Domain, HostFixture.User, HostFixture.Password); var b = RawSmb.Create("a", false, c.NextMessageId(), c.Session, c.Tree); RawSmb.Put32(b, 88, 0x10003); var resp = await c.ExchangeAsync(b, size: 89); var id = (RawSmb.U64(resp, 128), RawSmb.U64(resp, 136)); await c.ExchangeAsync(Disposition(id, c, true), size: 2); await c.ExchangeAsync(RawSmb.Create("a", false, c.NextMessageId(), c.Session, c.Tree), 0xc0000056, 9); await c.CloseAsync(id); Check.That(!File.Exists(r.Path + "/a"), "wire final delete"); }
}
