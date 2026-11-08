using Smb.Protocol.Enums;
using Smb.Server.Locking;
using Smb.Server.State;
using Smb.Testing;

static class P6RaceTests
{
    public static IEnumerable<(string Name, Func<Task> Run)> Cases() { yield return ("p6.grant.lock-check-admission-race", GrantLockRace); yield return ("p6.create.cancel-publication-one-winner", CancelPublication); yield return ("p6.create.async-backend-error-preserved", CreateError); }
    static async Task CreateError()
    {
        await using var d = new P2Tests.Direct(); d.Options.FeaturePolicy = P6Tests.Caching(); var gate = new AsyncBarrier(); d.Store.Control.Enqueue("Create", new OperationStep(Barrier: gate, Status: NtStatus.DiskFull)); var create = d.Send(d.Create()); await gate.Entered.WaitAsync(Check.Timeout); gate.Release(); var response = await create.WaitAsync(Check.Timeout); Check.Equal((uint)NtStatus.DiskFull, RawSmb.U32(response, 8), "provisional rollback preserves actual backend failure instead of cancelling its own response"); Check.That(d.Session.Opens.IsEmpty, "failed asynchronous CREATE rolls back");
    }
    sealed class PublicationMetrics : Smb.Server.Diagnostics.SmbServerMetrics
    {
        internal readonly TaskCompletionSource Entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly ManualResetEventSlim Resume = new ManualResetEventSlim(false);
        public override void OnHandleOpened() { base.OnHandleOpened(); Entered.TrySetResult(); Check.That(Resume.Wait(Check.Timeout), "publication callback released"); }
    }
    static async Task CancelPublication()
    {
        await using var d = new P2Tests.Direct(); d.Options.FeaturePolicy = P6Tests.Caching(); var metrics = new PublicationMetrics(); d.Options.Metrics = metrics; var info = new AsyncBarrier(); d.Store.Control.Enqueue("GetInfo", new OperationStep(Barrier: info)); var create = d.Send(d.Create()); await info.Entered.WaitAsync(Check.Timeout); var physical = d.Connection.OrdinaryRequests.Values.Single(); info.Release(); await metrics.Entered.Task.WaitAsync(Check.Timeout); physical.Cancel();
        try { var cancelled = await create.WaitAsync(Check.Timeout); Check.Equal(0xc0000120u, RawSmb.U32(cancelled, 8), "cancellation wins during prepublication observer work"); }
        finally { metrics.Resume.Set(); await physical.PhysicalFinished.WaitAsync(Check.Timeout); }
        Check.That(d.Session.Opens.IsEmpty, "losing CREATE cannot publish an open after the cancellation response won"); Check.Equal(0, d.Store.ActiveHandles, "losing publication releases acquired backend handle"); Check.Equal(0L, metrics.OpenHandles, "losing publication balances handle metrics");
    }
    sealed class PausedLockManager : ILockManager
    {
        readonly InMemoryLockManager inner = new InMemoryLockManager();
        internal bool Pause;
        internal readonly TaskCompletionSource Entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly ManualResetEventSlim Resume = new ManualResetEventSlim(false);
        public bool IsRangeAccessible(SmbOpen owner, ulong offset, ulong length, bool write)
        { var result = inner.IsRangeAccessible(owner, offset, length, write); if (Pause) { Pause = false; Entered.TrySetResult(); Check.That(Resume.Wait(Check.Timeout), "release lock eligibility callback"); } return result; }
        public Task<LockOutcome> ApplyAsync(SmbOpen open, IReadOnlyList<LockElement> elements, bool failImmediately, CancellationToken token) => inner.ApplyAsync(open, elements, failImmediately, token);
        public void ReleaseOwner(SmbOpen open) => inner.ReleaseOwner(open);
    }
    static async Task GrantLockRace()
    {
        using var r = new P6Tests.Root(); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(); var a = await d.Open(); var b = await d.Open(); var locks = new PausedLockManager(); d.Options.LockManager = locks; locks.Pause = true;
        var grant = Task.Run(() => d.Options.CacheCoordinator.RequestOplock(d.Session.Opens[b], OplockLevel.Batch)); await locks.Entered.Task.WaitAsync(Check.Timeout);
        try { var req = RawSmb.Header(10, 48, 0, 1, 42); RawSmb.Put16(req, 64, 48); RawSmb.Put16(req, 66, 1); RawSmb.Put64(req, 72, a.P); RawSmb.Put64(req, 80, a.V); RawSmb.Put64(req, 96, 1); RawSmb.Put32(req, 104, 0x12); Check.Equal(0u, RawSmb.U32(await d.Send(req), 8), "foreign LOCK completes between eligibility check and cache admission"); }
        finally { locks.Resume.Set(); }
        Check.Equal(OplockLevel.None, (await grant.WaitAsync(Check.Timeout)).GrantedLevel, "cache admission rechecks changes after an external lock eligibility callback");
    }
}
