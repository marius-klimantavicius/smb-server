using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Testing;

static class P6NamespaceTests
{
    public static IEnumerable<(string Name, Func<Task> Run)> Cases()
    {
        yield return ("p6.namespace.rename-destination-cache", Destination);
        yield return ("p6.namespace.rename-other-stream", Stream);
        yield return ("p6.namespace.no-stream-grant-during-rename", GrantDuringRename);
    }
    static async Task GrantDuringRename()
    {
        using var r = new P6Tests.Root(); var store = new P6AdvancedTests.GatedStore(P6Tests.Local(r.Path)); await using var d = new P2Tests.Direct(store); d.Options.FeaturePolicy = P6Tests.Caching(); var a = await d.Open(); var stream = await d.Open("a:stream"); var gate = new AsyncBarrier(); store.RenameBarrier = gate; var rename = d.Send(P6Tests.Rename(a, "b")); await gate.Entered.WaitAsync(Check.Timeout);
        try { var grant = d.Options.CacheCoordinator.RequestOplock(d.Session.Opens[stream], OplockLevel.Batch); Check.Equal(OplockLevel.None, grant.GrantedLevel, "namespace mutation blocks cache grants on every stream until actual completion"); }
        finally { gate.Release(); await rename.WaitAsync(Check.Timeout); }
    }
    static async Task Destination()
    {
        using var r = new P6Tests.Root(); File.WriteAllText(r.Path + "/a", "source"); File.WriteAllText(r.Path + "/b", "target"); var store = new P6AdvancedTests.GatedStore(P6Tests.Local(r.Path)); await using var d = new P2Tests.Direct(store); d.Options.FeaturePolicy = P6Tests.Caching(); var a = await d.Open(); var b = await d.Open("b"); d.Options.CacheCoordinator.RequestLease(d.Session.Opens[b], new LeaseRequest { Key = new LeaseKey(83, 84), RequestedState = LeaseState.ReadHandle }); var t = new RecordingTransport(); t.Attach(d.Connection); var req = P6Tests.Rename(a, "b"); req[96] = 1;
        var response = await d.Send(req); Check.That(t.Sends.Any(), "rename destination participates in pre-backend break decision"); Check.Equal(0x103u, RawSmb.U32(response, 8), "rename destination break wait"); Check.Equal(0, store.RenameCalls, "rename backend not entered before destination ACK"); var pending = d.Connection.PendingRequests.Values.Single(); await d.Send(P6Tests.LeaseAck(new LeaseKey(83, 84))); await pending.Finished.WaitAsync(Check.Timeout); Check.Equal(NtStatus.AccessDenied, pending.FinalStatus, "local backend still declines replacement of an open destination"); Check.Equal("source", NativeHost.ReadAllText(r.Path + "/a"), "failed replacement preserves source"); Check.Equal("target", NativeHost.ReadAllText(r.Path + "/b"), "failed replacement preserves target");
    }
    static async Task Stream()
    {
        using var r = new P6Tests.Root(); await using var d = new P2Tests.Direct(P6Tests.Local(r.Path)); d.Options.FeaturePolicy = P6Tests.Caching(); var a = await d.Open(); var stream = await d.Open("a:stream"); await d.Send(RawSmb.Write(stream, [42], 0, 0, 1, 42)); d.Options.CacheCoordinator.RequestLease(d.Session.Opens[stream], new LeaseRequest { Key = new LeaseKey(85, 86), RequestedState = LeaseState.ReadHandle }); var t = new RecordingTransport(); t.Attach(d.Connection);
        var response = await d.Send(P6Tests.Rename(a, "b")); Check.That(t.Sends.Any(), "base-file rename revokes namespace cache rights on other streams"); Check.Equal(0x103u, RawSmb.U32(response, 8), "other-stream handle cache waits"); var pending = d.Connection.PendingRequests.Values.Single(); await d.Send(P6Tests.LeaseAck(new LeaseKey(85, 86))); await pending.Finished.WaitAsync(Check.Timeout); Check.Equal(NtStatus.Success, pending.FinalStatus, "rename after other-stream ACK"); var read = await d.Send(RawSmb.Read(stream, 1, 0, 0, 1, 42)); Check.Equal((byte)42, read[80], "renamed stream retains stable handle/content");
    }
}
