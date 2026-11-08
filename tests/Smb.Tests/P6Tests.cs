using Smb.FileSystem.Local;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server;
using Smb.Testing;

static class P6Tests
{
    public static IEnumerable<(string Name, Func<Task> Run)> Cases()
    {
        yield return ("p6.profile.explicit", Profile);
        foreach (var level in new[] { OplockLevel.LevelII, OplockLevel.Exclusive, OplockLevel.Batch })
        foreach (var operation in new[] { "write", "overwrite", "size", "rename" })
        { var l = level; var o = operation; yield return ($"p6.seeded.{level}.{operation}", () => Seeded(l, o)); }
        yield return ("p6.ack.unsolicited", Unsolicited);
        yield return ("p6.seeded.mixed-managers", Mixed);
        foreach (var state in new[] { LeaseState.Read, LeaseState.ReadWrite, LeaseState.ReadHandle, LeaseState.ReadWriteHandle })
        { var st = state; yield return ($"p6.seeded.lease-{st}-write", () => LeaseWrite(st)); }
        foreach (var level in new[] { OplockLevel.LevelII, OplockLevel.Exclusive, OplockLevel.Batch })
        { var l = level; yield return ($"p6.grant.{level}", () => Grant(l)); }
    }
    internal static SmbFeaturePolicy Caching(bool copy = false) => copy ? SmbFeaturePolicy.CachingWithCopy : SmbFeaturePolicy.Caching;
    internal static LocalFileStore Local(string root, bool exclusive = true) => new LocalFileStore(root, false, null, exclusive);
    static Task Profile() { Check.That(Caching().Oplocks && Caching().Leasing, "explicit caching profile offers individually gated file caching"); return Task.CompletedTask; }
    static async Task Unsolicited()
    {
        using var r = new Root(); await using var d = new P2Tests.Direct(Local(r.Path));
        var id = await d.Open(); var ack = Ack(id, OplockLevel.None);
        Check.Equal(0xc0000184u, RawSmb.U32(await d.Send(ack), 8), "unsolicited ACK cannot create or upgrade cache state");
    }
    static async Task Grant(OplockLevel level)
    { using var r = new Root(); await using var d = new P2Tests.Direct(Local(r.Path)); d.Options.FeaturePolicy = Caching(); var req = d.Create(); req[67] = (byte)level; var b = await d.Send(req); Check.Equal((byte)level, b[66], "explicit coherent backend classic grant"); }
    static LeaseRequest Lease(LeaseState state) => new LeaseRequest { Key = new LeaseKey(1, 2), RequestedState = state };
    static async Task Mixed()
    { using var r = new Root(); await using var d = new P2Tests.Direct(Local(r.Path)); d.Options.FeaturePolicy = Caching(); var a = await d.Open(); var b = await d.Open(); var x = d.Options.LeaseManager.RequestLease(d.Session.Opens[a], Lease(LeaseState.ReadWrite)); Check.Equal(LeaseState.ReadWrite, x.GrantedState, "seed lease"); var g = d.Options.OplockManager.RequestOplock(d.Session.Opens[b], OplockLevel.Batch); Check.Equal(OplockLevel.None, g.GrantedLevel, "classic manager cannot independently grant against outstanding lease rights"); }
    static async Task LeaseWrite(LeaseState state)
    {
        using var r = new Root(); File.WriteAllText(r.Path + "/a", "original"); await using var d = new P2Tests.Direct(Local(r.Path)); d.Options.FeaturePolicy = Caching();
        var a = await d.Open(); var b = await d.Open(); var owner = d.Session.Opens[a]; var lease = Lease(state); owner.LeaseKey = lease.Key;
        var grant = d.Options.LeaseManager.RequestLease(owner, lease); Check.Equal(state, grant.GrantedState, "seed maintained lease state"); owner.LeaseState = state; owner.OplockLevel = OplockLevel.Lease;
        var t = new RecordingTransport(); t.Attach(d.Connection); var response = await d.Send(RawSmb.Write(b, "changed!"u8.ToArray(), 0, 0, 1, 42));
        Check.That(t.Sends.Any(s => RawSmb.U16(s.Message, 64) == 44), "lease break before conflicting WRITE");
        if (state != LeaseState.Read)
        { Check.Equal(0x103u, RawSmb.U32(response, 8), "lease WRITE parks"); Check.Equal("original", NativeHost.ReadAllText(r.Path + "/a"), "lease protected bytes before ACK"); var pending = d.Connection.PendingRequests.Values.Single(); Check.Equal(0u, RawSmb.U32(await d.Send(LeaseAck(lease.Key)), 8), "lease ACK accepted"); await pending.Finished.WaitAsync(Check.Timeout); Check.Equal(NtStatus.Success, pending.FinalStatus, "lease WRITE final"); }
        Check.Equal("changed!", NativeHost.ReadAllText(r.Path + "/a"), "lease WRITE after revocation"); Check.Equal(LeaseState.None, owner.LeaseState, "lease state revoked");
    }
    internal static byte[] LeaseAck(LeaseKey key, LeaseState state = LeaseState.None)
    { var b = RawSmb.Header(18, 36, 0, 1, 42); RawSmb.Put16(b, 64, 36); key.ToBytes().CopyTo(b, 72); RawSmb.Put32(b, 88, (uint)state); return b; }
    internal static byte[] Ack((ulong P, ulong V) id, OplockLevel level)
    { var b = RawSmb.Header(18, 24, 0, 1, 42); RawSmb.Put16(b, 64, 24); b[66] = (byte)level; RawSmb.Put64(b, 72, id.P); RawSmb.Put64(b, 80, id.V); return b; }
    internal static byte[] Set((ulong P, ulong V) id, byte cls, byte[] data)
    { var b = RawSmb.Header(17, 32 + data.Length, 0, 1, 42); RawSmb.Put16(b, 64, 33); b[66] = 1; b[67] = cls; RawSmb.Put32(b, 68, (uint)data.Length); RawSmb.Put16(b, 72, 96); RawSmb.Put64(b, 80, id.P); RawSmb.Put64(b, 88, id.V); data.CopyTo(b, 96); return b; }
    internal sealed class Root : IDisposable
    { public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "smb-p6-" + Guid.NewGuid().ToString("N")); public Root() => Directory.CreateDirectory(Path); public void Dispose() => Directory.Delete(Path, true); }
    internal static byte[] Rename((ulong P, ulong V) id, string name)
    { var n = System.Text.Encoding.Unicode.GetBytes(name); var data = new byte[20 + n.Length]; RawSmb.Put32(data, 16, (uint)n.Length); n.CopyTo(data, 20); return Set(id, 10, data); }
    static async Task Seeded(OplockLevel level, string operation)
    {
        using var r = new Root(); File.WriteAllText(r.Path + "/a", "original");
        await using var d = new P2Tests.Direct(Local(r.Path)); d.Options.FeaturePolicy = Caching();
        var owner = await d.Open(); var other = await d.Open();
        var open = d.Session.Opens[owner];
        // Seed the maintained manager directly, independently of profile/CREATE bootstrap.
        var grant = d.Options.OplockManager.RequestOplock(open, level);
        Check.Equal(level, grant.GrantedLevel, "seed existing cache holder"); open.OplockLevel = grant.GrantedLevel;
        var transport = new RecordingTransport(); transport.Attach(d.Connection);
        byte[] request;
        if (operation == "write") request = RawSmb.Write(other, "changed!"u8.ToArray(), 0, 0, 1, 42);
        else if (operation == "overwrite") { request = d.Create(); RawSmb.Put32(request, 100, 4); }
        else if (operation == "rename") request = Rename(other, "b");
        else { var n = new byte[8]; RawSmb.Put64(n, 0, 1); request = Set(other, 20, n); }
        var result = await d.Send(request).WaitAsync(Check.Timeout);
        Check.That(transport.Sends.Any(s => RawSmb.U16(s.Message, 12) == 18), "break notification must precede conflicting backend mutation");
        if (level is OplockLevel.Exclusive or OplockLevel.Batch)
        {
            Check.Equal(0x103u, RawSmb.U32(result, 8), "conflicting operation parks through P4 pending");
            Check.Equal("original", NativeHost.ReadAllText(r.Path + "/a"), "bytes preserved before acknowledgment");
            Check.That(!File.Exists(r.Path + "/b"), "namespace preserved before acknowledgment");
            var pending = d.Connection.PendingRequests.Values.Single();
            Check.Equal(0u, RawSmb.U32(await d.Send(Ack(owner, OplockLevel.None)), 8), "acknowledgment accepted");
            await pending.Finished.WaitAsync(Check.Timeout);
            Check.Equal(NtStatus.Success, pending.FinalStatus, "conflicting operation completes after ACK");
        }
        else Check.Equal(0u, RawSmb.U32(result, 8), "II revocation requires notification without ACK");
        Check.Equal(OplockLevel.None, open.OplockLevel, "conflicting cached reads/writes revoked");
        if (operation == "write") Check.Equal("changed!", NativeHost.ReadAllText(r.Path + "/a"), "write after revocation");
        if (operation == "overwrite") Check.Equal(0L, new FileInfo(r.Path + "/a").Length, "overwrite after revocation");
        if (operation == "size") Check.Equal(1L, new FileInfo(r.Path + "/a").Length, "resize after revocation");
        if (operation == "rename") Check.Equal("original", NativeHost.ReadAllText(r.Path + "/b"), "rename preserves bytes");
        Check.That(d.Connection.PendingRequests.IsEmpty, "pending state retired");
    }
}
