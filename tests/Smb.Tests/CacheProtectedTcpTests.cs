using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server;
using Smb.Server.Locking;
using Smb.Server.State;
using Smb.Testing;
using ProtectedPeer = MultichannelWireTests.Peer;

internal static partial class CacheSequenceRecoveryTests
{
    static IEnumerable<(string Name, Func<Task> Run)> ProtectedCases()
    {
        foreach (var durable in new[] { false, true })
        foreach (var encrypted in new[] { false, true })
            foreach (var existing in new[] { false, true })
                yield return ($"cache.repair.admission-race.{durable}.{encrypted}.{existing}", () => EligibilityRace(durable, encrypted, existing));
        foreach (var durable in new[] { false, true })
        foreach (var encrypted in new[] { false, true })
        foreach (var leased in new[] { false, true })
            yield return ($"cache.repair.barrier.{durable}.{encrypted}.{leased}", () => PhysicalBarrier(durable, encrypted, leased));
        foreach (var durable in new[] { false, true })
        foreach (var encrypted in new[] { false, true })
        foreach (var leaseFirst in new[] { false, true })
        foreach (var dialect in new ushort[] { 0x300, 0x311 })
            yield return ($"cache.repair.protected.{durable}.{encrypted}.{leaseFirst}.{dialect:x}", () => Protected(durable, encrypted, leaseFirst, dialect));
    }
    sealed class AdmissionGateLocks(ILockManager inner) : ILockManager
    {
        internal AsyncBarrier? Gate;
        public bool IsRangeAccessible(SmbOpen owner, ulong offset, ulong length, bool forWrite)
        { var gate = Interlocked.Exchange(ref Gate, null); if (gate != null) gate.WaitAsync().GetAwaiter().GetResult(); return inner.IsRangeAccessible(owner, offset, length, forWrite); }
        public Task<LockOutcome> ApplyAsync(SmbOpen owner, IReadOnlyList<LockElement> elements, bool failImmediately, CancellationToken token) => inner.ApplyAsync(owner, elements, failImmediately, token);
        public bool HasConflict(SmbOpen owner, IReadOnlyList<LockElement> elements) => inner.HasConflict(owner, elements);
        public void ReleaseOwner(SmbOpen owner) => inner.ReleaseOwner(owner);
    }
    static async Task EligibilityRace(bool durable, bool encrypted, bool existing)
    {
        using var root = new P6Tests.Root(); await using var host = new HostFixture(); var options = host.Server.State.Options;
        options.FeaturePolicy = durable ? SmbFeaturePolicy.Durable : SmbFeaturePolicy.Caching; options.RequireEncryption = encrypted;
        var locks = new AdmissionGateLocks(options.LockManager); options.LockManager = locks;
        options.Shares.Add(new Smb.FileSystem.Share { Name = "P0", FileStore = P6Tests.Local(root.Path) });
        await host.StartAsync(); await using var writer = new ProtectedPeer(); await writer.Login(host, 0x311, encrypted ? (ushort)1 : (ushort)0);
        await using var reader = new ProtectedPeer(); if (existing) reader.Guid = writer.Guid; await reader.Login(host, 0x311, encrypted ? (ushort)1 : (ushort)0);
        var original = await writer.Exchange(existing ? FullLease(0x311, 1, disposition: 3) : Classic(0, 3)); var id = Id(original);
        var epoch = existing ? RawSmb.U16(Context(original), 48) : (ushort)100;
        var gate = new AsyncBarrier(); locks.Gate = gate;
        var request = P7cTests.Context(Classic(255), "RqLs", ContextData(0x311, existing ? 3u : 1u, 1, 100)); await reader.SendRequest(request);
        await gate.Entered.WaitAsync(Check.Timeout);
        try { await writer.Exchange(RawSmb.Write(id, [42], 0, 0, 0, 0)); }
        finally { gate.Release(); }
        var result = await reader.Receive(); Status(result, 0, "raced lease CREATE completes"); if (!encrypted) reader.Verify(result);
        Grant(result, existing ? 1u : 0u); Check.Equal(52, Context(result).Length, "declined raced grant retains requested v2 context");
        Check.Equal(epoch, RawSmb.U16(Context(result), 48), "eligibility invalidation cannot reset lease epoch");
        var other = Id(result); var read = await reader.Exchange(RawSmb.Read(other, 1, 0, 0, 0, 0)); Check.Equal((byte)42, read[read[66]], "raced admission preserves physical data");
        await reader.Exchange(RawSmb.Close(other, 0, 0, 0)); await writer.Exchange(RawSmb.Close(id, 0, 0, 0));
    }
    static async Task PhysicalBarrier(bool durable, bool encrypted, bool leased)
    {
        using var root = new P6Tests.Root(); var store = new P6AdvancedTests.GatedStore(P6Tests.Local(root.Path));
        await using var host = new HostFixture(); var options = host.Server.State.Options;
        options.FeaturePolicy = durable ? SmbFeaturePolicy.Durable : SmbFeaturePolicy.Caching; options.RequireEncryption = encrypted;
        options.Shares.Add(new Smb.FileSystem.Share { Name = "P0", FileStore = store });
        await host.StartAsync(); await using var writer = new ProtectedPeer(); await writer.Login(host, 0x311, encrypted ? (ushort)1 : (ushort)0);
        await using var reader = new ProtectedPeer(); await reader.Login(host, 0x311, encrypted ? (ushort)1 : (ushort)0);
        var id = Id(await writer.Exchange(Classic(0, 3))); var gate = new AsyncBarrier(); store.WriteBarrier = gate;
        await writer.SendRequest(RawSmb.Write(id, [42], 0, 0, 0, 0)); await gate.Entered.WaitAsync(Check.Timeout);
        byte[] Request() => leased ? FullLease(0x311, 1) : Classic(1);
        (ulong P, ulong V) other;
        try
        {
            var response = await reader.Exchange(Request()); other = Id(response);
            if (leased) Grant(response, 0); else Check.Equal((byte)0, response[66], "no classic READ grant while backend WRITE is physically active");
            Check.Equal(0L, new FileInfo(root.Path + "/file").Length, "controlled backend barrier precedes data mutation");
            Check.That(options.CacheCoordinator.PhysicalScopeCount > 0, "in-flight writer retains physical admission");
        }
        finally { gate.Release(); }
        var completed = await writer.Receive(); Status(completed, 0, "gated WRITE completes"); if (!encrypted) writer.Verify(completed);
        var rearmed = await reader.Exchange(Request()); var extra = Id(rearmed);
        if (leased) Grant(rearmed, 1); else Check.Equal((byte)1, rearmed[66], "READ cache can be rearmed after physical retirement");
        var read = await reader.Exchange(RawSmb.Read(other, 1, 0, 0, 0, 0)); Check.Equal((byte)42, read[read[66]], "gated WRITE bytes visible after retirement");
        await reader.Exchange(RawSmb.Close(extra, 0, 0, 0)); await reader.Exchange(RawSmb.Close(other, 0, 0, 0)); await writer.Exchange(RawSmb.Close(id, 0, 0, 0));
        Check.Equal(0, options.CacheCoordinator.PhysicalScopeCount, "all physical admissions retired"); Check.Equal(0, options.CacheCoordinator.GrantCount, "all barrier-test grants retired");
    }
    static async Task Protected(bool durable, bool encrypted, bool leaseFirst, ushort dialect)
    {
        using var root = new P6Tests.Root(); await using var host = new HostFixture(); var options = host.Server.State.Options;
        options.FeaturePolicy = durable ? SmbFeaturePolicy.DurableWithMultichannel : SmbFeaturePolicy.MultichannelWithCaching;
        options.EnableMultichannel = true; options.RequireEncryption = encrypted;
        options.Shares.Add(new Smb.FileSystem.Share { Name = "P0", FileStore = P6Tests.Local(root.Path) });
        await host.StartAsync(); await using var owner = new ProtectedPeer(); await owner.Login(host, dialect, encrypted ? (ushort)1 : (ushort)0);
        await using var channel = new ProtectedPeer(); await channel.Bind(host, owner);
        await using var peer = new ProtectedPeer(); await peer.Login(host, dialect, encrypted ? (ushort)1 : (ushort)0);
        var key = new LeaseKey(11, 19);
        byte[] Leased(uint disposition)
        { var q = Classic(255, disposition); return P6AdvancedTests.LeaseCreate(q, key, LeaseState.Read, true); }
        var first = await owner.Exchange(leaseFirst ? Leased(3) : Classic(9, 3)); var id = Id(first);
        if (leaseFirst) Grant(first, 1); else Check.Equal((byte)9, first[66], "classic owner batch");
        var request = leaseFirst ? Classic(1) : Leased(1); await peer.SendRequest(request);
        if (!leaseFirst)
        {
            Status(await peer.Receive(), 0x103, "mixed CREATE pends for exclusive downgrade");
            var notification = await owner.Receive(); Check.Equal(encrypted, owner.LastEncrypted, "break uses negotiated protection");
            Check.Equal((ushort)24, RawSmb.U16(notification, 64), "classic notification"); Check.Equal((byte)1, notification[66], "classic mixed target II");
            await channel.Exchange(ClassicAck(id, 1)); // ACK through separately authenticated bound TCP.
        }
        var second = await peer.Receive(); Status(second, 0, "compatible mixed grant");
        if (encrypted) Check.That(peer.LastEncrypted, "mixed CREATE final encrypted"); else peer.Verify(second);
        var peerId = Id(second); if (leaseFirst) Check.Equal((byte)1, second[66], "READ lease permits level II"); else Grant(second, 1);
        var bytes = new byte[] { 1, 3, 3, 7 }; await peer.SendRequest(RawSmb.Write(peerId, bytes, 0, 0, 0, 0));
        var revoked = await owner.Receive(); Check.Equal(encrypted, owner.LastEncrypted, "data invalidation protection");
        Check.Equal((ushort)18, RawSmb.U16(revoked, 12), "foreign data invalidation command");
        Check.Equal(ulong.MaxValue, RawSmb.U64(revoked, 24), "foreign invalidation MessageId");
        if (leaseFirst)
        {
            Check.Equal((ushort)44, RawSmb.U16(revoked, 64), "lease READ invalidation");
            Check.Equal(1u, RawSmb.U32(revoked, 88), "lease held READ"); Check.Equal(0u, RawSmb.U32(revoked, 92), "lease target NONE"); Check.Equal(0u, RawSmb.U32(revoked, 68), "READ invalidation requires no ACK");
            var self = await peer.Receive(); Check.Equal((ushort)18, RawSmb.U16(self, 12), "writing level-II handle invalidates itself"); Check.Equal((byte)0, self[66], "self invalidation NONE");
        }
        else { Check.Equal((ushort)24, RawSmb.U16(revoked, 64), "classic invalidation structure"); Check.Equal((byte)0, revoked[66], "old classic target NONE"); }
        var completed = await peer.Receive(); Status(completed, 0, "WRITE completes after invalidations"); if (!encrypted) peer.Verify(completed); else Check.That(peer.LastEncrypted, "WRITE final encrypted");
        var read = await channel.Exchange(RawSmb.Read(id, (uint)bytes.Length, 0, 0, 0, 0)); Check.That(bytes.SequenceEqual(RawSmb.Buffer(read, read[66], RawSmb.U32(read, 68))), "bound channel reads coherent bytes");
        await channel.Exchange(RawSmb.Close(id, 0, 0, 0)); await peer.Exchange(RawSmb.Close(peerId, 0, 0, 0));
        Check.Equal(0, options.CacheCoordinator.GrantCount, "protected mixed grants cleaned up"); Check.Equal(0, options.CacheCoordinator.BreakingCount, "no outstanding ACK");
    }
}
