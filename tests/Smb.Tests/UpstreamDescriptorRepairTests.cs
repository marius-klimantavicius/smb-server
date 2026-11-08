using System.Text;
using Smb.Auth;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.FileSystem.Security;
using Smb.Protocol.Enums;
using Smb.Protocol.Security;
using Smb.Testing;

internal static class UpstreamDescriptorRepairTests
{
    const uint Full = 0x1f01ff, Denied = 0xc0000022;
    static readonly byte[] Payload = [19, 28, 37, 46];
    public static IEnumerable<(string Name, Func<Task> Run)> Cases()
    {
        foreach (var shape in new[] { "rename-reuse", "delete-reuse", "hardlink", "unlink-alias", "replace-alias", "directory", "host-rename" })
            yield return ("upstream.descriptorwire.identity." + shape, () => Namespace(shape));
        yield return ("upstream.descriptorwire.injected-path-store", Injected);
        yield return ("upstream.descriptorwire.injected-replaced-path", InjectedReplacement);
        yield return ("upstream.descriptorwire.set-rename-order", SetRename);
        yield return ("upstream.descriptorwire.concurrent-partial-set", PartialSet);
        foreach (var directory in new[] { false, true }) foreach (var deny in new[] { false, true })
            yield return ($"upstream.descriptorwire.inherit-only.{directory}.{deny}", () => InheritOnly(directory, deny));
        foreach (var mask in new uint[] { 0x80000000, 0x40000000, 0x20000000, 0x10000000 })
            yield return ($"upstream.descriptorwire.generic.{mask:x8}", () => Generic(mask));
        yield return ("upstream.descriptorwire.owner-and-owner-rights", Owner);
        yield return ("upstream.descriptorwire.maximum-plus-explicit", Maximum);
        yield return ("upstream.descriptorwire.null-dacl-query", NullDacl);
        foreach (var type in new byte[] { 6, 10 })
            yield return ($"upstream.descriptorwire.unsupported-deny.{type}", () => Unsupported(type));
        yield return ("upstream.descriptorwire.unsupported-creator-inheritance", CreatorInheritance);
        yield return ("upstream.descriptorfinding.denied-overwrite-preserves-bytes", DeniedOverwrite);
        yield return ("upstream.descriptorfinding.parent-deny-add-file", ParentAccess);
    }
    static void Status(byte[] b, uint status, string why) => Check.Equal(status, RawSmb.U32(b, 8), why);
    static (ulong P, ulong V) Id(byte[] b) => (RawSmb.U64(b, 128), RawSmb.U64(b, 136));
    static byte[] Create(string path = "file", uint access = Full, uint disposition = 1, bool directory = false)
    { var b = RawSmb.Create(path, directory, 0, 1, 42); RawSmb.Put32(b, 88, access); RawSmb.Put32(b, 100, disposition); return b; }
    static async Task<(ulong P, ulong V)> Open(P2Tests.Direct d, string path = "file", uint access = Full, uint disposition = 1, bool directory = false)
    { var b = await d.Send(Create(path, access, disposition, directory)); Status(b, 0, "public CREATE " + path); return Id(b); }
    static async Task Close(P2Tests.Direct d, (ulong P, ulong V) id) => Status(await d.Send(RawSmb.Close(id, 0, 1, 42)), 0, "CLOSE");
    static byte[] Set((ulong P, ulong V) id, byte[] sd, uint fields = 4)
    { var b = P5Tests.SetPacket(id, 0, sd); b[66] = 3; RawSmb.Put32(b, 76, fields); return b; }
    static byte[] Query((ulong P, ulong V) id, uint fields = 4)
    { var b = P5Tests.QueryPacket(id, 3, 0, 4096); RawSmb.Put32(b, 80, fields); return b; }
    static byte[] Output(byte[] b)
    { Status(b, 0, "QUERY_INFO"); return b.AsSpan(RawSmb.U16(b, 66), (int)RawSmb.U32(b, 68)).ToArray(); }
    static byte[] Rename((ulong P, ulong V) id, string path, bool replace = false)
    { var n = Encoding.Unicode.GetBytes(path); var data = new byte[Math.Max(24, 20 + n.Length)]; data[0] = replace ? (byte)1 : (byte)0; RawSmb.Put32(data, 16, (uint)n.Length); n.CopyTo(data, 20); return P5Tests.SetPacket(id, 10, data); }
    static byte[] Sid(uint authority, params uint[] subs)
    { var b = new byte[8 + 4 * subs.Length]; b[0] = 1; b[1] = (byte)subs.Length; b[7] = (byte)authority; for (var i = 0; i < subs.Length; i++) RawSmb.Put32(b, 8 + 4 * i, subs[i]); return b; }
    static byte[] Ace(uint mask, bool deny = false, byte flags = 0, byte[]? sid = null)
    { sid ??= Sid(1, 0); var b = new byte[8 + sid.Length]; b[0] = deny ? (byte)1 : (byte)0; b[1] = flags; RawSmb.Put16(b, 2, (ushort)b.Length); RawSmb.Put32(b, 4, mask); sid.CopyTo(b, 8); return b; }
    static byte[] Dacl(params byte[][] aces)
    { var b = new byte[28 + aces.Sum(a => a.Length)]; b[0] = 1; RawSmb.Put16(b, 2, 0x8004); RawSmb.Put32(b, 16, 20); b[20] = 2; RawSmb.Put16(b, 22, (ushort)(b.Length - 20)); RawSmb.Put16(b, 24, (ushort)aces.Length); var at = 28; foreach (var a in aces) { a.CopyTo(b, at); at += a.Length; } return b; }
    static byte[] DenyRead() => Dacl(Ace(1, true), Ace(Full));
    static async Task Apply(P2Tests.Direct d, (ulong P, ulong V) id, byte[]? sd = null) => Status(await d.Send(Set(id, sd ?? DenyRead())), 0, "SET_SECURITY accepted");
    static async Task Data(P2Tests.Direct d, (ulong P, ulong V) id)
    { var b = await d.Send(RawSmb.Read(id, (uint)Payload.Length, 0, 0, 1, 42)); Status(b, 0, "old grant remains readable"); Check.That(b.AsSpan(b[66], (int)RawSmb.U32(b, 68)).SequenceEqual(Payload), "wire bytes preserved"); }
    static async Task Namespace(string shape)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        var admin = await Open(d, disposition: 2); Status(await d.Send(RawSmb.Write(admin, Payload, 0, 0, 1, 42)), 0, "seed bytes");
        if (shape is "hardlink" or "unlink-alias") NativeHost.HardLink(Path.Combine(root.Path, "file"), Path.Combine(root.Path, "alias"));
        var stream = await Open(d, "file:stream", disposition: 3);
        await Apply(d, stream); // Setting through a named stream must protect its base and every alias.
        Status(await d.Send(Create(access: 1)), Denied, "deny applies on original path");
        if (shape == "rename-reuse")
        {
            Status(await d.Send(Rename(admin, "renamed")), 0, "rename with old DELETE grant");
            Status(await d.Send(Create("renamed", 1)), Denied, "renamed object retains deny");
            var replacement = await Open(d, disposition: 2); await Close(d, replacement);
            await Close(d, stream); await Close(d, admin);
            Status(await d.Send(Create("renamed", 1)), Denied, "deny persists after final close");
            await Close(d, await Open(d, access: 1));
        }
        if (shape == "delete-reuse")
        {
            await Close(d, stream); Status(await d.Send(P5Tests.SetPacket(admin, 13, [1])), 0, "arm final unlink"); await Close(d, admin);
            await Close(d, await Open(d, disposition: 2));
            await Close(d, await Open(d, access: 1));
        }
        if (shape == "hardlink")
        {
            Status(await d.Send(Create("alias", 1)), Denied, "alias cannot bypass deny"); await Close(d, stream); await Close(d, admin);
            Status(await d.Send(Create("alias", 1)), Denied, "alias ACL survives no open handles");
        }
        if (shape == "unlink-alias")
        {
            await Close(d, stream); var del = P5Tests.SetPacket(admin, 13, [1]); Status(await d.Send(del), 0, "arm unlink"); await Close(d, admin);
            Status(await d.Send(Create("alias", 1)), Denied, "remaining hardlink retains descriptor after unlink");
            await Close(d, await Open(d, disposition: 2));
            Status(await d.Send(Create("alias:stream", 1)), Denied, "remaining alias stream retains base policy");
        }
        if (shape == "replace-alias")
        {
            var destination = await Open(d, "destination", disposition: 2); await Apply(d, destination); await Close(d, destination);
            NativeHost.HardLink(Path.Combine(root.Path, "destination"), Path.Combine(root.Path, "survivor"));
            await Apply(d, admin, Dacl(Ace(Full))); Status(await d.Send(Rename(admin, "destination", true)), 0, "replace destination link");
            Status(await d.Send(Create("survivor", 1)), Denied, "replaced destination's other alias retains deny");
            await Data(d, await Open(d, "destination"));
        }
        if (shape == "directory")
        {
            var parent = await Open(d, "parent", disposition: 2, directory: true); await Apply(d, parent, Dacl(Ace(1, true, 1), Ace(Full, flags: 3)));
            var child = await Open(d, "parent\\child", Full & ~1u, 2); await Close(d, child);
            Status(await d.Send(Rename(parent, "moved")), 0, "rename parent directory");
            Status(await d.Send(Create("moved\\child", 1)), Denied, "closed child descriptor follows parent rename");
            await Close(d, await Open(d, "moved\\new", Full & ~1u, 2));
            Status(await d.Send(Create("moved\\new", 1)), Denied, "inheritance finds renamed parent's identity");
        }
        if (shape == "host-rename")
        {
            // Host mutation is only a sequential diagnostic; it does not assert coordinated cache safety.
            File.Move(Path.Combine(root.Path, "file"), Path.Combine(root.Path, "host-moved"));
            File.WriteAllBytes(Path.Combine(root.Path, "file"), [7]);
            Status(await d.Send(Create("host-moved", 1)), Denied, "sequential host rename retains same native object policy");
            await Close(d, await Open(d, access: 1)); await Data(d, admin);
        }
    }
    sealed class DescriptorStore : ISecurityDescriptorStore
    {
        readonly InMemorySecurityDescriptorStore inner = new();
        public readonly TaskCompletionSource Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public readonly ManualResetEventSlim Release = new(false);
        public bool Block;
        public int Sets;
        public SecurityDescriptor? TryGet(string key) => inner.TryGet(key);
        public void Set(string key, SecurityDescriptor sd) { Interlocked.Increment(ref Sets); if (Block) { Entered.TrySetResult(); if (!Release.Wait(Check.Timeout)) throw new TimeoutException("SET barrier"); } inner.Set(key, sd); }
        public void Remove(string key) => inner.Remove(key);
    }
    static async Task Injected()
    {
        using var root = new P7cTests.Root(); File.WriteAllBytes(Path.Combine(root.Path, "file"), Payload);
        var descriptors = new DescriptorStore(); descriptors.Set(Path.Combine(root.Path, "file"), SecurityDescriptor.Parse(DenyRead()));
        await using var d = new P2Tests.Direct(new LocalFileStore(root.Path, false, descriptors));
        var admin = await Open(d, access: Full & ~1u); Status(await d.Send(Create(access: 1)), Denied, "legacy injected pathname descriptor honored");
        await Apply(d, admin); Status(await d.Send(Rename(admin, "renamed")), 0, "rename injected descriptor");
        Status(await d.Send(Create("renamed", 1)), Denied, "injected store follows identity");
        Check.That(descriptors.Sets > 1, "injected store still receives writes");
        await Close(d, await Open(d, disposition: 2));
    }
    static async Task SetRename()
    {
        using var root = new P7cTests.Root(); var descriptors = new DescriptorStore();
        await using var d = new P2Tests.Direct(new LocalFileStore(root.Path, false, descriptors)); var admin = await Open(d, disposition: 2);
        descriptors.Block = true; var set = Task.Run(() => d.Send(Set(admin, DenyRead())));
        await descriptors.Entered.Task.WaitAsync(Check.Timeout);
        var rename = Task.Run(() => d.Send(Rename(admin, "renamed")));
        try { descriptors.Release.Set(); Status(await set, 0, "SET completes"); Status(await rename, 0, "overlapping rename completes"); }
        finally { descriptors.Release.Set(); }
        Status(await d.Send(Create("renamed", 1)), Denied, "overlapping SET and rename retain enforcement");
    }
    static async Task InjectedReplacement()
    {
        using var root = new P7cTests.Root(); File.WriteAllBytes(Path.Combine(root.Path, "destination"), [7]);
        var descriptors = new DescriptorStore(); descriptors.Set(Path.Combine(root.Path, "destination"), SecurityDescriptor.Parse(DenyRead()));
        await using var d = new P2Tests.Direct(new LocalFileStore(root.Path, false, descriptors)); var admin = await Open(d, disposition: 2);
        Status(await d.Send(RawSmb.Write(admin, Payload, 0, 0, 1, 42)), 0, "seed source bytes");
        Status(await d.Send(Rename(admin, "destination", true)), 0, "replace legacy path's prior object");
        var peer = await Open(d, "destination"); await Data(d, peer);
    }
    static async Task InheritOnly(bool directory, bool deny)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var admin = await Open(d, disposition: 2, directory: directory);
        await Apply(d, admin, deny ? Dacl(Ace(1, true, 8), Ace(Full)) : Dacl(Ace(1, flags: 8)));
        Status(await d.Send(Create(access: 1, directory: directory)), deny ? 0u : Denied, "INHERIT_ONLY ACE has no direct allow/deny effect");
    }
    static async Task Generic(uint mask)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var admin = await Open(d, disposition: 2);
        var specific = mask switch { 0x80000000 => 0x120089u, 0x40000000 => 0x120116u, 0x20000000 => 0x1200a0u, _ => Full };
        await Apply(d, admin, Dacl(Ace(mask))); var sd = Output(await d.Send(Query(admin)));
        Check.Equal(specific, RawSmb.U32(sd, (int)RawSmb.U32(sd, 16) + 12), "attached generic mask mapped before evaluation");
        foreach (var bit in new uint[] { 1, 2, 32 }) Status(await d.Send(Create(access: bit)), (specific & bit) != 0 ? 0u : Denied, "specific rights match generic ACE");
        await Apply(d, admin, Dacl(Ace(mask, true), Ace(Full)));
        foreach (var bit in new uint[] { 1, 2, 32 }) Status(await d.Send(Create(access: bit)), (specific & bit) != 0 ? Denied : 0u, "generic deny maps before ordered evaluation");
    }
    static async Task Owner()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        d.Session.Identity = new SecurityIdentity { DomainName = "UPSTREAM", UserName = "owner", UserSid = "S-1-5-21-1-2-3-1000" };
        var admin = await Open(d, disposition: 2); var sd = Dacl(); var owner = Sid(5, 21, 1, 2, 3, 1000); var at = sd.Length; Array.Resize(ref sd, at + owner.Length); RawSmb.Put32(sd, 4, (uint)at); owner.CopyTo(sd, at);
        Status(await d.Send(Set(admin, sd, 5)), 0, "set owner and empty ACL");
        Status(await d.Send(Create(access: 0x60000)), 0, "owner has implicit READ_CONTROL and WRITE_DAC"); Status(await d.Send(Create(access: 1)), Denied, "owner has no implicit data access");
        await Apply(d, admin, Dacl(Ace(1, sid: Sid(3, 4))));
        Status(await d.Send(Create(access: 1)), 0, "OWNER RIGHTS matches actual owner"); Status(await d.Send(Create(access: 0x20000)), Denied, "OWNER RIGHTS suppresses implicit control grant");
        d.Session.Identity = new SecurityIdentity { DomainName = "UPSTREAM", UserName = "other", UserSid = "S-1-5-21-1-2-3-1001" };
        Status(await d.Send(Create(access: 1)), Denied, "OWNER RIGHTS does not match nonowner");
    }
    static async Task Maximum()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var admin = await Open(d, disposition: 2); await Apply(d, admin, Dacl(Ace(1)));
        Status(await d.Send(Create(access: 0x02000001)), 0, "maximum plus allowed explicit bit");
        Status(await d.Send(Create(access: 0x02000002)), Denied, "maximum does not waive denied explicit bit");
    }
    static async Task NullDacl()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var admin = await Open(d, disposition: 2);
        var sd = new byte[20]; sd[0] = 1; RawSmb.Put16(sd, 2, 0x8004); await Apply(d, admin, sd);
        var q = Output(await d.Send(Query(admin))); Check.Equal((ushort)4, (ushort)(RawSmb.U16(q, 2) & 4), "NULL DACL remains present on query"); Check.Equal(0u, RawSmb.U32(q, 16), "NULL DACL offset");
    }
    static async Task Unsupported(byte type)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var admin = await Open(d, disposition: 2);
        var deny = type == 6 ? new byte[24] : Ace(1, true); deny[0] = type;
        if (type == 6) { RawSmb.Put16(deny, 2, 24); RawSmb.Put32(deny, 4, 1); Sid(1, 0).CopyTo(deny, 12); }
        var sd = Dacl(deny, Ace(Full)); sd[20] = 4; // Rich ACE envelope; no file-object enforcement support is claimed.
        Status(await d.Send(Set(admin, sd)), 0xc00000bb, "unsupported object/callback deny cannot be accepted and ignored");
        Status(await d.Send(Create(access: 1)), 0, "rejected ACL leaves prior policy");
    }
    static async Task CreatorInheritance()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var admin = await Open(d, disposition: 2, directory: true);
        Status(await d.Send(Set(admin, Dacl(Ace(Full, flags: 3, sid: Sid(3, 0))))), 0xc00000bb, "creator substitution inheritance requires explicit support");
    }

    // Backend barriers only force public SET_SECURITY requests to interleave.
    // Assertions inspect QUERY_INFO and fresh CREATE responses, never backend state.
    sealed class SecurityBarrierStore(LocalFileStore inner) : IFileStore, IFileIdentityStore, IAuthorizedCreateStore
    {
        public ValueTask<FileStoreResult<FileCreateResult>> CreateAuthorizedAsync(string p, string s, FileAccessIntent a, CreateDispositionIntent d, bool dir, bool non, uint attrs, Func<SecurityDescriptor, bool> existing, Func<SecurityDescriptor, bool, bool> parent, Func<FileIdentity?, bool> validateIdentity, CancellationToken ct = default) => inner.CreateAuthorizedAsync(p, s, a, d, dir, non, attrs, existing, parent, validateIdentity, ct);
        public readonly AsyncBarrier Snapshot = new();
        public bool Arm;
        public ValueTask<FileIdentity?> ResolveIdentityAsync(string p, string s = "", CancellationToken ct = default) => inner.ResolveIdentityAsync(p, s, ct);
        public ValueTask<FileStoreResult<FileCreateResult>> CreateAsync(string p, FileAccessIntent a, CreateDispositionIntent d, bool dir, bool non, CancellationToken ct = default) => inner.CreateAsync(p, a, d, dir, non, ct);
        public ValueTask<FileStoreResult<int>> ReadAsync(IFileHandle h, long o, Memory<byte> b, CancellationToken ct = default) => inner.ReadAsync(h, o, b, ct);
        public ValueTask<FileStoreResult<int>> WriteAsync(IFileHandle h, long o, ReadOnlyMemory<byte> b, CancellationToken ct = default) => inner.WriteAsync(h, o, b, ct);
        public ValueTask<FileStoreResult<IReadOnlyList<FileEntryInfo>>> QueryDirectoryAsync(IFileHandle h, string p, CancellationToken ct = default) => inner.QueryDirectoryAsync(h, p, ct);
        public ValueTask<NtStatus> SetEndOfFileAsync(IFileHandle h, long n, CancellationToken ct = default) => inner.SetEndOfFileAsync(h, n, ct);
        public ValueTask<NtStatus> RenameAsync(IFileHandle h, string p, bool r, CancellationToken ct = default) => inner.RenameAsync(h, p, r, ct);
        public ValueTask<NtStatus> SetDeleteOnCloseAsync(IFileHandle h, bool b, CancellationToken ct = default) => inner.SetDeleteOnCloseAsync(h, b, ct);
        public ValueTask<NtStatus> FlushAsync(IFileHandle h, CancellationToken ct = default) => inner.FlushAsync(h, ct);
        public async ValueTask<FileStoreResult<SecurityDescriptor>> GetSecurityAsync(IFileHandle h, CancellationToken ct = default)
        {
            var result = await inner.GetSecurityAsync(h, ct);
            if (Arm) { Arm = false; await Snapshot.WaitAsync(ct); }
            return result;
        }
        public ValueTask<NtStatus> SetSecurityAsync(IFileHandle h, SecurityDescriptor sd, CancellationToken ct = default) => inner.SetSecurityAsync(h, sd, ct);
    }
    static async Task PartialSet()
    {
        using var root = new P7cTests.Root(); var store = new SecurityBarrierStore(root.Store()); await using var d = new P2Tests.Direct(store);
        var a = await Open(d, disposition: 2); var b = await Open(d); var owner = Sid(5, 21, 1, 2, 3, 1000);
        var sd = new byte[20 + owner.Length]; sd[0] = 1; RawSmb.Put16(sd, 2, 0x8000); RawSmb.Put32(sd, 4, 20); owner.CopyTo(sd, 20);
        store.Arm = true; var first = d.Send(Set(a, sd, 1)); await store.Snapshot.Entered.WaitAsync(Check.Timeout);
        Task<byte[]> second;
        try { second = d.Send(Set(b, DenyRead())); }
        finally { store.Snapshot.Release(); }
        Status(await first, 0, "owner update"); Status(await second, 0, "concurrent DACL update");
        var q = Output(await d.Send(Query(a, 5))); Check.That(q.AsSpan((int)RawSmb.U32(q, 4), owner.Length).SequenceEqual(owner), "partial writes preserve new owner");
        Status(await d.Send(Create(access: 1)), Denied, "partial owner update cannot restore stale allowing DACL");
    }
    static async Task DeniedOverwrite()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var admin = await Open(d, disposition: 2);
        Status(await d.Send(RawSmb.Write(admin, Payload, 0, 0, 1, 42)), 0, "seed original bytes");
        await Apply(d, admin, Dacl(Ace(2, true), Ace(Full)));
        Status(await d.Send(Create(access: 2, disposition: 4)), Denied, "overwrite requires WRITE_DATA"); await Data(d, admin);
    }
    static async Task ParentAccess()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var parent = await Open(d, "parent", disposition: 2, directory: true);
        await Apply(d, parent, Dacl(Ace(2, true), Ace(Full)));
        Status(await d.Send(Create("parent\\child", 2, 2)), Denied, "new file requires parent's FILE_ADD_FILE");
    }
}
