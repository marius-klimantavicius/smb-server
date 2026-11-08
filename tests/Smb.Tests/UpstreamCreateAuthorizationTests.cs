using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Protocol.Enums;
using Smb.Protocol.Security;
using Smb.Testing;

// MS-FSA 2.1.5.1.1: authorize the parent before publishing a new file;
// 2.1.5.1.2.1/2.1.5.1.2: authorize an existing object before overwrite.
// Expected rights and statuses below are literal protocol values, not server helpers.
internal static class UpstreamCreateAuthorizationTests
{
    const uint Full = 0x1f01ff, Denied = 0xc0000022;
    static readonly byte[] Bytes = [11, 29, 47, 83, 101];
    public static IEnumerable<(string Name, Func<Task> Run)> Cases()
    {
        foreach (var disposition in new uint[] { 0, 4, 5 })
            foreach (var maximum in new[] { false, true })
                foreach (var stream in new[] { false, true })
                    yield return ($"upstream.createauth.overwrite.{disposition}.{maximum}.{stream}", () => Overwrite(disposition, maximum, stream));
        foreach (var directory in new[] { false, true })
            foreach (var disposition in directory ? new uint[] { 2, 3 } : new uint[] { 0, 2, 3, 5 })
                yield return ($"upstream.createauth.parent.{directory}.{disposition}", () => Parent(directory, disposition));
        yield return ("upstream.createauth.open-if-existing-and-stream", Existing);
        yield return ("upstream.createauth.stream-missing-base-parent", MissingBase);
        yield return ("upstream.createauth.hardlink-denial", Alias);
        yield return ("upstream.createauth.inherited-deny-new-grant", NewGrant);
        yield return ("upstream.createauth.backend-errors", Errors);
        foreach (var parent in new[] { false, true })
            yield return ($"upstream.createauth.policy-after-wait.{parent}", () => PolicyWait(parent));
        yield return ("upstream.createauth.cancel-before-acquisition", Cancel);
        yield return ("upstream.createauth.identity-after-wait", IdentityWait);
        yield return ("upstream.createauth.legacy-descriptor-contract", Legacy);
        foreach (var disposition in new uint[] { 0, 4, 5 })
        {
            yield return ($"upstream.createauth.maximum-implicit.{disposition}", () => Implicit(disposition));
            yield return ($"upstream.createauth.implicit-allowed.{disposition}", () => ImplicitAllowed(disposition));
        }
    }
    static void Status(byte[] b, uint s, string why) => Check.Equal(s, RawSmb.U32(b, 8), why);
    static byte[] Create(string path, uint access = Full, uint disposition = 1, bool dir = false)
    { var b = RawSmb.Create(path, dir, 0, 1, 42); RawSmb.Put32(b, 88, access); RawSmb.Put32(b, 100, disposition); return b; }
    static async Task<(ulong P, ulong V)> Open(P2Tests.Direct d, string path, uint access = Full, uint disposition = 1, bool dir = false)
    { var b = await d.Send(Create(path, access, disposition, dir)); Status(b, 0, "CREATE " + path); return (RawSmb.U64(b, 128), RawSmb.U64(b, 136)); }
    static async Task Close(P2Tests.Direct d, (ulong P, ulong V) id) => Status(await d.Send(RawSmb.Close(id, 0, 1, 42)), 0, "CLOSE");
    static byte[] Dacl(uint denied, byte flags = 0)
    {
        var b = new byte[68]; b[0] = 1; RawSmb.Put16(b, 2, 0x8004); RawSmb.Put32(b, 16, 20);
        b[20] = 2; RawSmb.Put16(b, 22, 48); RawSmb.Put16(b, 24, 2);
        for (var i = 0; i < 2; i++)
        { var at = 28 + 20 * i; b[at] = i == 0 ? (byte)1 : (byte)0; b[at + 1] = i == 0 ? flags : (byte)0;
          RawSmb.Put16(b, at + 2, 20); RawSmb.Put32(b, at + 4, i == 0 ? denied : Full);
          b[at + 8] = 1; b[at + 9] = 1; b[at + 15] = 1; } // S-1-1-0, Everyone
        return b;
    }
    static async Task Set(P2Tests.Direct d, (ulong P, ulong V) id, uint deny, byte flags = 0)
    { var b = P5Tests.SetPacket(id, 0, Dacl(deny, flags)); b[66] = 3; RawSmb.Put32(b, 76, 4); Status(await d.Send(b), 0, "signed SET_SECURITY"); }
    static async Task Write(P2Tests.Direct d, (ulong P, ulong V) id) => Status(await d.Send(RawSmb.Write(id, Bytes, 0, 0, 1, 42)), 0, "old granted WRITE");
    static async Task Read(P2Tests.Direct d, (ulong P, ulong V) id)
    { var b = await d.Send(RawSmb.Read(id, 32, 0, 0, 1, 42)); Status(b, 0, "old granted READ"); Check.That(b.AsSpan(b[66], (int)RawSmb.U32(b, 68)).SequenceEqual(Bytes), "exact original bytes"); }
    static async Task<byte[]> Basic(P2Tests.Direct d, (ulong P, ulong V) id)
    { var b = await d.Send(P5Tests.QueryPacket(id, 1, 4, 40)); Status(b, 0, "QUERY basic attributes"); return b.AsSpan(RawSmb.U16(b, 66), (int)RawSmb.U32(b, 68)).ToArray(); }
    static async Task Overwrite(uint disposition, bool maximum, bool stream)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        var admin = await Open(d, "file", disposition: 2); await Write(d, admin);
        var ads = await Open(d, "file:side", disposition: 2); await Write(d, ads);
        var basic = await Basic(d, admin);
        var denied = disposition == 0 ? 0x10000u : 2u;
        await Set(d, admin, denied);
        var before = d.Session.Opens.Count;
        var request = Create(stream ? "file:side" : "file", denied | (maximum ? 0x02000000u : 0), disposition);
        RawSmb.Put32(request, 92, 0x100); // TEMPORARY must not replace existing attributes on denial.
        RawSmb.Put32(request, 104, 0x1040); // Rejected DELETE_ON_CLOSE must not arm deletion.
        Status(await d.Send(request), Denied, "descriptor denial precedes destructive acquisition");
        Check.Equal(before, d.Session.Opens.Count, "denied CREATE publishes no open");
        await Read(d, admin); await Read(d, ads);
        var after = await Basic(d, admin);
        Check.Equal(RawSmb.U32(basic, 32), RawSmb.U32(after, 32), "DOS attributes preserved");
        await Write(d, admin); // Existing grants are not retroactively revoked.
        await Set(d, admin, 0);
        var retry = await Open(d, stream ? "file:side" : "file", disposition: disposition);
        await Close(d, retry); await Close(d, ads); await Close(d, admin);
        await Close(d, await Open(d, "file", access: 1)); // No armed delete or leaked sharing reservation.
    }
    static async Task Parent(bool directory, uint disposition)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        var parent = await Open(d, "parent", disposition: 2, dir: true);
        var required = directory ? 4u : 2u;
        await Set(d, parent, required); // Noninheritable: child's ACL cannot be the oracle.
        var before = d.Session.Opens.Count;
        Status(await d.Send(Create("parent\\denied", 1, disposition, directory)), Denied, "parent requires exact add right");
        Check.Equal(before, d.Session.Opens.Count, "denial publishes no handle");
        Status(await d.Send(Create("parent\\denied", 1, 1, directory)), 0xc0000034, "no orphan after denial");
        var other = await Open(d, "parent\\other", disposition: 2, dir: !directory);
        await Close(d, other); // ADD_FILE and ADD_SUBDIRECTORY are distinct.
        await Set(d, parent, 0);
        var retry = await Open(d, "parent\\denied", 1, disposition, directory); await Close(d, retry);
        var sameParent = await Open(d, "parent\\control", disposition: 2, dir: directory); await Close(d, sameParent);
    }
    static async Task Existing()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        var p = await Open(d, "p", disposition: 2, dir: true); var f = await Open(d, "p\\file", disposition: 2); await Write(d, f);
        await Set(d, p, 6); // Neither parent right is needed to open existing file or add stream to it.
        var existing = await Open(d, "p\\file", 1, 3); await Read(d, existing); await Close(d, existing);
        var stream = await Open(d, "p\\file:side", disposition: 2); await Write(d, stream); await Close(d, stream);
        await Set(d, f, 2);
        Status(await d.Send(Create("p\\file:new", 2, 2)), Denied, "new stream checks existing base policy");
        await Set(d, f, 0); Status(await d.Send(Create("p\\file:new", 1)), 0xc0000034, "denied stream was not published");
        Status(await d.Send(Create("p\\missing", 1, 3)), Denied, "OPEN_IF missing still needs parent add");
    }
    static async Task MissingBase()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        var p = await Open(d, "p", disposition: 2, dir: true); await Set(d, p, 2);
        Status(await d.Send(Create("p\\file:side", 2, 3)), Denied, "named stream creating base requires parent ADD_FILE");
        Status(await d.Send(Create("p\\file", 1)), 0xc0000034, "no orphan base on denied stream create");
        await Set(d, p, 0); await Close(d, await Open(d, "p\\file:side", disposition: 3));
    }
    static async Task Alias()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        var f = await Open(d, "file", disposition: 2); await Write(d, f);
        NativeHost.HardLink(Path.Combine(root.Path, "file"), Path.Combine(root.Path, "alias"));
        await Set(d, f, 2); Status(await d.Send(Create("alias", 2, 5)), Denied, "alias cannot bypass preauthorization"); await Read(d, f);
    }
    static async Task NewGrant()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        var p = await Open(d, "p", disposition: 2, dir: true); await Set(d, p, 1, 9); // OI | INHERIT_ONLY
        var child = await Open(d, "p\\child", 3, 2); await Write(d, child); await Read(d, child);
        Status(await d.Send(Create("p\\child", 1)), Denied, "inherited child deny applies to fresh admission");
    }
    static async Task Errors()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        Status(await d.Send(Create("missing\\file", 1, 3)), 0xc000003a, "missing parent status");
        Status(await d.Send(Create("missing\\dir", 1, 3, true)), 0xc000003a, "missing directory parent status");
        await using var ro = new P2Tests.Direct(new LocalFileStore(root.Path, true));
        Status(await ro.Send(Create("new", 1, 3)), Denied, "read-only OPEN_IF cannot create");
        Status(await d.Send(Create("new", 1)), 0xc0000034, "read-only denial leaves no object");
    }

    // These wrappers only control scheduling or model an unextended custom backend.
    // All assertions below inspect public wire results and bytes.
    class LegacyStore(LocalFileStore inner) : IFileStore, IFileIdentityStore
    {
        protected LocalFileStore Inner => inner;
        public ValueTask<FileIdentity?> ResolveIdentityAsync(string p, string s = "", CancellationToken ct = default) => inner.ResolveIdentityAsync(p, s, ct);
        public ValueTask<FileStoreResult<FileCreateResult>> CreateAsync(string p, FileAccessIntent a, CreateDispositionIntent d, bool dir, bool non, CancellationToken ct = default) => inner.CreateAsync(p, a, d, dir, non, ct);
        public ValueTask<FileStoreResult<int>> ReadAsync(IFileHandle h, long o, Memory<byte> b, CancellationToken ct = default) => inner.ReadAsync(h, o, b, ct);
        public ValueTask<FileStoreResult<int>> WriteAsync(IFileHandle h, long o, ReadOnlyMemory<byte> b, CancellationToken ct = default) => inner.WriteAsync(h, o, b, ct);
        public ValueTask<FileStoreResult<IReadOnlyList<FileEntryInfo>>> QueryDirectoryAsync(IFileHandle h, string p, CancellationToken ct = default) => inner.QueryDirectoryAsync(h, p, ct);
        public ValueTask<NtStatus> SetEndOfFileAsync(IFileHandle h, long n, CancellationToken ct = default) => inner.SetEndOfFileAsync(h, n, ct);
        public ValueTask<NtStatus> RenameAsync(IFileHandle h, string p, bool r, CancellationToken ct = default) => inner.RenameAsync(h, p, r, ct);
        public ValueTask<NtStatus> SetDeleteOnCloseAsync(IFileHandle h, bool b, CancellationToken ct = default) => inner.SetDeleteOnCloseAsync(h, b, ct);
        public ValueTask<NtStatus> FlushAsync(IFileHandle h, CancellationToken ct = default) => inner.FlushAsync(h, ct);
        public ValueTask<FileStoreResult<SecurityDescriptor>> GetSecurityAsync(IFileHandle h, CancellationToken ct = default) => inner.GetSecurityAsync(h, ct);
        public ValueTask<NtStatus> SetSecurityAsync(IFileHandle h, SecurityDescriptor sd, CancellationToken ct = default) => inner.SetSecurityAsync(h, sd, ct);
    }
    sealed class WaitingStore(LocalFileStore inner) : LegacyStore(inner), IAuthorizedCreateStore
    {
        public AsyncBarrier? Pause;
        public async ValueTask<FileStoreResult<FileCreateResult>> CreateAuthorizedAsync(string p, string s, FileAccessIntent a, CreateDispositionIntent d, bool dir, bool non, uint attrs, Func<SecurityDescriptor, bool> existing, Func<SecurityDescriptor, bool, bool> parent, Func<FileIdentity?, bool> validateIdentity, CancellationToken ct = default)
        {
            if (Pause is { } gate) { Pause = null; await gate.WaitAsync(CancellationToken.None); }
            return await Inner.CreateAuthorizedAsync(p, s, a, d, dir, non, attrs, existing, parent, validateIdentity, ct);
        }
    }
    static async Task PolicyWait(bool parent)
    {
        using var root = new P7cTests.Root(); var store = new WaitingStore(root.Store()); await using var d = new P2Tests.Direct(store);
        var id = await Open(d, "object", disposition: 2, dir: parent); if (!parent) await Write(d, id);
        var gate = new AsyncBarrier(); store.Pause = gate;
        var pending = d.Send(Create(parent ? "object\\child" : "object", 2, parent ? 2u : 4u));
        await gate.Entered.WaitAsync(Check.Timeout);
        try { await Set(d, id, 2); } finally { gate.Release(); }
        Status(await pending, Denied, "policy is read after asynchronous acquisition wait");
        if (parent) Status(await d.Send(Create("object\\child", 1)), 0xc0000034, "waited denial leaves no child");
        else await Read(d, id);
    }
    static async Task Cancel()
    {
        using var root = new P7cTests.Root(); var store = new WaitingStore(root.Store()); await using var d = new P2Tests.Direct(store);
        d.Options.FeaturePolicy = P6Tests.Caching();
        var id = await Open(d, "file", disposition: 2); await Write(d, id);
        var gate = new AsyncBarrier(); store.Pause = gate; var pending = d.Send(Create("file", 2, 4));
        await gate.Entered.WaitAsync(Check.Timeout);
        // Use the existing public CANCEL path, targeting the actual wire MessageId.
        var entry = d.Connection.OrdinaryRequests.Single(); var physical = entry.Value;
        var cancel = RawSmb.Header(12, 4, entry.Key, 1, 42); RawSmb.Put16(cancel, 64, 4);
        RawSmb.Sign(cancel, d.Session.SigningKey);
        try { await d.Dispatcher.ProcessMessageAsync(d.Connection, cancel); } finally { gate.Release(); }
        Status(await pending, 0xc0000120, "cancelled destructive CREATE");
        await physical.PhysicalFinished.WaitAsync(Check.Timeout); await Read(d, id);
        await Close(d, await Open(d, "file", 1));
    }
    static async Task IdentityWait()
    {
        using var root = new P7cTests.Root(); var store = new WaitingStore(root.Store()); await using var d = new P2Tests.Direct(store);
        var original = await Open(d, "file", disposition: 2); await Write(d, original);
        var gate = new AsyncBarrier(); store.Pause = gate; var pending = d.Send(Create("file", 2, 4));
        await gate.Entered.WaitAsync(Check.Timeout);
        (ulong P, ulong V) reader = default;
        try
        {
            var name = System.Text.Encoding.Unicode.GetBytes("moved"); var data = new byte[20 + name.Length];
            RawSmb.Put32(data, 16, (uint)name.Length); name.CopyTo(data, 20);
            Status(await d.Send(P5Tests.SetPacket(original, 10, data)), 0, "rename during guarded acquisition wait");
            var replacement = await Open(d, "file", disposition: 2); await Write(d, replacement); await Close(d, replacement);
            var request = Create("file", 1); RawSmb.Put32(request, 96, 1);
            var response = await d.Send(request); Status(response, 0, "replacement reader denies write sharing");
            reader = (RawSmb.U64(response, 128), RawSmb.U64(response, 136));
        }
        finally { gate.Release(); }
        Status(await pending, 0xc0000043, "replacement is readmitted before destructive acquisition");
        await Read(d, reader); await Read(d, original); await Close(d, reader);
        await Close(d, await Open(d, "file", 2, 4)); // Old reservations did not leak.
        await Read(d, original); // Moved object was not truncated either.
    }
    static async Task Legacy()
    {
        using var root = new P7cTests.Root();
        await using (var setup = new P2Tests.Direct(root.Store())) { var f = await Open(setup, "file", disposition: 2); await Write(setup, f); }
        await using var d = new P2Tests.Direct(new LegacyStore(root.Store()));
        var f2 = await Open(d, "file"); await Set(d, f2, 2);
        Status(await d.Send(Create("file", 2, 4)), Denied, "legacy descriptor denial before truncation"); await Read(d, f2);
        await Set(d, f2, 0);
        Status(await d.Send(Create("file", 2, 4)), 0xc00000bb, "descriptor-aware mutation needs atomic backend contract"); await Read(d, f2);
        await Close(d, await Open(d, "file", 1, 3)); // Nonmutating OPEN_IF remains available.
        var rootId = await Open(d, "", dir: true); await Set(d, rootId, 2);
        Status(await d.Send(Create("new", 1, 2)), Denied, "legacy parent denial before creating");
        await Set(d, rootId, 0);
        Status(await d.Send(Create("new", 1, 2)), 0xc00000bb, "legacy allowed creation requires guarded contract");
        Status(await d.Send(Create("new", 1)), 0xc0000034, "legacy decline leaves no orphan");
    }
    static async Task Implicit(uint disposition)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        var f = await Open(d, "file", disposition: 2); await Write(d, f);
        await Set(d, f, disposition == 0 ? 0x10000u : 2u);
        Status(await d.Send(Create("file", 0x02000000, disposition)), Denied, "maximum grant lacks required disposition right"); await Read(d, f);
    }
    static async Task ImplicitAllowed(uint disposition)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        var f = await Open(d, "file", disposition: 2); await Write(d, f);
        var reopened = await Open(d, "file", 1, disposition);
        Status(await d.Send(RawSmb.Read(reopened, 1, 0, 0, 1, 42)), 0xc0000011, "allowed implicit disposition access truncates");
        Status(await d.Send(RawSmb.Write(reopened, [1], 0, 0, 1, 42)), Denied, "implicit admission right does not add a client WRITE grant");
    }
}
