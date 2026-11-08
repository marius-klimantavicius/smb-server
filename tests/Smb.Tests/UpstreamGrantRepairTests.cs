using Smb.FileSystem.Local;
using Smb.Testing;

// Literal public-wire oracles for the supported local grant and basic inheritance profile.
internal static class UpstreamGrantRepairTests
{
    const uint Full = 0x1f01ff, Maximum = 0x02000000, Denied = 0xc0000022;
    static readonly byte[] Bytes = [17, 43, 79, 113];
    public static IEnumerable<(string Name, Func<Task> Run)> Cases()
    {
        foreach (var dir in new[] { false, true })
            foreach (var disposition in new uint[] { 1, 3 })
                yield return ($"upstream.grantwire.dos-readonly.{dir}.{disposition}", () => DosReadonly(dir, disposition));
        foreach (var dir in new[] { false, true })
            yield return ($"upstream.grantwire.backend-readonly.{dir}", () => BackendReadonly(dir));
        yield return ("upstream.grantwire.descriptor-final-host-access", DescriptorGrant);
        yield return ("upstream.grantwire.share-upper-bound", ShareGrant);
        foreach (var partition in Enumerable.Range(0, 16))
            yield return ($"upstream.grantwire.inheritance-control.{partition:x2}", () => Controls(partition));
    }
    static void Status(byte[] b, uint expected, string why) => Check.Equal(expected, RawSmb.U32(b, 8), why);
    static byte[] Create(string path = "file", uint access = Full, uint disposition = 1, bool dir = false)
    { var b = RawSmb.Create(path, dir, 0, 1, 42); RawSmb.Put32(b, 88, access); RawSmb.Put32(b, 100, disposition); return b; }
    static async Task<(ulong P, ulong V)> Open(P2Tests.Direct d, string path = "file", uint access = Full, uint disposition = 1, bool dir = false)
    { var b = await d.Send(Create(path, access, disposition, dir)); Status(b, 0, "public CREATE " + path); return (RawSmb.U64(b, 128), RawSmb.U64(b, 136)); }
    static async Task Close(P2Tests.Direct d, (ulong P, ulong V) id) => Status(await d.Send(RawSmb.Close(id, 0, 1, 42)), 0, "CLOSE");
    static byte[] Output(byte[] b)
    { Status(b, 0, "QUERY_INFO"); return b.AsSpan(RawSmb.U16(b, 66), (int)RawSmb.U32(b, 68)).ToArray(); }
    static async Task<uint> Grant(P2Tests.Direct d, (ulong P, ulong V) id)
        => RawSmb.U32(Output(await d.Send(P5Tests.QueryPacket(id, 1, 18, 4096))), 76);
    static async Task Basic(P2Tests.Direct d, (ulong P, ulong V) id, uint attributes)
    { var b = new byte[40]; RawSmb.Put32(b, 32, attributes); Status(await d.Send(P5Tests.SetPacket(id, 4, b)), 0, "SET basic attributes"); }
    static async Task Read(P2Tests.Direct d, (ulong P, ulong V) id)
    { var b = await d.Send(RawSmb.Read(id, (uint)Bytes.Length, 0, 0, 1, 42)); Status(b, 0, "READ with effective grant"); Check.That(b.AsSpan(b[66], (int)RawSmb.U32(b, 68)).SequenceEqual(Bytes), "wire bytes preserved"); }
    static async Task Write(P2Tests.Direct d, (ulong P, ulong V) id)
        => Status(await d.Send(RawSmb.Write(id, Bytes, 0, 0, 1, 42)), 0, "WRITE bytes");
    static byte[] Dacl(uint mask, byte flags = 0, ushort control = 0x8004)
    {
        var b = new byte[48]; b[0] = 1; RawSmb.Put16(b, 2, control); RawSmb.Put32(b, 16, 20);
        b[20] = 2; RawSmb.Put16(b, 22, 28); RawSmb.Put16(b, 24, 1);
        b[29] = flags; RawSmb.Put16(b, 30, 20); RawSmb.Put32(b, 32, mask);
        b[36] = 1; b[37] = 1; b[43] = 1; // Everyone S-1-1-0
        return b;
    }
    static byte[] SecuritySet((ulong P, ulong V) id, byte[] sd, uint fields = 4)
    { var b = P5Tests.SetPacket(id, 0, sd); b[66] = 3; RawSmb.Put32(b, 76, fields); return b; }
    static async Task<byte[]> SecurityQuery(P2Tests.Direct d, (ulong P, ulong V) id, uint fields = 4)
    { var b = P5Tests.QueryPacket(id, 3, 0, 4096); RawSmb.Put32(b, 80, fields); return Output(await d.Send(b)); }
    static async Task DosReadonly(bool dir, uint disposition)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        var admin = await Open(d, disposition: 2, dir: dir); if (!dir) await Write(d, admin);
        else await Close(d, await Open(d, "file\\child", disposition: 2));
        await Basic(d, admin, 1);
        try
        {
            foreach (var access in new uint[] { Maximum, Maximum | 1 })
            {
                var id = await Open(d, access: access, disposition: disposition, dir: dir);
                Check.Equal(dir ? Full : 0x1f01b9u, await Grant(d, id), "FILE_ALL_INFORMATION exposes filtered specific grant");
                if (!dir)
                {
                    await Read(d, id);
                    Status(await d.Send(RawSmb.Write(id, [99], 0, 0, 1, 42)), Denied, "filtered MAXIMUM_ALLOWED handle cannot write");
                    await Read(d, admin);
                }
                await Close(d, id);
            }
            foreach (var access in new uint[] { 2, 4, Maximum | 2, Maximum | 4 })
            {
                var b = await d.Send(Create(access: access, disposition: disposition, dir: dir));
                Status(b, dir ? 0u : Denied, "explicit data bit cannot be waived by MAXIMUM_ALLOWED");
                if (dir) await Close(d, (RawSmb.U64(b, 128), RawSmb.U64(b, 136)));
            }
            if (!dir)
            {
                var destructive = Create(access: Maximum, disposition: 4);
                Status(await d.Send(destructive), Denied, "readonly overwrite remains denied"); await Read(d, admin);
                var b = Output(await d.Send(P5Tests.QueryPacket(admin, 1, 4, 40)));
                Check.Equal(1u, RawSmb.U32(b, 32) & 1u, "failed opens preserve READONLY");
            }
            var retained = await Open(d, access: Maximum, dir: dir);
            await Basic(d, admin, 0x80);
            Check.Equal(dir ? Full : 0x1f01b9u, await Grant(d, retained), "existing handle grant stays fixed after attribute clear");
            if (!dir) Status(await d.Send(RawSmb.Write(retained, [99], 0, 0, 1, 42)), Denied, "attribute clear does not enlarge old handle grant");
            await Close(d, retained);
            var fresh = await Open(d, access: Maximum, dir: dir); Check.Equal(Full, await Grant(d, fresh), "attribute clear restores future maximal grant");
            if (!dir) { await Write(d, fresh); await Read(d, fresh); }
            await Close(d, fresh);
        }
        finally { await Basic(d, admin, 0x80); }
        await Close(d, admin);
    }
    static async Task BackendReadonly(bool dir)
    {
        using var root = new P7cTests.Root(); await using var seed = new P2Tests.Direct(root.Store());
        var admin = await Open(seed, disposition: 2, dir: dir); if (!dir) await Write(seed, admin); await Close(seed, admin);
        await using var d = new P2Tests.Direct(new LocalFileStore(root.Path, true));
        foreach (var disposition in new uint[] { 1, 3 })
        {
            var id = await Open(d, access: Maximum, disposition: disposition, dir: dir);
            Check.Equal(0x1200a9u, await Grant(d, id), "readonly backend caps all mutation rights independently of DOS attributes");
            if (!dir) { await Read(d, id); Status(await d.Send(RawSmb.Write(id, [99], 0, 0, 1, 42)), Denied, "backend readonly denies write"); }
            await Close(d, id);
        }
        foreach (var access in new uint[] { Maximum | 2, Maximum | 0x100, Maximum | 0x40000 })
            Status(await d.Send(Create(access: access, dir: dir)), Denied, "readonly backend cannot waive explicit mutation rights");
        Status(await d.Send(Create("missing", 1, 3, dir)), Denied, "readonly OPEN_IF cannot create");
        Status(await seed.Send(Create("missing", 1, dir: dir)), 0xc0000034, "no orphan from readonly OPEN_IF");
    }
    static async Task DescriptorGrant()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var admin = await Open(d, disposition: 2); await Write(d, admin);
        Status(await d.Send(SecuritySet(admin, Dacl(0x120089))), 0, "attach read descriptor");
        await Basic(d, admin, 1);
        try
        {
            var id = await Open(d, access: Maximum); Check.Equal(0x120089u, await Grant(d, id), "final host open uses descriptor grant"); await Read(d, id); await Close(d, id);
            Status(await d.Send(Create(access: Maximum | 2)), Denied, "descriptor explicit denial retained");
            await Basic(d, admin, 0x80);
            id = await Open(d, access: Maximum); Check.Equal(0x120089u, await Grant(d, id), "attribute clear cannot enlarge descriptor grant"); await Read(d, id); await Close(d, id);
        }
        finally { await Basic(d, admin, 0x80); }
    }
    static async Task ShareGrant()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var admin = await Open(d, disposition: 2); await Write(d, admin);
        // Fixture sets the share prerequisite; all decisions/grants are observed over signed SMB.
        d.Tree.MaximalAccess = 0x120089;
        var id = await Open(d, access: Maximum); Check.Equal(0x120089u, await Grant(d, id), "descriptor cannot enlarge share maximal access"); await Read(d, id); await Close(d, id);
        Status(await d.Send(Create(access: Maximum | 2)), Denied, "explicit right outside share remains denied");
    }
    static async Task Controls(int partition)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var parent = await Open(d, "parent", disposition: 2, dir: true);
        var control = (ushort)(0x8004 | ((partition & 1) != 0 ? 0x400 : 0) | ((partition & 2) != 0 ? 0x100 : 0) | ((partition & 4) != 0 ? 0x1000 : 0));
        var normalized = (ushort)(0x8004 | ((partition & 3) == 3 ? 0x400 : 0) | (control & 0x1000));
        var marker = (byte)((partition & 8) != 0 ? 16 : 0);
        Status(await d.Send(SecuritySet(parent, Dacl(Full, (byte)(3 | marker), control))), 0, "SET basic parent control partition");
        var sd = await SecurityQuery(d, parent); Check.Equal(normalized, RawSmb.U16(sd, 2), "DACL controls normalize and remain queryable");
        Check.Equal((byte)(3 | marker), sd[(int)RawSmb.U32(sd, 16) + 9], "explicit parent ACE marker retained");
        // An unrelated group-only SET must preserve DACL controls.
        var group = new byte[32]; group[0] = 1; RawSmb.Put16(group, 2, 0x8000); RawSmb.Put32(group, 8, 20);
        group[20] = 1; group[21] = 1; group[27] = 1; // Everyone S-1-1-0
        Status(await d.Send(SecuritySet(parent, group, 2)), 0, "group-only SET");
        sd = await SecurityQuery(d, parent); Check.Equal(normalized, RawSmb.U16(sd, 2), "unrequested DACL control preserved");
        sd = await SecurityQuery(d, parent, 0); Check.Equal((ushort)0x8000, RawSmb.U16(sd, 2), "zero-field query isolates DACL control");
        var child = await Open(d, "parent\\child", disposition: 2);
        sd = await SecurityQuery(d, child); Check.Equal((ushort)(0x8004 | (normalized & 0x400)), RawSmb.U16(sd, 2), "new child inherits auto-inherited state, not parent protection");
        Check.Equal((byte)16, sd[(int)RawSmb.U32(sd, 16) + 9], "basic profile records inherited ACE origin independently of parent control");
        Status(await d.Send(SecuritySet(child, Dacl(Full, marker, control))), 0, "explicit child control replacement");
        sd = await SecurityQuery(d, child); Check.Equal(normalized, RawSmb.U16(sd, 2), "explicit child control normalization"); Check.Equal(marker, sd[(int)RawSmb.U32(sd, 16) + 9], "explicit child marker retained");
        Status(await d.Send(SecuritySet(child, Dacl(Full))), 0, "clear child protection"); sd = await SecurityQuery(d, child); Check.Equal((ushort)0x8004, RawSmb.U16(sd, 2), "unprotected replacement clears controls");
        await Close(d, child); await Close(d, parent);
    }
}
