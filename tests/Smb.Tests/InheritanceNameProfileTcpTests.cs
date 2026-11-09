using System.Text;
using Smb.Server;
using Smb.Testing;

// Independent literal descriptor/name oracles. The existing TCP peer performs
// real NTLM and derives signing keys from BCL HMAC/SHA512, not server state.
// MS-DTYP 2.4.4.1; MS-FSA 2.1.5.17; MS-FSCC 2.1.5.2. These exercise the
// documented basic inheritance/host naming profile, not Windows auto-ACL repair
// or Samba smb3error.c's legacy OS2-name rejection convention.
internal static partial class DurableRecoveryTcpTests
{
    public static IEnumerable<(string Name, Func<Task> Run)> InheritanceNameCases()
    {
        foreach (ushort dialect in new ushort[] { 0x202, 0x300, 0x311 })
        {
            foreach (var parent in Enumerable.Range(0, 16))
                yield return ($"repair.inheritance.tcp.controls.{dialect:x}.{parent:x2}", () => InheritanceProfile(dialect, parent));
            foreach (var flags in Enumerable.Range(0, 16))
                yield return ($"repair.inheritance.tcp.propagation.{dialect:x}.{flags:x2}", () => PropagationProfile(dialect, (byte)flags));
            // The original ordinary os2-name registration runs the SMB300 case.
            if (dialect != 0x300)
                yield return ($"repair.name.tcp.legal-punctuation.{dialect:x}", () => LegalNameProfile(dialect));
        }
    }
    static ushort ProfileControl(int n, bool normalized = false) => (ushort)(0x8004 |
        ((normalized ? (n & 3) == 3 : (n & 1) != 0) ? 0x400 : 0) |
        (!normalized && (n & 2) != 0 ? 0x100 : 0) | ((n & 4) != 0 ? 0x1000 : 0));

    // Everyone SID, ACL revision 2, ordered basic READ deny then full allow.
    // Owner/group are deliberately supplied, not inferred from the implementation.
    static byte[] ProfileDescriptor(ushort control, byte denyFlags, byte allowFlags, bool deny = true)
    {
        var b = new byte[deny ? 92 : 72]; b[0] = 1; RawSmb.Put16(b, 2, control);
        RawSmb.Put32(b, 4, 20); RawSmb.Put32(b, 8, 32); RawSmb.Put32(b, 16, 44);
        byte[] everyone = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        everyone.CopyTo(b, 20); everyone.CopyTo(b, 32); b[44] = 2;
        RawSmb.Put16(b, 46, (ushort)(deny ? 48 : 28)); RawSmb.Put16(b, 48, (ushort)(deny ? 2 : 1));
        for (var i = 0; i < (deny ? 2 : 1); i++)
        {
            var at = 52 + i * 20; var isDeny = deny && i == 0;
            b[at] = isDeny ? (byte)1 : (byte)0; b[at + 1] = isDeny ? denyFlags : allowFlags;
            RawSmb.Put16(b, at + 2, 20); RawSmb.Put32(b, at + 4, isDeny ? 1u : 0x1f01ffu); everyone.CopyTo(b, at + 8);
        }
        return b;
    }
    static byte[] ProfileSecuritySet((ulong P, ulong V) id, byte[] sd, uint fields = 4)
    { var b = Set(id, 0, sd); b[66] = 3; RawSmb.Put32(b, 76, fields); return b; }
    static byte[] ProfileSecurityQuery((ulong P, ulong V) id)
    { var b = Query(id, 0); b[66] = 3; RawSmb.Put32(b, 80, 7); return b; }
    static byte[] ProfileOutput(byte[] b) => RawSmb.Buffer(b, RawSmb.U16(b, 66), RawSmb.U32(b, 68));
    static byte[] ProfileCreate(string path, uint disposition = 1, uint access = 0x1f01de, bool directory = false)
    {
        var b = RawSmb.Create(path, directory, 0, 0, 0); RawSmb.Put32(b, 88, access);
        RawSmb.Put32(b, 100, disposition); return b;
    }
    static async Task ProfileAccess(Peer p, string path, (ulong P, ulong V) writer, byte[] bytes, bool denied)
    {
        var written = await p.Exchange(RawSmb.Write(writer, bytes, 0, 0, 0, 0));
        Check.Equal((uint)bytes.Length, RawSmb.U32(written, 68), "complete allowed write");
        await p.Exchange(RawSmb.Read(writer, (uint)bytes.Length, 0, 0, 0, 0), Denied); // fixed write-only grant
        var opened = await p.Exchange(ProfileCreate(path, access: 1), denied ? Denied : 0);
        if (!denied) { var reader = Id(opened); await Bytes(p, reader, bytes); await p.Exchange(RawSmb.Close(reader, 0, 0, 0)); }
    }
    static async Task ProfileDelete(Peer p, (ulong P, ulong V) id)
    { await p.Exchange(Set(id, 13, [1])); await p.Exchange(RawSmb.Close(id, 0, 0, 0)); }
    static async Task InheritanceProfile(ushort dialect, int parentPartition)
    {
        await using var f = new Fixture(); f.Server.State.Options.FeaturePolicy = SmbFeaturePolicy.Restricted;
        await f.Server.StartAsync(); await using var a = await f.Connect(dialect, Guid.NewGuid()); await using var b = await f.Connect(dialect, Guid.NewGuid());
        var parent = Id(await a.Exchange(ProfileCreate("parent", 2, 0x1f01ff, true)));
        var flags = (byte)(3 | ((parentPartition & 8) != 0 ? 16 : 0));
        await a.Exchange(ProfileSecuritySet(parent, ProfileDescriptor(ProfileControl(parentPartition), flags, flags), 7));
        var expectedParent = ProfileDescriptor(ProfileControl(parentPartition, true), flags, flags);
        Check.That(ProfileOutput(await a.Exchange(ProfileSecurityQuery(parent))).SequenceEqual(expectedParent), "exact normalized parent owner/group/control/ordered ACL");
        var child = Id(await a.Exchange(ProfileCreate("parent\\child", 2)));
        var inherited = ProfileDescriptor((ushort)(0x8004 | ((parentPartition & 3) == 3 ? 0x400 : 0)), 16, 16);
        Check.That(ProfileOutput(await a.Exchange(ProfileSecurityQuery(child))).SequenceEqual(inherited), "complete inherited descriptor independent of auto-control and protection");
        var initialWriter = Id(await b.Exchange(ProfileCreate("parent\\child", access: 2)));
        await ProfileAccess(b, "parent\\child", initialWriter, [41], true);
        await b.Exchange(RawSmb.Close(initialWriter, 0, 0, 0));
        // Each parent executes ALL sixteen formerly unreachable explicit-child
        // partitions. These are inner workflows, not separately counted tests.
        for (var c = 0; c < 16; c++)
        {
            var marker = (byte)((c & 8) != 0 ? 16 : 0);
            await a.Exchange(ProfileSecuritySet(child, ProfileDescriptor(ProfileControl(c), marker, marker)));
            var expected = ProfileDescriptor(ProfileControl(c, true), marker, marker);
            Check.That(ProfileOutput(await a.Exchange(ProfileSecurityQuery(child))).SequenceEqual(expected), "exact explicit child replacement, parent-independent controls and marker");
            var writer = Id(await b.Exchange(ProfileCreate("parent\\child", access: 2)));
            await ProfileAccess(b, "parent\\child", writer, [(byte)c, (byte)parentPartition], true);
            await b.Exchange(ProfileSecuritySet(writer, ProfileDescriptor(0x8004, 0, 0)), Denied);
            Check.That(ProfileOutput(await a.Exchange(ProfileSecurityQuery(child))).SequenceEqual(expected), "denied WRITE_DAC cannot change descriptor");
            await b.Exchange(RawSmb.Close(writer, 0, 0, 0));
        }
        var before = ProfileOutput(await a.Exchange(Query(child, 6)));
        // Rename's implicit destination-parent open excludes DELETE sharing.
        await a.Exchange(RawSmb.Close(parent, 0, 0, 0));
        await a.Exchange(RenameRequest(child, "parent\\renamed"));
        await b.Exchange(ProfileCreate("parent\\child", access: 1), Missing);
        var alias = Id(await b.Exchange(ProfileCreate("parent\\renamed")));
        Check.That(ProfileOutput(await b.Exchange(Query(alias, 6))).SequenceEqual(before), "reopened name retains acquired object identity");
        Check.That(ProfileOutput(await b.Exchange(ProfileSecurityQuery(alias))).SequenceEqual(ProfileDescriptor(ProfileControl(15, true), 16, 16)), "descriptor survives new name and separately authenticated reopen");
        await ProfileAccess(b, "parent\\renamed", alias, [89, 97], true);
        await b.Exchange(RawSmb.Close(alias, 0, 0, 0));
        // A new allow descriptor must permit new READ handles, without enlarging
        // existing write-only grants. Parent changes do not rewrite this child.
        await a.Exchange(ProfileSecuritySet(child, ProfileDescriptor(0x8004, 0, 0, false)));
        await ProfileAccess(a, "parent\\renamed", child, [101, 103], false);
        await ProfileDelete(a, child); await b.Exchange(ProfileCreate("parent\\renamed"), Missing);
        parent = Id(await a.Exchange(ProfileCreate("parent", directory: true)));
        await ProfileDelete(a, parent); await b.Exchange(ProfileCreate("parent", directory: true), Missing);
    }
    static async Task PropagationProfile(ushort dialect, byte flags)
    {
        await using var f = new Fixture(); f.Server.State.Options.FeaturePolicy = SmbFeaturePolicy.Restricted;
        await f.Server.StartAsync(); await using var a = await f.Connect(dialect, Guid.NewGuid());
        var parent = Id(await a.Exchange(ProfileCreate("parent", 2, 0x1f01ff, true)));
        await a.Exchange(ProfileSecuritySet(parent, ProfileDescriptor(0x8004, flags, 3), 7));
        var file = Id(await a.Exchange(ProfileCreate("parent\\file", 2)));
        var dir = Id(await a.Exchange(ProfileCreate("parent\\dir", 2, directory: true)));
        var grand = Id(await a.Exchange(ProfileCreate("parent\\dir\\file", 2)));
        // Literal MS-DTYP ACE_HEADER truth table: OI/CI, NO_PROPAGATE,
        // INHERIT_ONLY (removed when effective on child). No production helper.
        byte?[] directoryDeny = [null,25,18,19,null,null,16,16,null,25,18,19,null,null,16,16];
        var expectedFile = ProfileDescriptor(0x8004, 16, 16, (flags & 1) != 0);
        var expectedDir = ProfileDescriptor(0x8004, directoryDeny[flags] ?? 0, 19, directoryDeny[flags] != null);
        var expectedGrand = ProfileDescriptor(0x8004, 16, 16, (flags & 1) != 0 && (flags & 4) == 0);
        foreach (var row in new[] { (file, expectedFile), (dir, expectedDir), (grand, expectedGrand) })
            Check.That(ProfileOutput(await a.Exchange(ProfileSecurityQuery(row.Item1))).SequenceEqual(row.Item2), "complete OI/CI/INHERIT_ONLY/NO_PROPAGATE descriptor truth table");
        await ProfileAccess(a, "parent\\file", file, [5, 7], (flags & 1) != 0);
        await ProfileAccess(a, "parent\\dir\\file", grand, [11, 13], (flags & 1) != 0 && (flags & 4) == 0);
        var probe = await a.Exchange(ProfileCreate("parent\\dir", access: 1, directory: true), (flags & 2) != 0 ? Denied : 0);
        if ((flags & 2) == 0) await a.Exchange(RawSmb.Close(Id(probe), 0, 0, 0));
        await ProfileDelete(a, file); await ProfileDelete(a, grand); await ProfileDelete(a, dir); await ProfileDelete(a, parent);
        await a.Exchange(ProfileCreate("parent", directory: true), Missing);
    }
    public static async Task LegalNameProfile(ushort dialect)
    {
        const string name = ".+,;=[].", sentinelName = "sentinel";
        byte[] data = [0, 31, 43, 44, 59, 61, 91, 93, 255], sentinelBytes = [19, 23, 29];
        await using var f = new Fixture(); f.Server.State.Options.FeaturePolicy = SmbFeaturePolicy.Restricted;
        await f.Server.StartAsync(); await using var a = await f.Connect(dialect, Guid.NewGuid()); await using var b = await f.Connect(dialect, Guid.NewGuid());
        var sentinel = Id(await a.Exchange(ProfileCreate(sentinelName, 2, 0x1f01ff))); await a.Exchange(RawSmb.Write(sentinel, sentinelBytes, 0, 0, 0, 0));
        // Same literal and OPEN_IF as the pinned original. FSCC's Unicode rule
        // does not impose the separate 8.3 short-name character restrictions.
        var first = await a.Exchange(ProfileCreate(name, 3, 0x1f01ff)); Check.Equal(2u, RawSmb.U32(first, 68), "OPEN_IF created the literal name");
        var id = Id(first); await a.Exchange(RawSmb.Write(id, data, 0, 0, 0, 0)); await Bytes(a, id, data);
        var info = ProfileOutput(await a.Exchange(Query(id, 18)));
        Check.Equal((ulong)data.Length, RawSmb.U64(info, 48), "queried EOF is exact");
        Check.Equal(name, Encoding.Unicode.GetString(info, 100, (int)RawSmb.U32(info, 96)), "FILE_ALL_INFORMATION literal name");
        var identity = ProfileOutput(await a.Exchange(Query(id, 6)));
        await a.Exchange(RawSmb.Close(id, 0, 0, 0));
        await a.Exchange(Query(id, 6), 0xc0000128);
        var second = await b.Exchange(ProfileCreate(name, 3, 0x1f01ff)); Check.Equal(1u, RawSmb.U32(second, 68), "OPEN_IF reopens rather than creates an alternative name");
        id = Id(second); Check.That(ProfileOutput(await b.Exchange(Query(id, 6))).SequenceEqual(identity), "identity stable across CLOSE and authenticated reopen"); await Bytes(b, id, data);
        var root = Id(await a.Exchange(ProfileCreate("", access: 0x81, directory: true)));
        async Task Names(params string[] expected)
        {
            var names = RawSmb.Names(ProfileOutput(await a.Exchange(RawSmb.Enumerate(root, 0, 0, 0))));
            // The host profile includes the root self-entry and omits its parent.
            Check.That(names.Order(StringComparer.Ordinal).SequenceEqual(expected.Append(".").Order(StringComparer.Ordinal)), "exact enumeration excludes alternate/normalized/mutated paths; actual=" + string.Join("|", names));
        }
        await Names(name, sentinelName);
        foreach (var wrong in new[] { ".+,;=[]", ".+,;=[].wrong" }) await b.Exchange(ProfileCreate(wrong, access: 1), Missing);
        foreach (var wildcard in new[] { ".+,;=[].*", ".+,;=[]?" }) await b.Exchange(ProfileCreate(wildcard, 3, 0x1f01ff), 0xc0000033);
        await Names(name, sentinelName); await Bytes(a, sentinel, sentinelBytes); await Bytes(b, id, data);
        await ProfileDelete(b, id); await a.Exchange(ProfileCreate(name, access: 1), Missing);
        await Names(sentinelName); await Bytes(a, sentinel, sentinelBytes); await ProfileDelete(a, sentinel);
        await Names(); await a.Exchange(RawSmb.Close(root, 0, 0, 0));
    }
}
