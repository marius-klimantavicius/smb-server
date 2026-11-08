using System.Text;
using Smb.FileSystem.Local;
using Smb.Protocol.Enums;
using Smb.Server;
using Smb.Server.State;
using Smb.Testing;

// Pinned Samba 2816d12d5346c4e6258d8263f68eb653fd44fd5e.
// See docs/correctness/upstream-samba-tests.md. All assertions cross the signed
// SMB dispatcher boundary; local bytes only corroborate the observable effects.
internal static partial class UpstreamSambaTests
{
    const uint Ok = 0, Invalid = 0xc000000d, Denied = 0xc0000022;
    const uint Missing = 0xc0000034, Collision = 0xc0000035, Sharing = 0xc0000043;
    const uint NotDirectory = 0xc0000103, IsDirectory = 0xc00000ba;
    const uint NotGranted = 0xc0000055, NotLocked = 0xc000007e;
    const uint Read = 1, Write = 2, All = 0x0013019f;
    static readonly byte[] Payload = "Samba independent payload"u8.ToArray();
    readonly record struct ShareRow(uint Share, uint Access, bool Allowed);
    // Literal, deduplicated rows from sharemode_table. The same access
    // mask in opposite acquisition directions is a distinct protocol operation.
    static readonly ShareRow[] Shares =
    [
        new(0x1, 0x1, true),
        new(0x1, 0x2, false),
        new(0x1, 0x4, false),
        new(0x1, 0x8, true),
        new(0x1, 0x10, true),
        new(0x1, 0x20, true),
        new(0x1, 0x80, true),
        new(0x1, 0x100, true),
        new(0x1, 0x10000, false),
        new(0x1, 0x20000, true),
        new(0x1, 0x40000, true),
        new(0x1, 0x80000, true),
        new(0x1, 0x100000, true),
        new(0x2, 0x1, false),
        new(0x2, 0x2, true),
        new(0x2, 0x4, true),
        new(0x2, 0x8, true),
        new(0x2, 0x10, true),
        new(0x2, 0x20, false),
        new(0x2, 0x80, true),
        new(0x2, 0x100, true),
        new(0x2, 0x10000, false),
        new(0x2, 0x20000, true),
        new(0x2, 0x40000, true),
        new(0x2, 0x80000, true),
        new(0x2, 0x100000, true),
        new(0x4, 0x1, false),
        new(0x4, 0x2, false),
        new(0x4, 0x4, false),
        new(0x4, 0x8, true),
        new(0x4, 0x10, true),
        new(0x4, 0x20, false),
        new(0x4, 0x80, true),
        new(0x4, 0x100, true),
        new(0x4, 0x10000, true),
        new(0x4, 0x20000, true),
        new(0x4, 0x40000, true),
        new(0x4, 0x80000, true),
        new(0x4, 0x100000, true),
        new(0x3, 0x1, true),
        new(0x3, 0x2, true),
        new(0x3, 0x4, true),
        new(0x3, 0x8, true),
        new(0x3, 0x10, true),
        new(0x3, 0x20, true),
        new(0x3, 0x80, true),
        new(0x3, 0x100, true),
        new(0x3, 0x10000, false),
        new(0x3, 0x20000, true),
        new(0x3, 0x40000, true),
        new(0x3, 0x80000, true),
        new(0x3, 0x100000, true),
        new(0x5, 0x1, true),
        new(0x5, 0x2, false),
        new(0x5, 0x4, false),
        new(0x5, 0x8, true),
        new(0x5, 0x10, true),
        new(0x5, 0x20, true),
        new(0x5, 0x80, true),
        new(0x5, 0x100, true),
        new(0x5, 0x10000, true),
        new(0x5, 0x20000, true),
        new(0x5, 0x40000, true),
        new(0x5, 0x80000, true),
        new(0x5, 0x100000, true),
        new(0x6, 0x1, false),
        new(0x6, 0x2, true),
        new(0x6, 0x4, true),
        new(0x6, 0x8, true),
        new(0x6, 0x10, true),
        new(0x6, 0x20, false),
        new(0x6, 0x80, true),
        new(0x6, 0x100, true),
        new(0x6, 0x10000, true),
        new(0x6, 0x20000, true),
        new(0x6, 0x40000, true),
        new(0x6, 0x80000, true),
        new(0x6, 0x100000, true),
        new(0x7, 0x1, true),
        new(0x7, 0x2, true),
        new(0x7, 0x4, true),
        new(0x7, 0x8, true),
        new(0x7, 0x10, true),
        new(0x7, 0x20, true),
        new(0x7, 0x80, true),
        new(0x7, 0x100, true),
        new(0x7, 0x10000, true),
        new(0x7, 0x20000, true),
        new(0x7, 0x40000, true),
        new(0x7, 0x80000, true),
        new(0x7, 0x100000, true),
        new(0x1, 0x3, false),
        new(0x1, 0x5, false),
        new(0x1, 0x9, true),
        new(0x1, 0x11, true),
        new(0x1, 0x21, true),
        new(0x1, 0x81, true),
        new(0x1, 0x101, true),
        new(0x1, 0x10001, false),
        new(0x1, 0x20001, true),
        new(0x1, 0x40001, true),
        new(0x1, 0x80001, true),
        new(0x1, 0x100001, true),
        new(0x2, 0x3, false),
        new(0x2, 0x6, true),
        new(0x2, 0xa, true),
        new(0x2, 0x12, true),
        new(0x2, 0x22, false),
        new(0x2, 0x82, true),
        new(0x2, 0x102, true),
        new(0x2, 0x10002, false),
        new(0x2, 0x20002, true),
        new(0x2, 0x40002, true),
        new(0x2, 0x80002, true),
        new(0x2, 0x100002, true),
        new(0x3, 0x3, true),
        new(0x3, 0x5, true),
        new(0x3, 0x9, true),
        new(0x3, 0x11, true),
        new(0x3, 0x21, true),
        new(0x3, 0x81, true),
        new(0x3, 0x101, true),
        new(0x3, 0x10001, false),
        new(0x3, 0x20001, true),
        new(0x3, 0x40001, true),
        new(0x3, 0x80001, true),
        new(0x3, 0x100001, true),
        new(0x5, 0x3, false),
        new(0x5, 0x5, false),
        new(0x5, 0x9, true),
        new(0x5, 0x11, true),
        new(0x5, 0x21, true),
        new(0x5, 0x81, true),
        new(0x5, 0x101, true),
        new(0x5, 0x10001, true),
        new(0x5, 0x20001, true),
        new(0x5, 0x40001, true),
        new(0x5, 0x80001, true),
        new(0x5, 0x100001, true),
        new(0x6, 0x3, false),
        new(0x6, 0x6, true),
        new(0x6, 0xa, true),
        new(0x6, 0x12, true),
        new(0x6, 0x22, false),
        new(0x6, 0x82, true),
        new(0x6, 0x102, true),
        new(0x6, 0x10002, true),
        new(0x6, 0x20002, true),
        new(0x6, 0x40002, true),
        new(0x6, 0x80002, true),
        new(0x6, 0x100002, true),
        new(0x7, 0x3, true),
        new(0x7, 0x5, true),
        new(0x7, 0x9, true),
        new(0x7, 0x11, true),
        new(0x7, 0x21, true),
        new(0x7, 0x81, true),
        new(0x7, 0x101, true),
        new(0x7, 0x10001, true),
        new(0x7, 0x20001, true),
        new(0x7, 0x40001, true),
        new(0x7, 0x80001, true),
        new(0x7, 0x100001, true),
    ];

    public static IEnumerable<(string Name, Func<Task> Run)> Cases()
    {
        foreach (var test in SessionCases()) yield return test;
        foreach (var row in Shares)
            foreach (var reverse in new[] { false, true })
            {
                // Exact already-covered single-bit conflicts from campaign 1.
                if ((!reverse && row.Share == 1 && row.Access == 2) ||
                    (reverse && row.Share == 2 && row.Access == 1) ||
                    (!reverse && row.Share == 3 && row.Access == 0x10000)) continue;
                yield return ($"upstream.samba.share.{(reverse ? "access-share" : "share-access")}.{row.Share:x}.{row.Access:x}", () => Share(row, reverse));
            }
        yield return ("upstream.samba.share.stat-open-share-none", StatOpen);
        foreach (var attr in new uint[] { 0, 1, 2, 4, 0x20, 0x21, 0x22, 0x24, 0x23, 0x25, 0x26, 3, 5, 7, 0x80 })
            yield return ($"upstream.samba.attr.create.{attr:x}", () => CreateAttributes(attr));
        foreach (var initial in new uint[] { 0x80, 0x20, 2, 4, 0x22, 0x24, 0x26 })
            foreach (var requested in new uint[] { 0x80, 0x20, 1, 2, 4, 3, 5, 6, 7, 0x22, 0x24, 0x23, 0x25, 0x26, 0x27 })
                yield return ($"upstream.samba.attr.overwrite.{initial:x}.{requested:x}", () => OverwriteAttributes(initial, requested));
        foreach (var disposition in new uint[] { 0, 4, 5 })
            foreach (var exists in new[] { false, true })
            {
                if (disposition == 4 && exists) continue; // upstream.create.semantic.directory-overwrite
                yield return ($"upstream.samba.directory.disposition.{disposition}.{exists}", () => DirectoryDisposition(disposition, exists));
            }
        foreach (var option in new uint[] { 4, 8, 0x800, 0x200 })
            yield return ($"upstream.samba.directory.option.{option:x}", () => DirectoryOption(option));
        yield return ("upstream.samba.directory.mkdir-collision-file", MkdirFile);
        yield return ("upstream.samba.directory.missing-parent", MissingParent);
        yield return ("upstream.samba.directory.long-component", LongDirectory);
        yield return ("upstream.samba.directory.temporary-attribute", TemporaryDirectory);
        yield return ("upstream.samba.create.ignored-reserved-fields", IgnoredCreateFields);
        yield return ("upstream.samba.create.overwrite-locked-file", OverwriteLocked);
        for (var bit = 0; bit < 32; bit++)
        {
            var option = 1u << bit;
            if (option is 0x1000 or 0x80) continue; // DELETE_ON_CLOSE is destructive; 0x80 is an undefined legacy tree-connect option
            yield return ($"upstream.samba.create.option-bit.{option:x8}", () => CreateOptionBit(option));
        }
        foreach (var access in new uint[] { 0x04000000, 0x08000000 })
            yield return ($"upstream.samba.create.reserved-access.{access:x8}", () => ReservedAccess(access));
        foreach (var disp in new uint[] { 0, 1, 2, 3, 4, 5 })
            foreach (var exists in new[] { false, true })
                yield return ($"upstream.samba.stream.disposition.{disp}.{exists}", () => StreamDisposition(disp, exists));
        foreach (var disp in new uint[] { 0, 4, 5 })
            yield return ($"upstream.samba.stream.base-overwrite.{disp}", () => BaseOverwriteStreams(disp));
        foreach (var name in new[] { "space name", "?Stream*", "\u0005Stream\n One", "MStream Two:$DaTa" })
            yield return ($"upstream.samba.stream.name.{Convert.ToHexString(Encoding.UTF8.GetBytes(name))}", () => StreamName(name));
        foreach (var suffix in new[] { ":named:$FOO", ":named:", ":named:?D*a" })
            yield return ($"upstream.samba.stream.invalid-type.{Convert.ToHexString(Encoding.UTF8.GetBytes(suffix))}", () => InvalidStreamType(suffix));
        yield return ("upstream.samba.stream.implicit-base-create", ImplicitBase);
        yield return ("upstream.samba.stream.share-isolation", StreamShare);
        yield return ("upstream.samba.stream.directory-option", StreamDirectory);
        yield return ("upstream.samba.stream.zero-byte-enumeration", ZeroStream);
        yield return ("upstream.samba.stream.base-delete-all-streams", BaseDelete);
        yield return ("upstream.samba.stream.attributes-shared", StreamAttributes);
        foreach (var row in ZeroLocks)
            foreach (var same in new[] { false, true })
                yield return ($"upstream.samba.lock.zero.{row.A}.{row.AL}.{row.B}.{row.BL}.{same}", () => ZeroLock(row, same));
        foreach (var at in new ulong[] { 0, 0xffffffff, 0x100000000, 0x7fffffffffffffff, 0x8000000000000000, 0xfffffffffffffffd })
            yield return ($"upstream.samba.lock.range.{at:x}", () => LockRange(at));
        yield return ("upstream.samba.lock.truncate-retains-range", TruncateLock);
        yield return ("upstream.samba.lock.zero-read-over-exclusive", ZeroRead);
        foreach (var mode in new[] { "close", "tree", "logoff" })
            yield return ($"upstream.samba.lock.cleanup.{mode}", () => LockCleanup(mode));
        foreach (var test in AdvancedCases()) yield return test;
    }

    static byte[] Create(string path, uint disposition = 1, uint access = All,
        uint share = 7, uint options = 0x40, uint attrs = 0x80)
    {
        var b = RawSmb.Create(path, false, 0, 1, 42);
        RawSmb.Put32(b, 88, access); RawSmb.Put32(b, 92, attrs); RawSmb.Put32(b, 96, share);
        RawSmb.Put32(b, 100, disposition); RawSmb.Put32(b, 104, options); return b;
    }
    static void Status(byte[] b, uint expected, string why) => Check.Equal(expected, RawSmb.U32(b, 8), why);
    static (ulong P, ulong V) Id(byte[] b) { Status(b, Ok, "CREATE"); return (RawSmb.U64(b, 128), RawSmb.U64(b, 136)); }
    static async Task<(ulong P, ulong V)> Open(P2Tests.Direct d, string name = "file", uint disposition = 1, uint access = All, uint share = 7)
        => Id(await d.Send(Create(name, disposition, access, share)));
    static async Task Close(P2Tests.Direct d, (ulong P, ulong V) id) => Status(await d.Send(RawSmb.Close(id, 0, 1, 42)), Ok, "CLOSE");
    static async Task Data(P2Tests.Direct d, (ulong P, ulong V) id, byte[] expected)
    {
        var b = await d.Send(RawSmb.Read(id, (uint)Math.Max(1, expected.Length + 1), 0, 0, 1, 42));
        Status(b, expected.Length == 0 ? 0xc0000011u : Ok, "READ exact content");
        if (expected.Length != 0) Check.That(RawSmb.Buffer(b, b[66], RawSmb.U32(b, 68)).SequenceEqual(expected), "independently known bytes");
    }
    static byte[] Set((ulong P, ulong V) id, byte cls, byte[] data) => P5Tests.SetPacket(id, cls, data);
    static byte[] Query((ulong P, ulong V) id, byte cls, uint max = 4096)
    {
        var b = RawSmb.Header(16, 40, 0, 1, 42); RawSmb.Put16(b, 64, 41); b[66] = 1; b[67] = cls;
        RawSmb.Put32(b, 68, max); RawSmb.Put64(b, 88, id.P); RawSmb.Put64(b, 96, id.V); return b;
    }
    static async Task<uint> Attributes(P2Tests.Direct d, (ulong P, ulong V) id)
    {
        var b = await d.Send(Query(id, 4)); Status(b, Ok, "QUERY FileBasicInformation");
        return RawSmb.U32(b, RawSmb.U16(b, 66) + 32);
    }
    static async Task SetAttributes(P2Tests.Direct d, (ulong P, ulong V) id, uint value)
    {
        var data = new byte[40]; RawSmb.Put32(data, 32, value);
        Status(await d.Send(Set(id, 4, data)), Ok, "SET FileBasicInformation attributes");
    }
    static async Task Share(ShareRow row, bool reverse)
    {
        using var root = new P7cTests.Root(); File.WriteAllBytes(Path.Combine(root.Path, "file"), Payload);
        await using var d = new P2Tests.Direct(root.Store());
        var a = await Open(d, access: reverse ? row.Access : All, share: reverse ? 7 : row.Share);
        var b = await d.Send(Create("file", access: reverse ? All : row.Access, share: reverse ? row.Share : 7));
        Status(b, row.Allowed ? Ok : Sharing, "pinned sharemode_table status in " + (reverse ? "reverse" : "forward") + " acquisition order");
        if (row.Allowed) await Close(d, Id(b));
        await Close(d, a);
        // A failed acquisition may not leave a share reservation behind.
        var retry = await Open(d, access: reverse ? All : row.Access, share: reverse ? row.Share : 7);
        await Close(d, retry); Check.That(File.ReadAllBytes(Path.Combine(root.Path, "file")).SequenceEqual(Payload), "sharing never changes file bytes");
    }
    static async Task StatOpen()
    {
        using var root = new P7cTests.Root(); File.WriteAllBytes(Path.Combine(root.Path, "file"), Payload);
        await using var d = new P2Tests.Direct(root.Store());
        var stat = await Open(d, access: 0x80, share: 0);
        var reader = await Open(d, access: 1, share: 7);
        await Data(d, reader, Payload); var writer = await Open(d, access: 2, share: 7);
        await Close(d, writer); await Close(d, reader); await Close(d, stat);
    }
    static async Task CreateAttributes(uint attr)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        var b = await d.Send(Create("file", 2, attrs: attr)); var id = Id(b);
        var expected = (attr & ~0x80u) | 0x20;
        Check.Equal(expected, RawSmb.U32(b, 120), "CREATE attributes: archive added, NORMAL alone has no stored bit");
        Check.Equal(expected, await Attributes(d, id), "QUERY attributes agree with independent expected mask");
        if ((attr & 1) != 0) await SetAttributes(d, id, 0x80);
        await Close(d, id);
    }
    static async Task OverwriteAttributes(uint initial, uint requested)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        var id = await Open(d, disposition: 2); Status(await d.Send(RawSmb.Write(id, Payload, 0, 0, 1, 42)), Ok, "seed WRITE");
        await SetAttributes(d, id, initial); await Close(d, id);
        var expectedStatus = ((initial & 6) & ~requested) != 0 ? Denied : Ok;
        var b = await d.Send(Create("file", 4, attrs: requested)); Status(b, expectedStatus, "hidden/system attributes must match on overwrite");
        if (expectedStatus == Ok)
        {
            id = Id(b); Check.Equal((requested & ~0x80u) | 0x20, await Attributes(d, id), "overwrite attribute result");
            await Data(d, id, []); if ((requested & 1) != 0) await SetAttributes(d, id, 0x80); await Close(d, id);
        }
        else
        {
            id = await Open(d); await Data(d, id, Payload); await SetAttributes(d, id, 0x80); await Close(d, id);
        }
    }
    static async Task DirectoryDisposition(uint disposition, bool exists)
    {
        using var root = new P7cTests.Root(); if (exists) Directory.CreateDirectory(Path.Combine(root.Path, "dir"));
        await using var d = new P2Tests.Direct(root.Store());
        Status(await d.Send(Create("dir", disposition, options: 1, attrs: 0x10)), Invalid, "directory only permits OPEN/CREATE/OPEN_IF");
        Check.Equal(exists, Directory.Exists(Path.Combine(root.Path, "dir")), "invalid disposition cannot change namespace");
    }
    static async Task DirectoryOption(uint option)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        Status(await d.Send(Create("dir", 2, options: 1 | option, attrs: 0x10)), Invalid, "invalid directory option combination");
        Check.That(!Directory.Exists(Path.Combine(root.Path, "dir")), "invalid directory option cannot create object");
    }
    static async Task MkdirFile()
    {
        using var root = new P7cTests.Root(); File.WriteAllBytes(Path.Combine(root.Path, "dir"), Payload);
        await using var d = new P2Tests.Direct(root.Store());
        Status(await d.Send(Create("dir", 2, options: 1, attrs: 0x10)), Collision, "mkdir against file uses collision precedence");
        var id = await Open(d, "dir"); await Data(d, id, Payload); await Close(d, id);
    }
    static async Task MissingParent()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        Status(await d.Send(Create("missing\\child", 2, options: 1, attrs: 0x10)), 0xc000003a, "mkdir does not recursively invent parent");
        Check.That(!Directory.Exists(Path.Combine(root.Path, "missing")), "no implicit parent creation");
    }
    static async Task LongDirectory()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var name = new string('a', 255);
        var id = Id(await d.Send(Create(name, 2, options: 1, attrs: 0x10)));
        Status(await d.Send(Set(id, 13, [1])), Ok, "delete long-component directory"); await Close(d, id);
        Check.That(!Directory.Exists(Path.Combine(root.Path, name)), "255-character component removed");
    }
    static async Task TemporaryDirectory()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        var id = Id(await d.Send(Create("dir", 2, options: 1, attrs: 0x10)));
        var b = new byte[40]; RawSmb.Put32(b, 32, 0x100);
        Status(await d.Send(Set(id, 4, b)), Invalid, "temporary attribute invalid for a directory");
        Check.Equal(0x10u, await Attributes(d, id), "failed SET retains directory attributes"); await Close(d, id);
    }
    static async Task IgnoredCreateFields()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        var b = Create("file", 2); b[66] = 0xff; RawSmb.Put64(b, 72, ulong.MaxValue); RawSmb.Put64(b, 80, ulong.MaxValue);
        var id = Id(await d.Send(b)); await Close(d, id); id = await Open(d); await Close(d, id);
    }
    static async Task CreateOptionBit(uint option)
    {
        using var root = new P7cTests.Root(); File.WriteAllBytes(Path.Combine(root.Path, "file"), Payload);
        await using var d = new P2Tests.Direct(root.Store());
        // Literal test_create_gentest masks, excluding its obsolete 0x80 bit.
        // MS-SMB2 2.2.13 requires NOT_SUPPORTED for OPEN_BY_FILE_ID/RESERVE_OPFILTER.
        var expected = (option & 0xff000000) != 0 ? Invalid : option == 1 ? NotDirectory :
            (option & 0x00102080) != 0 ? 0xc00000bbu : Ok;
        var b = await d.Send(Create("file", 3, options: option)); Status(b, expected, "pinned per-bit CREATE options table");
        if (expected == Ok) await Close(d, Id(b));
        var id = await Open(d); await Data(d, id, Payload); await Close(d, id);
    }
    static async Task ReservedAccess(uint access)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        Status(await d.Send(Create("file", 2, access)), Denied, "reserved DesiredAccess bits rejected before namespace mutation");
        Check.That(!File.Exists(Path.Combine(root.Path, "file")), "rejected access leaves no file");
    }
    static async Task OverwriteLocked()
    {
        using var root = new P7cTests.Root(); File.WriteAllBytes(Path.Combine(root.Path, "file"), Payload);
        await using var d = new P2Tests.Direct(root.Store()); var a = await Open(d);
        Status(await d.Send(Lock(a, 0, 1)), Ok, "lock initial byte");
        var b = await Open(d, disposition: 5);
        var info = await d.Send(Query(b, 5)); Status(info, Ok, "query truncated EOF without accessing locked bytes");
        Check.Equal(0ul, RawSmb.U64(info, RawSmb.U16(info, 66) + 8), "locked file was truncated");
        Status(await d.Send(Lock(b, 0, 1)), NotGranted, "truncation does not release other open's lock");
        await Close(d, a); Status(await d.Send(Lock(b, 0, 1)), Ok, "close releases original owner"); await Close(d, b);
    }
    static async Task StreamDisposition(uint disposition, bool exists)
    {
        using var root = new P7cTests.Root(); File.WriteAllBytes(Path.Combine(root.Path, "file"), Payload);
        await using var d = new P2Tests.Direct(root.Store());
        if (exists) { var old = await Open(d, "file:one", 2); Status(await d.Send(RawSmb.Write(old, [9, 8, 7], 0, 0, 1, 42)), Ok, "seed stream"); await Close(d, old); }
        var expectedStatus = exists && disposition == 2 ? Collision : !exists && disposition is 1 or 4 ? Missing : Ok;
        var b = await d.Send(Create("file:one", disposition)); Status(b, expectedStatus, "named stream disposition independent of existing base");
        if (expectedStatus == Ok)
        {
            Check.Equal(exists ? disposition == 0 ? 0u : disposition is 4 or 5 ? 3u : 1u : 2u, RawSmb.U32(b, 68), "stream CREATE action");
            var id = Id(b); await Data(d, id, exists && disposition is 1 or 3 ? [9, 8, 7] : []); await Close(d, id);
        }
        var baseId = await Open(d); await Data(d, baseId, Payload); await Close(d, baseId);
    }
    static async Task BaseOverwriteStreams(uint disposition)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        var id = await Open(d, disposition: 2); await Close(d, id);
        id = await Open(d, "file:one", 2); Status(await d.Send(RawSmb.Write(id, [1], 0, 0, 1, 42)), Ok, "seed alternate stream"); await Close(d, id);
        id = await Open(d, disposition: disposition); await Close(d, id);
        Status(await d.Send(Create("file:one")), Missing, "base overwrite/supersede removes named streams");
    }
    static async Task StreamName(string name)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        await Close(d, await Open(d, disposition: 2));
        var id = await Open(d, "file:" + name, 2); Status(await d.Send(RawSmb.Write(id, Payload, 0, 0, 1, 42)), Ok, "write non-path stream name"); await Close(d, id);
        id = await Open(d, "file:" + name); await Data(d, id, Payload); await Close(d, id);
    }
    static async Task InvalidStreamType(string suffix)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        Status(await d.Send(Create("file" + suffix, 2)), 0xc0000033, "unsupported/empty stream type has invalid object name");
        Check.That(!File.Exists(Path.Combine(root.Path, "file")), "invalid stream type creates no base");
    }
    static async Task ImplicitBase()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        var id = await Open(d, "file:one", 2); await Close(d, id); id = await Open(d); await Data(d, id, []); await Close(d, id);
    }
    static async Task StreamShare()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        await Close(d, await Open(d, disposition: 2));
        var a = await Open(d, "file:one", 2, Read | Write, 0);
        var b = await Open(d, "file:two", 2, Read | Write, 0);
        Status(await d.Send(Create("file:one", access: Read, share: 7)), Sharing, "same stream conflicts");
        Status(await d.Send(RawSmb.Write(a, [1, 2], 0, 0, 1, 42)), Ok, "first stream WRITE");
        Status(await d.Send(RawSmb.Write(b, [3, 4], 0, 0, 1, 42)), Ok, "second stream WRITE");
        await Data(d, a, [1, 2]); await Data(d, b, [3, 4]); await Close(d, a); await Close(d, b);
    }
    static async Task StreamDirectory()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        Status(await d.Send(Create("file:one", 2, options: 1)), NotDirectory, "named stream cannot be a directory");
        Check.That(!File.Exists(Path.Combine(root.Path, "file")), "rejected directory stream creates no base");
    }
    static async Task ZeroStream()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        await Close(d, await Open(d, disposition: 2));
        var id = await Open(d, "file:empty", 2); await Close(d, id); id = await Open(d);
        var b = await d.Send(Query(id, 22)); Status(b, Ok, "enumerate empty named stream");
        var names = StreamList(b); Check.That(names.Contains(":empty:$DATA"), "zero-byte named stream is listed"); await Close(d, id);
    }
    static HashSet<string> StreamList(byte[] b)
    {
        var at = (int)RawSmb.U16(b, 66); var end = at + (int)RawSmb.U32(b, 68); var names = new HashSet<string>();
        while (at < end)
        {
            Check.That(at + 24 <= end, "bounded stream record"); var next = (int)RawSmb.U32(b, at); var n = (int)RawSmb.U32(b, at + 4);
            Check.That((n & 1) == 0 && at + 24 + n <= end, "bounded UTF16 stream name"); names.Add(Encoding.Unicode.GetString(b, at + 24, n));
            if (next == 0) break; Check.That((next & 7) == 0 && next >= 24 + n, "stream chain progresses"); at += next;
        }
        return names;
    }
    static async Task BaseDelete()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        await Close(d, await Open(d, disposition: 2));
        var a = await Open(d, "file:one", 2); await Close(d, a); a = await Open(d);
        Status(await d.Send(Set(a, 13, [1])), Ok, "delete base with named stream"); await Close(d, a);
        a = await Open(d, disposition: 2); await Close(d, a);
        Status(await d.Send(Create("file:one")), Missing, "recreated base cannot inherit deleted object's streams");
    }
    static async Task StreamAttributes()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        await Close(d, await Open(d, disposition: 2));
        var a = await Open(d, "file:one", 2); var b = await Open(d); await SetAttributes(d, a, 2);
        Check.Equal(2u, await Attributes(d, b), "stream SET updates base attributes");
        await SetAttributes(d, b, 4); Check.Equal(4u, await Attributes(d, a), "base SET updates stream attributes");
        await SetAttributes(d, b, 0x80); await Close(d, a); await Close(d, b);
    }
    readonly record struct ZeroRow(ulong A, ulong AL, ulong B, ulong BL, uint Status);
    static readonly ZeroRow[] ZeroLocks =
    [
        new(10,0,10,0,Ok), new(10,0,9,1,Ok), new(10,0,10,1,Ok), new(10,0,11,1,Ok),
        new(10,0,9,2,NotGranted), new(10,0,10,2,Ok), new(10,0,9,3,NotGranted),
        new(9,1,10,0,Ok), new(10,1,10,0,Ok), new(11,1,10,0,Ok),
        new(9,2,10,0,NotGranted), new(10,2,10,0,Ok), new(9,3,10,0,NotGranted), new(0,0,0,0,Ok)
    ];
    static byte[] Lock((ulong P, ulong V) id, ulong at, ulong length, uint flags = 0x12)
    {
        var b = RawSmb.Header(10, 48, 0, 1, 42); RawSmb.Put16(b, 64, 48); RawSmb.Put16(b, 66, 1);
        RawSmb.Put64(b, 72, id.P); RawSmb.Put64(b, 80, id.V); RawSmb.Put64(b, 88, at); RawSmb.Put64(b, 96, length); RawSmb.Put32(b, 104, flags); return b;
    }
    static async Task ZeroLock(ZeroRow row, bool same)
    {
        await using var d = new P2Tests.Direct(); var a = await d.Open(); var b = same ? a : await d.Open();
        Status(await d.Send(Lock(a, row.A, row.AL)), Ok, "initial zero-range-table lock");
        Status(await d.Send(Lock(b, row.B, row.BL)), row.Status, "zero-length ranges conflict only with strict interior");
        if (row.Status == Ok) Status(await d.Send(Lock(b, row.B, row.BL, 4)), Ok, "release second zero-table lock");
        Status(await d.Send(Lock(a, row.A, row.AL, 4)), Ok, "release first zero-table lock");
    }
    static async Task LockRange(ulong at)
    {
        await using var d = new P2Tests.Direct(); var a = await d.Open(); var b = await d.Open();
        Status(await d.Send(Lock(a, at, 1)), Ok, "64-bit lock offset accepted");
        Status(await d.Send(Lock(b, at + 1, 1)), Ok, "adjacent high-offset lock accepted");
        Status(await d.Send(Lock(b, at, 1)), NotGranted, "exact high-offset lock conflicts");
        Status(await d.Send(Lock(a, at, 1, 4)), Ok, "high-offset exact unlock");
        Status(await d.Send(Lock(b, at, 1)), Ok, "high-offset range reusable");
    }
    static async Task TruncateLock()
    {
        await using var d = new P2Tests.Direct(); var a = await d.Open(); var b = await d.Open();
        Status(await d.Send(RawSmb.Write(a, new byte[32], 0, 0, 1, 42)), Ok, "seed bytes");
        Status(await d.Send(Lock(a, 16, 16)), Ok, "lock beyond new EOF");
        var size = new byte[8]; RawSmb.Put64(size, 0, 4); Status(await d.Send(Set(b, 20, size)), Ok, "truncate with peer byte-range lock");
        Status(await d.Send(Lock(b, 16, 16)), NotGranted, "truncate retains lock past EOF");
        await Close(d, a); Status(await d.Send(Lock(b, 16, 16)), Ok, "owner CLOSE releases past-EOF lock");
    }
    static async Task ZeroRead()
    {
        await using var d = new P2Tests.Direct(); var a = await d.Open(); var b = await d.Open();
        Status(await d.Send(RawSmb.Write(a, [1, 2], 0, 0, 1, 42)), Ok, "seed file"); Status(await d.Send(Lock(a, 0, 2)), Ok, "exclusive lock");
        var response = await d.Send(RawSmb.Read(b, 0, 1, 0, 1, 42)); Status(response, Ok, "zero-byte READ does not conflict with a lock"); Check.Equal(0u, RawSmb.U32(response, 68), "zero bytes returned");
    }
    static async Task LockCleanup(string mode)
    {
        await using var d = new P2Tests.Direct(); var transport = new RecordingTransport(); transport.Attach(d.Connection);
        var a = await d.Open(); var b = await d.Open(); Status(await d.Send(Lock(a, 4, 4)), Ok, "blocker lock");
        Status(await d.Send(Lock(b, 4, 4, 2)), 0x103, "waiter is pending"); var pending = d.Connection.PendingRequests.Values.Single();
        if (mode == "close") await Close(d, b);
        else if (mode == "tree") Status(await d.Send(RawSmb.TreeDisconnect(0, 1, 42)), Ok, "TREE_DISCONNECT");
        else { var logoff = RawSmb.Header(2, 4, 0, 1); RawSmb.Put16(logoff, 64, 4); Status(await d.Send(logoff), Ok, "LOGOFF"); }
        await pending.Finished.WaitAsync(Check.Timeout);
        Status(transport.Sends.Single().Message, 0xc0000120, "waiting LOCK completes CANCELLED when teardown cancels its operation");
        Check.That(d.Connection.PendingRequests.IsEmpty && d.Connection.AsyncRequests.IsEmpty, "no late pending reply remains");
        if (mode == "close") { Status(await d.Send(Lock(a, 4, 4, 4)), Ok, "blocker survives peer close"); await Close(d, a); }
    }
}
