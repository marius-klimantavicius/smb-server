using Smb.Server;
using Smb.Testing;

internal static partial class UpstreamSambaMoreTests
{
    static IEnumerable<(string Name, Func<Task> Run)> InfoCases()
    {
        foreach (var directory in new[] { false, true })
        {
            // Basic/standard/internal/all/network consistency is already exact
            // in upstream.microsoft.metadata.class-consistency-{False,True}.
            foreach (var cls in new byte[] { 7, 9, 14, 22, 35 })
            {
                if (!directory && cls == 22) continue; // existing Microsoft stream-list-mutation and Samba zero-stream
                yield return ($"upstream.samba.more.info.file.{directory}.{cls}", () => FileInformation(directory, cls));
            }
            foreach (var cls in new byte[] { 16, 17, 21, 28, 48, 59 })
                yield return ($"upstream.samba.more.info.unsupported.{directory}.{cls}", () => UnsupportedInformation(directory, cls));
            foreach (var cls in new byte[] { 1, 3, 4, 5, 6, 7, 8, 11 })
                yield return ($"upstream.samba.more.info.volume.{directory}.{cls}", () => VolumeInformation(directory, cls));
            yield return ($"upstream.samba.more.info.execute-access.{directory}", () => ExecuteGranted(directory));
        }
        foreach (var control in new[] { false, true })
            yield return ($"upstream.samba.more.info.security-buffer.{control}", () => SecurityBuffer(control));
        foreach (var type in new byte[] { 0, 5, 255 })
            yield return ($"upstream.samba.more.info.invalid-type.{type}", () => InvalidInfoType(type));
        foreach (var srcAccess in new uint[] { 0x81, 0x82, 0xa0 })
            foreach (var dstAccess in new uint[] { 0x81, 0x82, 0x83 })
                foreach (var writeOnly in new[] { false, true })
                    yield return ($"upstream.samba.more.copy.access.{srcAccess:x}.{dstAccess:x}.{writeOnly}", () => CopyAccess(srcAccess, dstAccess, writeOnly));
        foreach (var flags in new byte[] { 0, 1, 2, 3, 4, 8, 16, 0x10 | 3 })
            foreach (var deny in new[] { false, true })
                yield return ($"upstream.samba.more.security.dacl.{flags:x}.{deny}", () => DaclPolicy(flags, deny));
        foreach (var directory in new[] { false, true })
            foreach (var kind in new[] { "allow", "deny", "null", "empty" })
                yield return ($"upstream.samba.more.security.unsupported-create.{directory}.{kind}", () => CreateSecurityRejection(directory, kind));
    }
    static async Task FileInformation(bool directory, byte cls)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var id = await Open(d, directory ? "dir" : "file", 3, directory: directory);
        if (!directory) await Write(d, id, Payload); var bytes = Output(await d.Send(Query(id, cls)));
        if (cls == 5) { Check.Equal((byte)(directory ? 1 : 0), bytes[21], "standard file type"); Check.Equal(directory ? 0ul : (ulong)Payload.Length, RawSmb.U64(bytes, 8), "standard EOF"); }
        if (cls is 4 or 34) Check.That((RawSmb.U32(bytes, cls == 4 ? 32 : 48) & 16) == (directory ? 16u : 0u), "basic/network-open type");
        if (cls == 6) Check.That(RawSmb.U64(bytes, 0) != 0, "opaque file index nonzero");
        if (cls == 7) Check.Equal(0u, RawSmb.U32(bytes, 0), "no EAs on new object");
        if (cls == 9) Check.That(System.Text.Encoding.Unicode.GetString(bytes, 4, (int)RawSmb.U32(bytes, 0)).EndsWith(directory ? "dir" : "file", StringComparison.Ordinal), "FileNameInformation current name");
        if (cls == 14) Check.Equal(0ul, RawSmb.U64(bytes, 0), "new open position");
        if (cls == 18) { Check.Equal((byte)(directory ? 1 : 0), bytes[61], "ALL_INFORMATION standard type"); Check.Equal(directory ? 0ul : (ulong)Payload.Length, RawSmb.U64(bytes, 48), "ALL_INFORMATION EOF"); }
        if (cls == 35) Check.Equal(0u, RawSmb.U32(bytes, 4), "no fabricated reparse tag");
        if (cls == 22 && !directory) Check.That((await StreamNames(d, id)).SequenceEqual(new[] { "::$DATA" }), "new file only has default stream");
    }
    static async Task UnsupportedInformation(bool directory, byte cls)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var id = await Open(d, directory ? "dir" : "file", 3, directory: directory);
        // MS-SMB2 3.3.5.20.1 distinguishes recognized unsupported classes
        // from undefined classes. This profile selects NOT_SUPPORTED for known
        // classes; 59 remains undefined here. Original expectations are archived.
        if (!directory) await Write(d, id, Payload);
        Status(await d.Send(Query(id, cls)), cls is 16 or 17 or 21 or 28 or 48 ? 0xc00000bbu : 0xc0000003u, "recognized optional query uses NOT_SUPPORTED; undefined query uses INVALID_INFO_CLASS");
        Check.Equal((byte)(directory ? 1 : 0), Output(await d.Send(Query(id, 5)))[21], "rejected query preserves usable FileId");
        if (!directory) await Data(d, id, Payload);
        await Close(d, id); id = await Open(d, directory ? "dir" : "file", directory: directory);
        Check.Equal((byte)(directory ? 1 : 0), Output(await d.Send(Query(id, 5)))[21], "reopen preserves type after unsupported query");
        if (!directory) await Data(d, id, Payload);
        await Close(d, id);
    }
    static async Task VolumeInformation(bool directory, byte cls)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var id = await Open(d, directory ? "" : "file", directory ? 1u : 3u, directory: directory);
        if (cls is 6 or 8 or 11)
        {
            Status(await d.Send(Query(id, cls, 4096, 2)), 0xc0000003, "quota control/object-ID/sector information is outside local backend profile"); return;
        }
        var bytes = Output(await d.Send(Query(id, cls, 4096, 2)));
        if (cls is 3 or 7)
        {
            Check.That(RawSmb.U64(bytes, 0) > 0, "volume total allocation units positive");
            var at = cls == 3 ? 16 : 24; Check.That(RawSmb.U32(bytes, at) > 0 && RawSmb.U32(bytes, at + 4) > 0, "nonzero sector geometry");
        }
        if (cls == 4) { Check.Equal(7u, RawSmb.U32(bytes, 0), "FILE_DEVICE_DISK"); Check.That(bytes.Length >= 8, "device information complete"); }
        if (cls == 5) Check.That(bytes.Length >= 12 && RawSmb.U32(bytes, 4) >= 255, "filesystem attributes and maximum component length");
        if (cls == 11) Check.That(bytes.Length >= 28 && RawSmb.U32(bytes, 0) > 0, "sector-size information complete");
        // Short-buffer status is independently required for a fixed record.
        if (cls is 3 or 4 or 7 or 11) Status(await d.Send(Query(id, cls, (uint)bytes.Length - 1, 2)), 0xc0000004, "fixed filesystem information is not truncated");
    }
    static async Task ExecuteGranted(bool directory)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); await Close(d, await Open(d, directory ? "dir" : "file", 3, directory: directory));
        var id = await Open(d, directory ? "dir" : "file", access: 0xa0, directory: directory);
        Check.Equal(0xa0u, RawSmb.U32(Output(await d.Send(Query(id, 18))), 76), "ALL_INFORMATION same granted mask");
    }
    static async Task SecurityBuffer(bool control)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); await Close(d, await Open(d, disposition: 3)); var id = await Open(d, access: control ? 0x20000u : 0x80u);
        byte[] Q(uint max) { var b = Query(id, 0, max, 3); RawSmb.Put32(b, 80, 7); return b; }
        if (!control) { Status(await d.Send(Q(4096)), Denied, "security descriptor query requires READ_CONTROL"); return; }
        Status(await d.Send(Q(1)), 0xc0000023, "security descriptor short buffer reports BUFFER_TOO_SMALL");
        var bytes = Output(await d.Send(Q(4096))); Check.That(bytes.Length >= 20 && bytes[0] == 1 && (RawSmb.U16(bytes, 2) & 0x8000) != 0, "self-relative descriptor revision/control");
    }
    static async Task InvalidInfoType(byte type)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var id = await Open(d, disposition: 3); await Write(d, id, Payload);
        Status(await d.Send(Query(id, 5, type: type)), 0xc0000003, "unknown QUERY_INFO InfoType has no valid information class"); await Data(d, id, Payload);
    }
    static async Task CopyAccess(uint srcAccess, uint dstAccess, bool writeOnly)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); d.Options.FeaturePolicy = SmbFeaturePolicy.CopyOnly;
        var seed = await Open(d, "source", 3); await Write(d, seed, Payload); await Close(d, seed); await Close(d, await Open(d, "target", 3));
        var src = await Open(d, "source", access: srcAccess); var dst = await Open(d, "target", access: dstAccess);
        var response = await d.Send(P5Tests.Ioctl(src, 0x140078, [], 32)); Status(response, Ok, "resume key issued independent of data access");
        var data = new byte[56]; RawSmb.Buffer(response, checked((int)RawSmb.U32(response, 96)), 24).CopyTo(data, 0); RawSmb.Put32(data, 24, 1); RawSmb.Put32(data, 48, (uint)Payload.Length);
        var b = await d.Send(P5Tests.Ioctl(dst, writeOnly ? 0x1480f2u : 0x1440f2u, data, 12));
        var allowed = (srcAccess & 1) != 0 && (dstAccess & 2) != 0 && (writeOnly || (dstAccess & 1) != 0);
        Status(b, allowed ? Ok : Denied, "COPYCHUNK versus COPYCHUNK_WRITE source/destination permission requirements");
        await Close(d, dst); var reader = await Open(d, "target"); await Data(d, reader, allowed ? Payload : []);
    }
    static async Task DaclPolicy(byte flags, bool deny)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var id = await Open(d, disposition: 3, access: 0x001f01ff); await Write(d, id, Payload);
        // A deny/read ACE plus an unconditional Everyone allow fallback makes
        // INHERIT_ONLY observably different from an applicable deny on this file.
        // The first RED fixture assumed no basic DACL implementation; the repair
        // evidence demonstrates support, so test actual enforcement and readback.
        var sd = DaclWithFallback(flags, deny);
        var b = Set(id, 0, sd); b[66] = 3; RawSmb.Put32(b, 76, 4);
        Status(await d.Send(b), Ok, "valid basic DACL update");
        var q = Query(id, 0, type: 3); RawSmb.Put32(q, 80, 4); var stored = Output(await d.Send(q)); var acl = (int)RawSmb.U32(stored, 16);
        Check.Equal((ushort)2, RawSmb.U16(stored, acl + 4), "DACL retains both ordered ACEs"); Check.Equal(deny ? (byte)1 : (byte)0, stored[acl + 8], "first ACE type retained");
        Check.Equal(flags, stored[acl + 9], "explicit ACE inheritance flags retained");
        Status(await d.Send(Create(access: 1)), deny && (flags & 8) == 0 ? Denied : Ok, "fresh READ_DATA admission reflects applicable deny versus INHERIT_ONLY");
        var writer = await Open(d, access: 2); await Write(d, writer, Payload); await Close(d, writer);
        await Data(d, id, Payload);
    }
    static byte[] DaclWithFallback(byte flags, bool deny, byte fallbackFlags = 0)
    {
        var first = Dacl(flags, deny); var second = Dacl(fallbackFlags, false); var sd = new byte[68]; first.CopyTo(sd, 0); second.AsSpan(28, 20).CopyTo(sd.AsSpan(48));
        RawSmb.Put32(sd, 52, 0x001f01ff); RawSmb.Put16(sd, 22, 48); RawSmb.Put16(sd, 24, 2); return sd;
    }
    static byte[] Dacl(byte flags, bool deny)
    {
        var sd = new byte[48]; sd[0] = 1; RawSmb.Put16(sd, 2, 0x8004); RawSmb.Put32(sd, 16, 20);
        sd[20] = 2; RawSmb.Put16(sd, 22, 28); RawSmb.Put16(sd, 24, 1);
        sd[28] = deny ? (byte)1 : (byte)0; sd[29] = flags; RawSmb.Put16(sd, 30, 20); RawSmb.Put32(sd, 32, 1);
        sd[36] = 1; sd[37] = 1; sd[43] = 1; RawSmb.Put32(sd, 44, 0);
        return sd;
    }
    static async Task CreateSecurityRejection(bool directory, string kind)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var sd = Dacl(directory ? (byte)3 : (byte)0, kind == "deny");
        if (kind is "null" or "empty")
        {
            sd = new byte[kind == "null" ? 20 : 28]; sd[0] = 1; RawSmb.Put16(sd, 2, 0x8004);
            if (kind == "empty") { RawSmb.Put32(sd, 16, 20); sd[20] = 2; RawSmb.Put16(sd, 22, 8); }
        }
        var response = await d.Send(P7cTests.Context(Create("secured", 2, access: 0x001f01ff, directory: directory), "SecD", sd));
        Status(response, 0xc00000bb, "unsupported CREATE security descriptor must reject before creating an unsecured replacement");
        Check.That(!File.Exists(Path.Combine(root.Path, "secured")) && !Directory.Exists(Path.Combine(root.Path, "secured")), "failed security CREATE creates no object");
        await Close(d, await Open(d, "secured", 2, directory: directory));
    }
}
