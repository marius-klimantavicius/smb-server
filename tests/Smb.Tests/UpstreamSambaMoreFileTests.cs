using Smb.Testing;

internal static partial class UpstreamSambaMoreTests
{
    static IEnumerable<(string Name, Func<Task> Run)> FileCases()
    {
        foreach (var row in new (uint N, ulong At, uint Min, uint Status, uint Count)[]
        {
            (10,0,1,Ok,10), (10,65536,0,Eof,0), (0,65536,0,Ok,0), (0,65536,1,Eof,0),
            (2,65535,0,Ok,1), (1,65535,2,Eof,0), (1,0,65536,Eof,0), (1,0,65534,Eof,0), (5,0,10,Eof,0)
        })
            yield return ($"upstream.samba.more.read.minimum.{row.N}.{row.At}.{row.Min}", () => ReadMinimum(row));
        foreach (var access in new uint[] { 0x81, 0xa0, 0x80 })
            yield return ($"upstream.samba.more.read.access.{access:x}", () => ReadAccess(access));
        foreach (var count in new uint[] { 0, 10 })
            yield return ($"upstream.samba.more.read.directory.{count}", () => ReadDirectory(count));
        foreach (var access in new uint[] { All, All & ~0x10000u })
            foreach (var share in new uint[] { 0, 7 })
                yield return ($"upstream.samba.more.rename.access.{access:x}.{share}", () => RenameAccess(access, share));
        foreach (var peerAccess in new uint[] { 1, 3, 0x10001, 0x80 })
            foreach (var peerShare in new uint[] { 3, 7 })
                yield return ($"upstream.samba.more.rename.peer.{peerAccess:x}.{peerShare}", () => RenamePeer(peerAccess, peerShare));
        foreach (var disposition in new uint[] { 2, 3, 5 })
            foreach (var exists in new[] { false, true })
            {
                if (disposition == 2 && exists || disposition == 5 && !exists) continue; // exact upstream.create.delete.* workflows
                yield return ($"upstream.samba.more.delete.create.{disposition}.{exists}", () => DeleteCreate(disposition, exists));
            }
        yield return ("upstream.samba.more.delete.find-and-set", DeleteEnumerate);
        yield return ("upstream.samba.more.create.leading-backslash", LeadingBackslash);
        yield return ("upstream.samba.more.create.impersonation-invalid", Impersonation);
        yield return ("upstream.samba.more.create.directory-duplicate-visible", DirectoryDuplicate);
        yield return ("upstream.samba.more.create.delete-only", DeleteOnly);
        yield return ("upstream.samba.more.charset.composed-distinct", ComposedNames);
        yield return ("upstream.samba.more.charset.naked-diacritical", DiacriticalNames);
        yield return ("upstream.samba.more.lock.close-releases-owner-only", CloseLocks);
        yield return ("upstream.samba.more.lock.reopen-is-distinct-owner", ReopenLock);
        foreach (var cls in new byte[] { 4, 5, 6, 7, 14, 16, 17, 18, 22, 34, 35 })
            yield return ($"upstream.samba.more.query.access.{cls}", () => QueryAccess(cls));
        foreach (var cls in new byte[] { 16, 17 }) // fixed supported-class boundaries are already p5.query.file-*
            yield return ($"upstream.samba.more.query.exact-buffer.{cls}", () => QueryBuffer(cls));
        foreach (var shape in new[] { "sparse", "sparse-empty", "sparse-oversize", "allocated-ranges", "zero-data", "compression", "shadow-copies" })
            yield return ($"upstream.samba.more.ioctl.unsupported.{shape}", () => OptionalIoctl(shape));
        foreach (var seconds in new long[] { 15032385535, 10000000000, 4294967295, 1, 0, -1, -2, -63158400 })
            yield return ($"upstream.samba.more.timestamp.unix.{seconds}", () => TimeRoundtrip(seconds));
        yield return ("upstream.samba.more.rename.timestamps-and-close-info", RenameTimeClose);
    }
    static async Task ReadMinimum((uint N, ulong At, uint Min, uint Status, uint Count) row)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var id = await Open(d, disposition: 3);
        // Two ordinary requests avoid requiring multi-credit support for the seed.
        await Write(d, id, new byte[32768]); await Write(d, id, new byte[32768], 32768);
        var b = RawSmb.Read(id, row.N, row.At, 0, 1, 42); RawSmb.Put32(b, 96, row.Min);
        var response = await d.Send(b); Status(response, row.Status, "READ MinimumCount/EOF table");
        if (row.Status == Ok) Check.Equal(row.Count, RawSmb.U32(response, 68), "exact successful READ count");
    }
    static async Task ReadAccess(uint access)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var seed = await Open(d, disposition: 3); await Write(d, seed, Payload); await Close(d, seed);
        var id = await Open(d, access: access); var response = await d.Send(RawSmb.Read(id, 5, 0, 0, 1, 42));
        Status(response, access == 0x80 ? Denied : Ok, "READ accepts FILE_READ_DATA or FILE_EXECUTE");
        if (access != 0x80) Check.That(RawSmb.Buffer(response, response[66], RawSmb.U32(response, 68)).SequenceEqual(Payload[..5]), "read/execute returns known data");
    }
    static async Task ReadDirectory(uint count)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var id = await Open(d, "", directory: true);
        // The local backend follows Samba's directory device rejection. The
        // upstream Windows zero-length branch is explicitly a platform policy.
        Status(await d.Send(RawSmb.Read(id, count, 0, 0, 1, 42)), 0xc0000010, "directory handles cannot be read as file data");
    }
    static async Task RenameAccess(uint access, uint share)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var id = await Open(d, disposition: 3, access: access, share: share); await Write(d, id, Payload);
        var expected = (access & 0x10000) != 0 ? Ok : Denied;
        Status(await d.Send(Rename(id, "newname")), expected, "rename needs DELETE; own sharing mask does not bar it");
        await Data(d, id, Payload); await Close(d, id);
        await Data(d, await Open(d, expected == Ok ? "newname" : "file"), Payload);
        Status(await d.Send(Create(expected == Ok ? "file" : "newname")), Missing, "other pathname absent");
    }
    static async Task RenamePeer(uint peerAccess, uint peerShare)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var id = await Open(d, disposition: 3); await Write(d, id, Payload);
        // Source rename tests open rename owner first, then a peer that may deny
        // delete sharing. Share admission can reject the peer immediately.
        var attempt = await d.Send(Create(access: peerAccess, share: peerShare));
        if (peerShare == 3 && (peerAccess & 0x23) != 0)
        {
            Status(attempt, Sharing, "peer cannot deny existing DELETE access"); Status(await d.Send(Rename(id, "renamed")), Ok, "rejected peer leaves no reservation"); return;
        }
        var peer = Id(attempt); Status(await d.Send(Rename(id, "renamed")), Ok, "compatible/stat peer does not block rename");
        if ((peerAccess & 1) != 0) await Data(d, peer, Payload); await Data(d, id, Payload);
        Status(await d.Send(Create()), Missing, "old path absent after peer-visible rename");
    }
    static async Task DeleteCreate(uint disposition, bool exists)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        if (exists) { var seed = await Open(d, disposition: 3); await Write(d, seed, Payload); await Close(d, seed); }
        var b = Create(disposition: disposition); RawSmb.Put32(b, 104, 0x1040); var response = await d.Send(b);
        if (exists && disposition == 2)
        { Status(response, Collision, "failed CREATE cannot arm delete"); await Data(d, await Open(d), Payload); return; }
        var id = Id(response); var info = Output(await d.Send(Query(id, 5))); Check.Equal((byte)1, info[20], "DELETE_ON_CLOSE reflected before close");
        if (exists && disposition == 3) await Data(d, id, Payload);
        await Close(d, id); Status(await d.Send(Create()), Missing, "successful DELETE_ON_CLOSE removes object");
    }
    static async Task DeleteEnumerate()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var dir = await Open(d, "", directory: true); var id = await Open(d, disposition: 3);
        Status(await d.Send(Set(id, 13, [1])), Ok, "mark existing file for delete");
        var b = await d.Send(Enum(dir, "file")); Status(b, Ok, "pending object still enumerated until final close");
        var names = RawSmb.Buffer(b, RawSmb.U16(b, 66), RawSmb.U32(b, 68));
        Check.Equal(0u, RawSmb.U32(names, 0), "single pending filename record");
        Check.Equal("file", System.Text.Encoding.Unicode.GetString(names, 12, (int)RawSmb.U32(names, 8)), "pending filename");
        await Close(d, id); Status(await d.Send(Enum(dir, "file", 1)), 0xc000000f, "deleted filename no longer matches restart");
    }
    static async Task LeadingBackslash()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        Status(await d.Send(Create("\\directory", 3, directory: true)), Invalid, "CREATE names are relative to share");
        Check.That(!Directory.Exists(Path.Combine(root.Path, "directory")), "invalid leading slash creates no directory");
    }
    static async Task Impersonation()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var b = Create(disposition: 2); RawSmb.Put32(b, 68, 0x12345678);
        Status(await d.Send(b), 0xc00000a5, "invalid impersonation level"); Check.That(!File.Exists(Path.Combine(root.Path, "file")), "invalid impersonation cannot create file");
    }
    static async Task DirectoryDuplicate()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var a = await Open(d, "directory", 2, directory: true);
        Status(await d.Send(Create("directory", 2, directory: true)), Collision, "duplicate mkdir collision");
        var b = await Open(d, "directory", directory: true); Check.Equal((byte)1, Output(await d.Send(Query(b, 5)))[21], "directory visible through second open"); await Close(d, a); await Close(d, b);
    }
    static async Task DeleteOnly()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var seed = await Open(d, disposition: 3); await Write(d, seed, Payload); await Close(d, seed);
        var id = await Open(d, access: 0x10000); Status(await d.Send(Set(id, 13, [1])), Ok, "DELETE-only open can set disposition"); await Close(d, id); Status(await d.Send(Create()), Missing, "delete-only final close removes name");
    }
    static async Task ComposedNames()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        var a = await Open(d, "a\u0308", 2); var b = await Open(d, "\u00e4", 2); await Write(d, a, [1]); await Write(d, b, [2]); await Data(d, a, [1]); await Data(d, b, [2]);
    }
    static async Task DiacriticalNames()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        await Close(d, await Open(d, "\u0308", 2)); await Close(d, await Open(d, "\u0308\u0308", 2));
    }
    static async Task CloseLocks()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var a = await Open(d, disposition: 3); var b = await Open(d); var c = await Open(d);
        Status(await d.Send(Lock(a, 0, 4)), Ok, "first owner's lock"); Status(await d.Send(Lock(b, 8, 4)), Ok, "second owner's lock"); await Close(d, a);
        Status(await d.Send(Lock(c, 0, 4)), Ok, "close releases first range"); Status(await d.Send(Lock(c, 8, 4)), 0xc0000055, "close preserves other owner's range");
        await Close(d, b); Status(await d.Send(Lock(c, 8, 4)), Ok, "last blocker close releases second range");
    }
    static async Task ReopenLock()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var a = await Open(d, disposition: 3); var b = await Open(d);
        Status(await d.Send(Lock(a, 0, 4)), Ok, "owner lock"); Status(await d.Send(Lock(b, 0, 4, 4)), 0xc000007e, "same path/session is not lock ownership");
        Status(await d.Send(Lock(b, 0, 4)), 0xc0000055, "failed peer unlock preserves lock"); Status(await d.Send(Lock(a, 0, 4, 4)), Ok, "exact owner unlock");
    }
    static async Task QueryAccess(byte cls)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var seed = await Open(d, disposition: 3); await Write(d, seed, Payload); await Close(d, seed); var id = await Open(d, access: 1);
        // MS-SMB2 3.3.5.20.1: known unsupported classes retain the selected
        // NOT_SUPPORTED policy even on a READ_DATA-only open.
        var expected = cls is 4 or 18 or 34 or 35 ? Denied : cls is 16 or 17 ? 0xc00000bbu : Ok; Status(await d.Send(Query(id, cls)), expected, "MS-SMB2 QUERY_INFO class-specific access check");
        await Data(d, id, Payload); Status(await d.Send(RawSmb.Write(id, [99], 0, 0, 1, 42)), Denied, "query cannot enlarge original read-only access"); await Close(d, id);
    }
    static readonly Dictionary<byte, int> QuerySizes = new() { [4] = 40, [5] = 24, [6] = 8, [7] = 4, [14] = 8, [16] = 4, [17] = 4, [34] = 56, [35] = 8 };
    static async Task QueryBuffer(byte cls)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var id = await Open(d, disposition: 3); await Write(d, id, Payload); var size = QuerySizes[cls];
        if (cls is 16 or 17)
        {
            // MS-SMB2 3.3.5.20.1 selected known-class rejection precedes sizing.
            Status(await d.Send(Query(id, cls, (uint)size - 1)), 0xc00000bb, "unsupported class rejected with short allowance");
            Status(await d.Send(Query(id, cls, (uint)size)), 0xc00000bb, "larger allowance cannot falsely enable unsupported class"); await Data(d, id, Payload);
            await Close(d, id); id = await Open(d); await Data(d, id, Payload); await Close(d, id); return;
        }
        Status(await d.Send(Query(id, cls, (uint)size - 1)), 0xc0000004, "fixed FSCC record cannot be truncated");
        var bytes = Output(await d.Send(Query(id, cls, (uint)size))); Check.Equal(size, bytes.Length, "exact output allowance succeeds"); await Data(d, id, Payload);
    }
    static async Task OptionalIoctl(string shape)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var id = await Open(d, disposition: 3); await Write(d, id, Payload);
        var code = shape switch { "allocated-ranges" => 0x940cfu, "zero-data" => 0x980c8u, "compression" => 0x9c040u, "shadow-copies" => 0x144064u, _ => 0x900c4u };
        var input = shape switch { "sparse-empty" or "shadow-copies" => Array.Empty<byte>(), "sparse-oversize" => new byte[] { 1, 0, 0 }, "allocated-ranges" => new byte[16], "zero-data" => new byte[16], "compression" => new byte[2], _ => new byte[] { 1 } };
        if (shape == "allocated-ranges") RawSmb.Put64(input, 8, 4096); if (shape == "zero-data") RawSmb.Put64(input, 8, 1);
        var response = await d.Send(P5Tests.Ioctl(id, code, input, 1024));
        if (shape is "compression" or "shadow-copies")
            Check.That(RawSmb.U32(response, 8) is 0xc00000bb or 0xc0000010, "unsupported filesystem control rejects NOT_SUPPORTED or INVALID_DEVICE_REQUEST");
        else Status(response, 0xc00000bb, "optional unsupported FSCTL must reject explicitly");
        await Data(d, id, Payload);
    }
    static async Task TimeRoundtrip(long seconds)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var id = await Open(d, disposition: 3);
        var stamp = (ulong)DateTimeOffset.FromUnixTimeSeconds(seconds).UtcDateTime.ToFileTimeUtc(); var data = new byte[40]; RawSmb.Put64(data, 8, stamp); RawSmb.Put64(data, 16, stamp);
        Status(await d.Send(Set(id, 4, data)), Ok, "set representable explicit timestamp");
        foreach (var field in new[] { 8, 16 }) Check.Equal(stamp, RawSmb.U64(Output(await d.Send(Query(id, 4))), field), "explicit time_t vector exact readback");
    }
    static async Task RenameTimeClose()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var id = await Open(d, disposition: 3); await Write(d, id, Payload);
        var before = Output(await d.Send(Query(id, 4))); Status(await d.Send(Rename(id, "renamed")), Ok, "rename with live metadata");
        var after = Output(await d.Send(Query(id, 4))); Check.Equal(RawSmb.U64(before, 16), RawSmb.U64(after, 16), "rename preserves LastWriteTime");
        var close = RawSmb.Close(id, 0, 1, 42); RawSmb.Put16(close, 66, 1); var b = await d.Send(close); Status(b, Ok, "full CLOSE after rename");
        Check.Equal((ushort)1, RawSmb.U16(b, 66), "postquery flag"); Check.Equal((ulong)Payload.Length, RawSmb.U64(b, 112), "CLOSE live EOF");
        Check.Equal(RawSmb.U64(after, 16), RawSmb.U64(b, 88), "CLOSE LastWriteTime matches query");
    }
}
