using System.Text;
using Smb.Testing;

internal static class UpstreamCreateTests
{
    // Independent NTSTATUS/access/action values: MS-SMB2 2.2.13, 2.2.14;
    // MS-ERREF 2.3.1. No production enums, serializers or backend results form an oracle.
    const uint Success = 0x00000000, InvalidParameter = 0xc000000d;
    const uint NameNotFound = 0xc0000034, NameCollision = 0xc0000035;
    const uint SharingViolation = 0xc0000043, EndOfFile = 0xc0000011;
    const uint FileIsDirectory = 0xc00000ba, NotDirectory = 0xc0000103;
    const uint InfoLengthMismatch = 0xc0000004, FileClosed = 0xc0000128;
    const uint Read = 0x00000001, Write = 0x00000002, ReadWriteDelete = 0x00010083;
    static readonly byte[] Seed = "upstream-seed:ABCD"u8.ToArray();

    readonly record struct DispositionRow(string Name, uint Disposition, bool Exists,
        uint Status, uint Action, bool Preserve);

    // Samba create.c:test_smb2_open, open_funcs[] (all 14 rows).
    // https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/create.c#L704-L867
    // Action and nonempty-data assertions extend the upstream status table using
    // MS-SMB2 2.2.13/2.2.14, rather than inferring success from this server.
    static readonly DispositionRow[] Dispositions =
    [
        new("supersede.existing", 0, true,  Success,          0, false),
        new("supersede.missing",  0, false, Success,          2, false),
        new("open.existing",      1, true,  Success,          1, true),
        new("open.missing",       1, false, NameNotFound,     0, false),
        new("create.existing",    2, true,  NameCollision,    0, true),
        new("create.missing",     2, false, Success,          2, false),
        new("open-if.existing",   3, true,  Success,          1, true),
        new("open-if.missing",    3, false, Success,          2, false),
        new("overwrite.existing", 4, true,  Success,          3, false),
        new("overwrite.missing",  4, false, NameNotFound,     0, false),
        new("overwrite-if.existing", 5, true,  Success,       3, false),
        new("overwrite-if.missing",  5, false, Success,       2, false),
        new("invalid-6.existing", 6, true,  InvalidParameter, 0, true),
        new("invalid-6.missing",  6, false, InvalidParameter, 0, false),
    ];

    readonly record struct SemanticRow(string Name, char Kind, uint Disposition,
        uint Attributes, uint Options, uint Status);

    // Samba create.c:test_create_gentest: reserved options, DEVICE/VOLUME attrs,
    // and not_a_directory_mask. MS-SMB2 2.2.13 adds explicit incompatible flag
    // and directory-disposition combinations plus the inverse type mismatch.
    // https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/create.c#L135-L229
    static readonly SemanticRow[] Semantics =
    [
        new("reserved-options",    'f', 5, 0x80, 0xf0000040, InvalidParameter),
        new("device-attribute",    'f', 5, 0x40, 0x40,       InvalidParameter),
        new("volume-attribute",    'f', 5, 0x08, 0x40,       InvalidParameter),
        new("both-type-options",   'm', 3, 0x80, 0x41,       InvalidParameter),
        new("file-as-directory",   'f', 1, 0x10, 0x01,       NotDirectory),
        new("directory-as-file",   'd', 1, 0x80, 0x40,       FileIsDirectory),
        new("directory-overwrite", 'd', 4, 0x10, 0x01,       InvalidParameter),
    ];

    public static IEnumerable<(string Name, Func<Task> Run)> Cases()
    {
        foreach (var row in Dispositions)
            yield return ($"upstream.create.disposition.{row.Name}", () => DispositionAsync(row));
        foreach (var row in Semantics)
            yield return ($"upstream.create.semantic.{row.Name}", () => SemanticAsync(row));
        yield return ("upstream.create.share.existing-denies-write-retry", ShareDeniesWriteAsync);
        yield return ("upstream.create.share.new-denies-existing-read-retry", ReverseShareAsync);
        yield return ("upstream.create.share.delete-conflict-close-recreate", DeleteShareAsync);
        yield return ("upstream.create.rename.collision-replace-old-name-reuse", RenameCollisionAsync);
        yield return ("upstream.create.rename.nonzero-root-atomic-retry", () => InvalidRenameAsync(false));
        yield return ("upstream.create.rename.short-record-atomic-retry", () => InvalidRenameAsync(true));
        yield return ("upstream.create.delete.failed-create-does-not-arm", FailedDeleteCreateAsync);
        yield return ("upstream.create.delete.overwrite-if-close-stale-id-recreate", DeleteRecreateAsync);
    }

    static byte[] Create(WireClient c, string name, uint disposition = 1,
        uint access = ReadWriteDelete, uint share = 7, uint options = 0x40, uint attributes = 0x80)
    {
        var request = RawSmb.Create(name, false, c.NextMessageId(), c.Session, c.Tree);
        RawSmb.Put32(request, 88, access);
        RawSmb.Put32(request, 92, attributes);
        RawSmb.Put32(request, 96, share);
        RawSmb.Put32(request, 100, disposition);
        RawSmb.Put32(request, 104, options);
        return request;
    }

    static (ulong P, ulong V) Id(byte[] response)
    {
        Check.That(response.Length >= 152, "CREATE response contains complete fixed fields");
        return (RawSmb.U64(response, 128), RawSmb.U64(response, 136));
    }

    static Task<byte[]> CreateResponseAsync(WireClient c, byte[] request, uint status = Success)
        => c.ExchangeAsync(request, status, status == Success ? (ushort)89 : (ushort)9);

    static async Task<(ulong P, ulong V)> OpenAsync(WireClient c, string name,
        uint access = ReadWriteDelete, uint share = 7)
        => Id(await CreateResponseAsync(c, Create(c, name, access: access, share: share)));

    static async Task AssertDataAsync(WireClient c, (ulong P, ulong V) id, byte[] expected)
    {
        if (expected.Length == 0)
        {
            await c.ExchangeAsync(RawSmb.Read(id, 1, 0, c.NextMessageId(), c.Session, c.Tree), EndOfFile, 9);
            return;
        }
        var actual = await c.ReadAsync(id, (uint)expected.Length + 8);
        Check.That(actual.SequenceEqual(expected), "wire data equals independent payload, with no stale tail");
    }

    static void AssertFile(UpstreamLocalFixture fixture, string name, byte[] expected)
        => Check.That(NativeHost.ReadAllBytes(fixture.PathFor(name)).SequenceEqual(expected),
            "physical file bytes match independent payload");

    static void AssertMissing(UpstreamLocalFixture fixture, string name)
        => Check.That(!File.Exists(fixture.PathFor(name)) && !Directory.Exists(fixture.PathFor(name)),
            "operation leaves no file or directory at " + name);

    static async Task DispositionAsync(DispositionRow row)
    {
        await using var fixture = await UpstreamLocalFixture.StartAsync();
        if (row.Exists) File.WriteAllBytes(fixture.PathFor("subject"), Seed);
        await using var c = await fixture.ConnectAsync();
        var response = await CreateResponseAsync(c, Create(c, "subject", row.Disposition), row.Status);
        if (row.Status == Success)
        {
            var expected = row.Preserve ? Seed : Array.Empty<byte>();
            Check.Equal(row.Action, RawSmb.U32(response, 68), "CREATE action for " + row.Name);
            Check.Equal((ulong)expected.Length, RawSmb.U64(response, 112), "CREATE EOF for " + row.Name);
            var id = Id(response);
            await AssertDataAsync(c, id, expected);
            await c.CloseAsync(id);
            AssertFile(fixture, "subject", expected);
        }
        else
        {
            if (row.Exists) AssertFile(fixture, "subject", Seed);
            else AssertMissing(fixture, "subject");
            // A rejected disposition must leave neither a ghost object nor a
            // reservation that obstructs a later legitimate acquisition.
            var retry = await CreateResponseAsync(c, Create(c, "subject", row.Exists ? 1u : 2u));
            Check.Equal(row.Exists ? 1u : 2u, RawSmb.U32(retry, 68), "clean action after rejected CREATE");
            var id = Id(retry);
            await AssertDataAsync(c, id, row.Exists ? Seed : Array.Empty<byte>());
            await c.CloseAsync(id);
        }
    }

    static async Task SemanticAsync(SemanticRow row)
    {
        await using var fixture = await UpstreamLocalFixture.StartAsync();
        if (row.Kind == 'f') File.WriteAllBytes(fixture.PathFor("subject"), Seed);
        if (row.Kind == 'd')
        {
            Directory.CreateDirectory(fixture.PathFor("subject"));
            File.WriteAllBytes(Path.Combine(fixture.PathFor("subject"), "child"), Seed);
        }
        await using var c = await fixture.ConnectAsync();
        await CreateResponseAsync(c, Create(c, "subject", row.Disposition,
            options: row.Options, attributes: row.Attributes), row.Status);
        if (row.Kind == 'f') AssertFile(fixture, "subject", Seed);
        else if (row.Kind == 'd') AssertFile(fixture, Path.Combine("subject", "child"), Seed);
        else AssertMissing(fixture, "subject");

        var retry = await CreateResponseAsync(c, Create(c, "subject", row.Kind == 'm' ? 2u : 1u,
            options: row.Kind == 'd' ? 1u : 0x40u, attributes: row.Kind == 'd' ? 0x10u : 0x80u));
        Check.Equal(row.Kind == 'm' ? 2u : 1u, RawSmb.U32(retry, 68), "valid CREATE after semantic rejection");
        var id = Id(retry);
        if (row.Kind != 'd') await AssertDataAsync(c, id, row.Kind == 'f' ? Seed : Array.Empty<byte>());
        await c.CloseAsync(id);
    }

    // Samba sharemode.c:test_smb2_sharemode_access / test_smb2_access_sharemode.
    // https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/sharemode.c#L471-L631
    // Selected conflicting R/W/DELETE rows, extended with mutation/retry checks.
    // MS-SMB2 2.2.13 ShareAccess; MS-FSA 2.1.5.1.2 sharing-access checks.
    static async Task ShareDeniesWriteAsync()
    {
        await using var fixture = await UpstreamLocalFixture.StartAsync();
        File.WriteAllBytes(fixture.PathFor("subject"), Seed);
        await using var first = await fixture.ConnectAsync();
        await using var second = await fixture.ConnectAsync();
        var reader = await OpenAsync(first, "subject", Read, 1);
        var compatible = await OpenAsync(second, "subject", Read);
        await AssertDataAsync(second, compatible, Seed);
        await second.CloseAsync(compatible);
        await CreateResponseAsync(second, Create(second, "subject", 5, Write), SharingViolation);
        AssertFile(fixture, "subject", Seed);
        await AssertDataAsync(first, reader, Seed);
        await first.CloseAsync(reader);
        var retry = await CreateResponseAsync(second, Create(second, "subject", 5, Write));
        Check.Equal(3u, RawSmb.U32(retry, 68), "overwrite permitted after conflicting reader closes");
        Check.Equal(0ul, RawSmb.U64(retry, 112), "successful overwrite truncates only on retry");
        var writer = Id(retry);
        await second.WriteAsync(writer, "after-share-close"u8.ToArray());
        await second.CloseAsync(writer);
        AssertFile(fixture, "subject", "after-share-close"u8.ToArray());
    }

    static async Task ReverseShareAsync()
    {
        await using var fixture = await UpstreamLocalFixture.StartAsync();
        File.WriteAllBytes(fixture.PathFor("subject"), Seed);
        await using var first = await fixture.ConnectAsync();
        await using var second = await fixture.ConnectAsync();
        var reader = await OpenAsync(first, "subject", Read);
        // Existing open shares everything; the new open's share mode itself
        // conflicts with the first open's READ_DATA access.
        await CreateResponseAsync(second, Create(second, "subject", access: Read, share: 2), SharingViolation);
        await AssertDataAsync(first, reader, Seed);
        await first.CloseAsync(reader);
        var retry = await OpenAsync(second, "subject", Read, 2);
        await AssertDataAsync(second, retry, Seed);
        await second.CloseAsync(retry);
        AssertFile(fixture, "subject", Seed);
    }

    static async Task DeleteShareAsync()
    {
        await using var fixture = await UpstreamLocalFixture.StartAsync();
        File.WriteAllBytes(fixture.PathFor("subject"), Seed);
        await using var first = await fixture.ConnectAsync();
        await using var second = await fixture.ConnectAsync();
        var reader = await OpenAsync(first, "subject", Read, 3);
        await CreateResponseAsync(second, Create(second, "subject"), SharingViolation);
        await AssertDataAsync(first, reader, Seed);
        await first.CloseAsync(reader);
        var deleter = await OpenAsync(second, "subject");
        await second.ExchangeAsync(SetInfo(second, deleter, 13, [1]), size: 2);
        await second.CloseAsync(deleter);
        AssertMissing(fixture, "subject");
        var replacement = Id(await CreateResponseAsync(first, Create(first, "subject", 2)));
        await first.WriteAsync(replacement, "replacement"u8.ToArray());
        await first.CloseAsync(replacement);
        AssertFile(fixture, "subject", "replacement"u8.ToArray());
    }

    static byte[] SetInfo(WireClient c, (ulong P, ulong V) id, byte infoClass, byte[] data)
    {
        var request = RawSmb.Header(17, 32 + data.Length, c.NextMessageId(), c.Session, c.Tree);
        RawSmb.Put16(request, 64, 33);
        request[66] = 1;
        request[67] = infoClass;
        RawSmb.Put32(request, 68, (uint)data.Length);
        RawSmb.Put16(request, 72, 96);
        RawSmb.Put64(request, 80, id.P);
        RawSmb.Put64(request, 88, id.V);
        data.CopyTo(request, 96);
        return request;
    }

    // MS-FSCC 2.4.42.2 FILE_RENAME_INFORMATION_TYPE_2 has a 24-byte minimum,
    // including ignored padding; short target names must still be padded.
    static byte[] RenameData(string target, bool replace = false)
    {
        var name = Encoding.Unicode.GetBytes(target);
        var data = new byte[Math.Max(24, 20 + name.Length)];
        data[0] = replace ? (byte)1 : (byte)0;
        RawSmb.Put32(data, 16, (uint)name.Length);
        name.CopyTo(data, 20);
        return data;
    }

    // Samba rename.c:torture_smb2_rename_open, extended with collision/replacement
    // and reuse of the old name. MS-FSCC FileRenameInformation specifies collision
    // when ReplaceIfExists=FALSE; MS-FSA 2.1.5.15.12 covers replacement semantics.
    // https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/rename.c#L1690-L1768
    static async Task RenameCollisionAsync()
    {
        await using var fixture = await UpstreamLocalFixture.StartAsync();
        File.WriteAllBytes(fixture.PathFor("source"), "source-original"u8.ToArray());
        File.WriteAllBytes(fixture.PathFor("target"), "target-original"u8.ToArray());
        await using var first = await fixture.ConnectAsync();
        await using var second = await fixture.ConnectAsync();
        var source = await OpenAsync(first, "source");
        var peer = await OpenAsync(second, "source", Read | Write);
        await first.ExchangeAsync(SetInfo(first, source, 10, RenameData("target")), NameCollision, 9);
        AssertFile(fixture, "source", "source-original"u8.ToArray());
        AssertFile(fixture, "target", "target-original"u8.ToArray());
        await AssertDataAsync(second, peer, "source-original"u8.ToArray());
        await first.ExchangeAsync(SetInfo(first, source, 10, RenameData("target", true)), size: 2);
        AssertMissing(fixture, "source");
        await CreateResponseAsync(second, Create(second, "source", access: Read), NameNotFound);
        var recycled = Id(await CreateResponseAsync(second, Create(second, "source", 2)));
        await second.WriteAsync(recycled, "independent-old-name"u8.ToArray());
        await second.WriteAsync(peer, "source-modified"u8.ToArray());
        await AssertDataAsync(first, source, "source-modified"u8.ToArray());
        var target = await OpenAsync(first, "target", Read);
        await AssertDataAsync(first, target, "source-modified"u8.ToArray());
        await AssertDataAsync(second, recycled, "independent-old-name"u8.ToArray());
        await first.CloseAsync(target);
        await first.CloseAsync(source);
        await second.CloseAsync(peer);
        await second.CloseAsync(recycled);
        AssertFile(fixture, "target", "source-modified"u8.ToArray());
        AssertFile(fixture, "source", "independent-old-name"u8.ToArray());
    }

    // Microsoft FSA FileInfo_Set_FileRenameInformation.cs:
    // FileInfo_Set_FileRenameInformation_SMB2_RootDirectory_NonZero / _BufferSize.
    // https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileInformation/FileInfo_Set_FileRenameInformation.cs#L27-L140
    // The upstream _SeparatorCharacter case unconditionally marks itself
    // inconclusive and has conflicting commentary; it is deliberately excluded.
    // RootDirectory!=0 -> INVALID_PARAMETER; a record below the minimum ->
    // INFO_LENGTH_MISMATCH (MS-FSCC FileRenameInformation / MS-SMB2 3.3.5.21.1).
    static async Task InvalidRenameAsync(bool shortRecord)
    {
        await using var fixture = await UpstreamLocalFixture.StartAsync();
        File.WriteAllBytes(fixture.PathFor("source"), Seed);
        await using var c = await fixture.ConnectAsync();
        var source = await OpenAsync(c, "source");
        var data = RenameData("b");
        if (shortRecord)
        {
            // Complete fields and complete UTF-16 name, only required padding
            // is short. The enclosing SET_INFO buffer offset/length are valid.
            Array.Resize(ref data, 23);
        }
        else RawSmb.Put64(data, 8, 1);
        await c.ExchangeAsync(SetInfo(c, source, 10, data),
            shortRecord ? InfoLengthMismatch : InvalidParameter, 9);
        AssertFile(fixture, "source", Seed);
        AssertMissing(fixture, "b");
        await AssertDataAsync(c, source, Seed);
        await c.ExchangeAsync(SetInfo(c, source, 10, RenameData("b")), size: 2);
        AssertMissing(fixture, "source");
        await c.WriteAsync(source, "renamed-and-written"u8.ToArray());
        await c.CloseAsync(source);
        var reopened = await OpenAsync(c, "b", Read);
        await AssertDataAsync(c, reopened, "renamed-and-written"u8.ToArray());
        await c.CloseAsync(reopened);
        AssertFile(fixture, "b", "renamed-and-written"u8.ToArray());
    }

    // Samba delete-on-close.c:test_doc_create_exist: a colliding FILE_CREATE with
    // DELETE_ON_CLOSE must fail without arming deletion on the existing object.
    // https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/delete-on-close.c#L359-L410
    static async Task FailedDeleteCreateAsync()
    {
        await using var fixture = await UpstreamLocalFixture.StartAsync();
        File.WriteAllBytes(fixture.PathFor("subject"), Seed);
        await using var c = await fixture.ConnectAsync();
        await CreateResponseAsync(c, Create(c, "subject", 2, options: 0x1040), NameCollision);
        var id = await OpenAsync(c, "subject");
        await AssertDataAsync(c, id, Seed);
        var query = RawSmb.Header(16, 40, c.NextMessageId(), c.Session, c.Tree);
        RawSmb.Put16(query, 64, 41);
        query[66] = 1; // SMB2_0_INFO_FILE
        query[67] = 5; // FileStandardInformation, MS-FSCC 2.4.47
        RawSmb.Put32(query, 68, 24);
        RawSmb.Put64(query, 88, id.P);
        RawSmb.Put64(query, 96, id.V);
        var response = await c.ExchangeAsync(query, size: 9);
        var info = RawSmb.Buffer(response, RawSmb.U16(response, 66), RawSmb.U32(response, 68));
        Check.That(info.Length >= 24, "complete FILE_STANDARD_INFORMATION");
        Check.Equal((byte)0, info[20], "colliding CREATE did not mark DeletePending");
        await c.CloseAsync(id);
        AssertFile(fixture, "subject", Seed);
    }

    // Samba delete-on-close.c:test_doc_overwrite_if: newly created temporary
    // file disappears after CLOSE; extend with pathname reuse and stale CLOSE.
    // https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/delete-on-close.c#L199-L249
    // MS-SMB2 2.2.13 FILE_DELETE_ON_CLOSE and 3.3.5.10 invalid FileId handling.
    static async Task DeleteRecreateAsync()
    {
        await using var fixture = await UpstreamLocalFixture.StartAsync();
        await using var first = await fixture.ConnectAsync();
        await using var second = await fixture.ConnectAsync();
        var response = await CreateResponseAsync(first, Create(first, "subject", 5, options: 0x1040));
        Check.Equal(2u, RawSmb.U32(response, 68), "missing overwrite-if temporary file is CREATED");
        var temporary = Id(response);
        await first.WriteAsync(temporary, Seed);
        await first.CloseAsync(temporary);
        AssertMissing(fixture, "subject");
        await CreateResponseAsync(second, Create(second, "subject"), NameNotFound);
        var replacement = Id(await CreateResponseAsync(second, Create(second, "subject", 2)));
        await second.WriteAsync(replacement, "new-lifetime"u8.ToArray());
        await first.ExchangeAsync(RawSmb.Close(temporary, first.NextMessageId(), first.Session, first.Tree), FileClosed, 9);
        await AssertDataAsync(second, replacement, "new-lifetime"u8.ToArray());
        await second.CloseAsync(replacement);
        AssertFile(fixture, "subject", "new-lifetime"u8.ToArray());
    }
}
