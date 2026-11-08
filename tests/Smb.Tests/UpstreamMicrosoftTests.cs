using System.Text;
using Smb.FileSystem.Local;
using Smb.Protocol.Enums;
using Smb.Testing;

// Independent wire scenarios from WindowsProtocolTestSuites, pinned source and
// applicability are recorded in docs/correctness/upstream-microsoft-tests.md.
internal static partial class UpstreamMicrosoftTests
{
    const uint Success = 0, Invalid = 0xc000000d, LengthMismatch = 0xc0000004,
        Eof = 0xc0000011, Denied = 0xc0000022, Closed = 0xc0000128;

    public static IEnumerable<(string Name, Func<Task> Run)> Cases()
    {
        foreach (var c in new byte[] { 1, 2, 3, 37, 38 })
        {
            foreach (var p in new[] { "star", "star-dot-star", "question", "suffix", "dos-star", "dos-question", "dos-dot" })
                yield return ($"upstream.microsoft.directory.{c}.{p}", () => DirectoryPattern(c, p));
        }
        foreach (var c in new byte[] { 1, 2, 3, 12, 37, 38 })
        {
            yield return ($"upstream.microsoft.directory.{c}.metadata-single-pages", () => DirectoryMetadata(c));
            yield return ($"upstream.microsoft.directory.{c}.short-retry", () => DirectoryShortRetry(c));
        }
        foreach (var n in new[] { 0, 7 })
        {
            yield return ($"upstream.microsoft.set.eof-short-{n}", () => ShortSet(20, n));
            yield return ($"upstream.microsoft.set.position-short-{n}", () => ShortSet(14, n));
        }
        foreach (var n in new[] { 0, 35, 36, 39 })
            yield return ($"upstream.microsoft.set.basic-short-{n}", () => ShortSet(4, n));
        foreach (var field in new[] { 0, 8, 16, 24 })
            yield return ($"upstream.microsoft.metadata.invalid-time-{field}", () => InvalidTimestamp(field));
        foreach (var directory in new[] { false, true })
        {
            yield return ($"upstream.microsoft.metadata.zero-noop-{directory}", () => TimestampNoop(directory));
            foreach (var field in new[] { 8, 16 })
                yield return ($"upstream.microsoft.metadata.roundtrip-{directory}-{field}", () => TimestampRoundtrip(directory, field));
            yield return ($"upstream.microsoft.metadata.class-consistency-{directory}", () => MetadataConsistency(directory));
            yield return ($"upstream.microsoft.metadata.ea-size-{directory}", () => EaSize(directory));
        }
        yield return ("upstream.microsoft.metadata.freeze-last-write", FreezeWriteTime);
        foreach (var directory in new[] { false, true })
        {
            yield return ($"upstream.microsoft.metadata.modification-time-{directory}", () => ModificationTime(directory));
            yield return ($"upstream.microsoft.metadata.creation-time-stable-{directory}", () => CreationStable(directory));
        }
        yield return ("upstream.microsoft.metadata.all-access-read-open", AllAccess);
        yield return ("upstream.microsoft.metadata.stream-list-mutation", Streams);
        yield return ("upstream.microsoft.metadata.ea-replace-delete", EaReplaceDelete);
        foreach (var flags in new[] { false, true })
            yield return ($"upstream.microsoft.metadata.ea-invalid-{flags}", () => InvalidEa(flags));
        yield return ("upstream.microsoft.io.truncate-extend-peer", ResizePeer);
        yield return ("upstream.microsoft.io.sparse-write-hole", Hole);
        yield return ("upstream.microsoft.io.zero-write-no-extension", ZeroWrite);
        yield return ("upstream.microsoft.io.append-only-at-eof", AppendOnly);
        yield return ("upstream.microsoft.io.append-sentinel", AppendSentinel);
        yield return ("upstream.microsoft.io.flush-close-reopen", FlushReopen);
        yield return ("upstream.microsoft.io.eof-directory", DirectoryEof);
        yield return ("upstream.microsoft.io.eof-readonly-open", ReadOnlyEof);
        yield return ("upstream.microsoft.io.position-negative", NegativePosition);
        yield return ("upstream.microsoft.io.large-transfer-tail", LargeTransfer);
        foreach (var kind in new[] { "read-negative-zero", "read-negative-data", "read-overflow", "write-overflow" })
            yield return ("upstream.microsoft.io." + kind, () => OffsetBounds(kind));
        yield return ("upstream.microsoft.notify.non-directory", NotifyFile);
        yield return ("upstream.microsoft.notify.no-list-access", NotifyAccess);
        foreach (var dialect in new[] { SmbDialect.Smb202, SmbDialect.Smb210, SmbDialect.Smb300, SmbDialect.Smb302, SmbDialect.Smb311 })
            yield return ($"upstream.microsoft.query.normalized-unsupported-{(ushort)dialect:x}", () => NormalizedName(dialect));
        foreach (var test in AuthCases()) yield return test;
        foreach (var test in CompressionCases()) yield return test;
        foreach (var test in NamespaceCases()) yield return test;
        foreach (var test in ContextCases()) yield return test;
        foreach (var test in ModelCases()) yield return test;
        foreach (var test in AdditionalCases()) yield return test;
    }

    // FSA QueryDirectory_FileNameInExpression_*: same expressions, five additional
    // FSCC layouts. NamesInformation already exists in UpstreamStateTests.
    static (string Pattern, string[] Names, string[] Expected) Pattern(string kind) => kind switch
    {
        "star" => ("*", ["Fine", "File", "Bile", "Fille", "Nine"], [".", "..", "Fine", "File", "Bile", "Fille", "Nine"]),
        "star-dot-star" => ("*.*", ["Fine", "File.txt", "Bile", "Fille.log", "Nine"], [".", "..", "Fine", "File.txt", "Bile", "Fille.log", "Nine"]),
        "question" => ("Fi?e", ["Fine", "File", "Bile", "Fille", "Nine"], ["Fine", "File"]),
        "suffix" => ("*ile", ["Fine", "File", "Bile", "Fille", "Nine"], ["File", "Bile"]),
        "dos-star" => ("<txt", ["Fine.txt", "FileGrip.txt", "Bile.txt", "Tile.txt", "Nine.jpg"], ["Fine.txt", "FileGrip.txt", "Bile.txt", "Tile.txt"]),
        "dos-question" => ("Fi>e", ["Fine", "File", "Bile", "Fille", "Nine"], ["Fine", "File"]),
        _ => ("grcBlankFile?\"", ["grcBlankFile1", "grcBlankFile2", "grcBlankFile3", "grc.BadFile_1.txt"], ["grcBlankFile1", "grcBlankFile2", "grcBlankFile3"])
    };

    static async Task DirectoryPattern(byte cls, string kind)
    {
        using var root = new Root(); var p = Pattern(kind);
        Directory.CreateDirectory(root.At("scan"));
        foreach (var name in p.Names) File.WriteAllText(root.At("scan", name), "");
        await using var d = root.Direct(); var id = await Open(d, "scan", true);
        var names = await Scan(d, id, cls, p.Pattern, 1);
        Names(p.Expected, names, "wildcard set independent of filesystem ordering");
        Names(p.Expected, await Scan(d, id, cls, p.Pattern, 16), "reopen resets layout and pattern cursor");
    }

    static async Task DirectoryMetadata(byte cls)
    {
        using var root = new Root(); Directory.CreateDirectory(root.At("scan"));
        File.WriteAllBytes(root.At("scan", "alpha"), [1, 2, 3]);
        Directory.CreateDirectory(root.At("scan", "folder"));
        await using var d = root.Direct(); var id = await Open(d, "scan", true);
        var found = new List<string>(); var stableIds = new Dictionary<string, ulong>();
        for (var i = 0; i < 8; i++)
        {
            var response = await d.Send(Enum(id, cls, i == 0 ? "*" : "", 2, 4096));
            if (RawSmb.U32(response, 8) == 0x80000006) break;
            Status(response, 0, "single-entry directory page"); var data = Output(response);
            var entries = ParseDirectory(data, cls); Check.Equal(1, entries.Count, "RETURN_SINGLE_ENTRY");
            var entry = entries.Single(); found.Add(entry.Name);
            if (cls != 12)
            {
                Check.That(RawSmb.U64(data, 8) > 0 && RawSmb.U64(data, 24) > 0, "nonzero creation/write timestamps");
                if (entry.Name == "alpha") Check.Equal(3ul, RawSmb.U64(data, 40), "enumeration reports known EOF");
                if (entry.Name == "folder") Check.That((RawSmb.U32(data, 56) & 16) != 0, "directory attribute");
                if (cls is 37 or 38) stableIds[entry.Name] = RawSmb.U64(data, cls == 37 ? 96 : 72);
                if (cls is 3 or 37) Check.Equal((byte)0, data[68], "no invented short name");
            }
        }
        Names([".", "..", "alpha", "folder"], found, "all single-entry pages exactly once");
        Status(await d.Send(Enum(id, cls, "", 0, 4096)), 0x80000006, "stable exhaustion");
        if (cls is 37 or 38)
        {
            var response = await d.Send(Enum(id, cls, "alpha", 1, 4096)); Status(response, 0, "restart exact name");
            Check.Equal(stableIds["alpha"], RawSmb.U64(Output(response), cls == 37 ? 96 : 72), "ID stable across restart");
        }
    }

    static async Task DirectoryShortRetry(byte cls)
    {
        using var root = new Root(); Directory.CreateDirectory(root.At("scan")); File.WriteAllText(root.At("scan", "only"), "x");
        await using var d = root.Direct(); var id = await Open(d, "scan", true);
        // Fixed fields are insufficient for even one complete UTF-16 name.
        Status(await d.Send(Enum(id, cls, "only", 1, (uint)NameOffset(cls))), LengthMismatch, "short page rejected");
        var response = await d.Send(Enum(id, cls, "", 0, (uint)(NameOffset(cls) + 8)));
        Status(response, 0, "exact record retry retains first entry");
        Names(["only"], ParseDirectory(Output(response), cls).Select(e => e.Name), "failed page cannot consume cursor");
        Status(await d.Send(Enum(id, cls, "", 0, 4096)), 0x80000006, "one successful retry consumed one record");
    }

    static int NameOffset(byte cls) => cls switch { 1 => 64, 2 => 68, 3 => 94, 12 => 12, 37 => 104, 38 => 80, _ => throw new ArgumentException() };
    static List<(string Name, int At)> ParseDirectory(byte[] data, byte cls)
    {
        var names = new List<(string, int)>(); var at = 0; var fixedSize = NameOffset(cls);
        while (true)
        {
            Check.That(at + fixedSize <= data.Length, "directory fixed fields bounded");
            var length = RawSmb.U32(data, at + (cls == 12 ? 8 : 60));
            Check.That((length & 1) == 0 && (ulong)(at + fixedSize) + length <= (ulong)data.Length, "UTF16 name bounded");
            names.Add((Encoding.Unicode.GetString(data, at + fixedSize, (int)length), at));
            var next = RawSmb.U32(data, at); if (next == 0) return names;
            Check.That((next & 7) == 0 && next >= fixedSize + length, "aligned progressing chain"); at += checked((int)next);
        }
    }
    static async Task<List<string>> Scan(P2Tests.Direct d, (ulong P, ulong V) id, byte cls, string pattern, byte flags)
    {
        var names = new List<string>();
        for (var i = 0; i < 32; i++)
        {
            var b = await d.Send(Enum(id, cls, i == 0 ? pattern : "", i == 0 ? flags : (byte)0, 240));
            if (RawSmb.U32(b, 8) == 0x80000006) return names;
            Status(b, 0, "bounded directory progress"); var page = ParseDirectory(Output(b), cls);
            Check.That(page.Count > 0, "nonempty successful page"); names.AddRange(page.Select(e => e.Name));
        }
        throw new InvalidOperationException("directory failed to terminate");
    }

    // FSAModel SetFile{Basic,EndOfFile,Position}Information and FSA timestamp tests.
    static async Task ShortSet(byte cls, int size)
    {
        using var root = new Root(); File.WriteAllBytes(root.At("data"), [1, 2, 3]);
        await using var d = root.Direct(); var id = await Open(d, "data");
        Status(await d.Send(Set(id, cls, new byte[size])), LengthMismatch, "FSCC fixed SET record minimum");
        Check.That(File.ReadAllBytes(root.At("data")).SequenceEqual(new byte[] { 1, 2, 3 }), "rejected SET preserves bytes");
        Status(await d.Send(Set(id, 20, U64(2))), 0, "valid EOF retry on same handle");
        Check.Equal(2L, new FileInfo(root.At("data")).Length, "valid retry mutates EOF");
    }
    static async Task InvalidTimestamp(int field)
    {
        using var root = new Root(); await using var d = root.Direct(); var id = await Open(d, "data");
        var before = Output(await Query(d, id, 4, 40)); var data = new byte[40]; RawSmb.Put64(data, field, unchecked((ulong)-3L));
        Status(await d.Send(Set(id, 4, data)), Invalid, "timestamp below -2 is invalid before backend mutation");
        var after = Output(await Query(d, id, 4, 40));
        Check.That(before.SequenceEqual(after), "invalid timestamp leaves all metadata unchanged");
    }
    static async Task TimestampNoop(bool directory)
    {
        using var root = new Root(); if (directory) Directory.CreateDirectory(root.At("data"));
        await using var d = root.Direct(); var id = await Open(d, "data", directory);
        var before = Output(await Query(d, id, 4, 40));
        Status(await d.Send(Set(id, 4, new byte[40])), 0, "zero timestamps leave attributes alone");
        var after = Output(await Query(d, id, 4, 40));
        Check.That(before.AsSpan(0, 24).SequenceEqual(after.AsSpan(0, 24)), "creation/access/write unchanged");
        Check.Equal(RawSmb.U32(before, 32), RawSmb.U32(after, 32), "attributes unchanged");
    }
    static async Task TimestampRoundtrip(bool directory, int field)
    {
        using var root = new Root(); if (directory) Directory.CreateDirectory(root.At("data"));
        await using var d = root.Direct(); var id = await Open(d, "data", directory);
        var value = (ulong)new DateTime(2020, 2, 3, 4, 5, 6, DateTimeKind.Utc).ToFileTimeUtc();
        var data = new byte[40]; RawSmb.Put64(data, field, value); Status(await d.Send(Set(id, 4, data)), 0, "portable explicit host timestamp");
        Check.Equal(value, RawSmb.U64(Output(await Query(d, id, 4, 40)), field), "wire timestamp exact roundtrip");
        var peer = await Open(d, "data", directory);
        Check.Equal(value, RawSmb.U64(Output(await Query(d, peer, 34, 56)), field), "peer network info sees timestamp");
    }
    static async Task MetadataConsistency(bool directory)
    {
        using var root = new Root(); if (directory) Directory.CreateDirectory(root.At("data")); else File.WriteAllBytes(root.At("data"), [7, 8, 9]);
        await using var d = root.Direct(); var id = await Open(d, "data", directory);
        var basic = Output(await Query(d, id, 4, 40)); var standard = Output(await Query(d, id, 5, 24));
        var all = Output(await Query(d, id, 18, 512)); var net = Output(await Query(d, id, 34, 56));
        Check.That(basic.SequenceEqual(all.AsSpan(0, 40).ToArray()), "all contains basic record");
        Check.That(standard.SequenceEqual(all.AsSpan(40, 24).ToArray()), "all contains standard record");
        Check.That(basic.AsSpan(0, 32).SequenceEqual(net.AsSpan(0, 32)), "network timestamps agree");
        Check.Equal(RawSmb.U32(basic, 32), RawSmb.U32(net, 48), "network attributes agree");
        Check.Equal((byte)(directory ? 1 : 0), standard[21], "standard directory bit");
        if (!directory) { Check.Equal(3ul, RawSmb.U64(standard, 8), "known data EOF"); Check.Equal(3ul, RawSmb.U64(net, 40), "network EOF"); }
        var peer = await Open(d, "data", directory);
        Check.Equal(RawSmb.U64(all, 64), RawSmb.U64(Output(await Query(d, peer, 6, 8)), 0), "identity stable through different info classes and opens");
    }
    static async Task AllAccess()
    {
        using var root = new Root(); File.WriteAllText(root.At("data"), "x");
        await using var d = root.Direct(); var id = await Open(d, "data", access: 0x81);
        Check.Equal(0x81u, RawSmb.U32(Output(await Query(d, id, 18, 512)), 76), "FileAllInformation reports this open's actual granted access");
    }
    static async Task EaSize(bool directory)
    {
        using var root = new Root(); if (directory) Directory.CreateDirectory(root.At("data"));
        await using var d = root.Direct(); var id = await Open(d, "data", directory, 0x1019b);
        var ea = new byte[] { 0, 0, 0, 0, 0, 3, 2, 0, (byte)'k', (byte)'e', (byte)'y', 0, 7, 8 };
        Status(await d.Send(Set(id, 15, ea)), 0, "SET FullEa wire record");
        Check.That(RawSmb.U32(Output(await Query(d, id, 7, 4)), 0) > 0, "EA-capable store reports nonzero EaSize after successful SET");
        var queried = Output(await Query(d, id, 15, 4096));
        Check.That(queried.SequenceEqual(ea), "complete EA name/value roundtrip");
    }
    static async Task FreezeWriteTime()
    {
        using var root = new Root(); await using var d = root.Direct(); var id = await Open(d, "data");
        var stamp = (ulong)new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc).ToFileTimeUtc(); var basic = new byte[40];
        RawSmb.Put64(basic, 16, stamp); Status(await d.Send(Set(id, 4, basic)), 0, "set distinct old write time");
        RawSmb.Put64(basic, 16, ulong.MaxValue); Status(await d.Send(Set(id, 4, basic)), 0, "-1 suppresses updates on this open");
        await Write(d, id, [42], 0); Status(await d.Send(Flush(id)), 0, "flush write before timestamp query");
        Check.Equal(stamp, RawSmb.U64(Output(await Query(d, id, 4, 40)), 16), "-1 preserves write timestamp through data write");
    }
    static async Task ModificationTime(bool directory)
    {
        using var root = new Root(); if (directory) Directory.CreateDirectory(root.At("data"));
        await using var d = root.Direct(); var id = await Open(d, "data", directory);
        var oldTime = (ulong)new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc).ToFileTimeUtc(); var basic = new byte[40]; RawSmb.Put64(basic, 16, oldTime);
        Status(await d.Send(Set(id, 4, basic)), 0, "seed independently old modification time without sleeps");
        if (directory) { var child = await Open(d, "data\\child"); Status(await d.Send(RawSmb.Close(child, 0, 1, 42)), 0, "close created child"); }
        else { await Write(d, id, [42], 0); Status(await d.Send(Flush(id)), 0, "flush ordinary write"); }
        Status(await d.Send(RawSmb.Close(id, 0, 1, 42)), 0, "close permits deferred timestamp update");
        var reopened = await Open(d, "data", directory); var info = Output(await Query(d, reopened, 4, 40));
        Check.That(RawSmb.U64(info, 16) > oldTime, "normal mutation updates LastWriteTime after close");
    }
    static async Task CreationStable(bool directory)
    {
        using var root = new Root(); if (directory) Directory.CreateDirectory(root.At("data"));
        await using var d = root.Direct(); var id = await Open(d, "data", directory); var before = Output(await Query(d, id, 4, 40));
        if (directory) { var child = await Open(d, "data\\child"); Status(await d.Send(RawSmb.Close(child, 0, 1, 42)), 0, "close child"); }
        else { await Write(d, id, [7, 8, 9], 0); Status(await d.Send(Flush(id)), 0, "flush data write"); }
        var after = Output(await Query(d, id, 4, 40));
        Check.Equal(RawSmb.U64(before, 0), RawSmb.U64(after, 0), "creation time is not an automatic access/write timestamp");
    }
    static async Task Streams()
    {
        using var root = new Root(); await using var d = root.Direct(); var id = await Open(d, "data");
        await Write(d, id, [1, 2, 3], 0); var a = await Open(d, "data:alpha:$DATA"); var b = await Open(d, "data:beta:$DATA");
        await Write(d, a, [4, 5], 0); await Write(d, b, [6, 7, 8, 9], 0);
        StreamSet(Output(await Query(d, id, 22, 4096)), new() { ["::$DATA"] = 3, [":alpha:$DATA"] = 2, [":beta:$DATA"] = 4 });
        Status(await d.Send(Set(a, 20, U64(1))), 0, "truncate one named stream");
        StreamSet(Output(await Query(d, b, 22, 4096)), new() { ["::$DATA"] = 3, [":alpha:$DATA"] = 1, [":beta:$DATA"] = 4 });
        var streamStandard = Output(await Query(d, a, 5, 24)); Check.Equal(1ul, RawSmb.U64(streamStandard, 8), "stream standard EOF after truncate");
        Check.Equal((byte)0, streamStandard[21], "named data stream is not a directory");
        Check.Equal(4ul, RawSmb.U64(Output(await Query(d, b, 34, 56)), 40), "stream network EOF independent of base size");
        var baseBasic = Output(await Query(d, id, 4, 40)); var streamBasic = Output(await Query(d, a, 4, 40));
        Check.Equal(RawSmb.U32(baseBasic, 32), RawSmb.U32(streamBasic, 32), "streams share base file attributes");
        await ReadEquals(d, id, [1, 2, 3]); await ReadEquals(d, a, [4]); await ReadEquals(d, b, [6, 7, 8, 9]);
    }
    static byte[] EaRecord(string name, byte[] value)
    {
        var bytes = Encoding.ASCII.GetBytes(name); var b = new byte[9 + bytes.Length + value.Length]; b[5] = (byte)bytes.Length;
        RawSmb.Put16(b, 6, (ushort)value.Length); bytes.CopyTo(b, 8); value.CopyTo(b, 9 + bytes.Length); return b;
    }
    static async Task EaReplaceDelete()
    {
        using var root = new Root(); await using var d = root.Direct(); var id = await Open(d, "data", access: 0x1019b);
        Status(await d.Send(Set(id, 15, EaRecord("alpha", [1]))), 0, "add first EA");
        Status(await d.Send(Set(id, 15, EaRecord("beta", [2]))), 0, "add second EA");
        Status(await d.Send(Set(id, 15, EaRecord("alpha", [3, 4]))), 0, "replace EA value without replacing unrelated attributes");
        var peer = await Open(d, "data", access: 0x1019b); var eas = ParseEas(Output(await Query(d, peer, 15, 4096)));
        Names(["alpha", "beta"], eas.Keys, "EA replacement retains other names"); Check.That(eas["alpha"].SequenceEqual(new byte[] { 3, 4 }) && eas["beta"].SequenceEqual(new byte[] { 2 }), "known replacement values");
        Status(await d.Send(Set(id, 15, EaRecord("alpha", []))), 0, "zero value deletes existing EA");
        peer = await Open(d, "data", access: 0x1019b); eas = ParseEas(Output(await Query(d, peer, 15, 4096)));
        Names(["beta"], eas.Keys, "delete only selected EA"); Check.That(eas["beta"].SequenceEqual(new byte[] { 2 }), "unrelated EA value retained");
    }
    static async Task InvalidEa(bool flags)
    {
        using var root = new Root(); await using var d = root.Direct(); var id = await Open(d, "data", access: 0x1019b);
        Status(await d.Send(Set(id, 15, EaRecord("good", [42]))), 0, "seed EA before invalid update");
        var invalid = EaRecord(flags ? "good" : "+<", [7]); if (flags) invalid[4] = 255;
        Status(await d.Send(Set(id, 15, invalid)), 0xc0000054, "FSAModel invalid EA name/flags return INVALID_EA_NAME");
        var eas = ParseEas(Output(await Query(d, id, 15, 4096))); Names(["good"], eas.Keys, "invalid EA update atomic");
        Check.That(eas["good"].SequenceEqual(new byte[] { 42 }), "original EA value preserved");
    }
    static Dictionary<string, byte[]> ParseEas(byte[] data)
    {
        var eas = new Dictionary<string, byte[]>(StringComparer.Ordinal); var at = 0;
        while (true)
        {
            Check.That(at + 8 <= data.Length, "EA fixed record bounded"); var nameLength = data[at + 5]; var valueLength = RawSmb.U16(data, at + 6);
            Check.That(at + 9 + nameLength + valueLength <= data.Length && data[at + 8 + nameLength] == 0, "EA buffers and NUL bounded");
            Check.That(eas.TryAdd(Encoding.ASCII.GetString(data, at + 8, nameLength), data.AsSpan(at + 9 + nameLength, valueLength).ToArray()), "unique EA names");
            var next = RawSmb.U32(data, at); if (next == 0) return eas;
            Check.That((next & 3) == 0 && next >= 9 + nameLength + valueLength, "EA next record aligned and progressing"); at += (int)next;
        }
    }
    static void StreamSet(byte[] data, Dictionary<string, ulong> expected)
    {
        var seen = new Dictionary<string, ulong>(); var at = 0;
        while (true)
        {
            Check.That(at + 24 <= data.Length, "stream fixed record bounded"); var length = RawSmb.U32(data, at + 4);
            Check.That((length & 1) == 0 && (ulong)at + 24 + length <= (ulong)data.Length, "stream name bounded");
            var name = Encoding.Unicode.GetString(data, at + 24, (int)length); Check.That(seen.TryAdd(name, RawSmb.U64(data, at + 8)), "unique stream");
            var next = RawSmb.U32(data, at); if (next == 0) break;
            Check.That((next & 7) == 0 && next >= 24 + length, "stream chain aligned"); at += checked((int)next);
        }
        Names(expected.Keys, seen.Keys, "independent stream names"); foreach (var e in expected) Check.Equal(e.Value, seen[e.Key], "stream EOF " + e.Key);
    }

    static async Task ResizePeer()
    {
        using var root = new Root(); await using var d = root.Direct(); var id = await Open(d, "data"); var peer = await Open(d, "data");
        await Write(d, id, [1, 2, 3, 4, 5, 6], 0);
        Status(await d.Send(Set(id, 20, U64(3))), 0, "truncate"); await ReadEquals(d, peer, [1, 2, 3]);
        Status(await d.Send(RawSmb.Read(peer, 1, 3, 0, 1, 42)), Eof, "peer sees truncated EOF");
        Status(await d.Send(Set(peer, 20, U64(8))), 0, "extend"); await ReadEquals(d, id, [1, 2, 3, 0, 0, 0, 0, 0]);
        Check.Equal(8ul, RawSmb.U64(Output(await Query(d, id, 5, 24)), 8), "query EOF after extension");
        Status(await d.Send(Set(id, 20, U64(0))), 0, "truncate to zero");
        Status(await d.Send(RawSmb.Read(peer, 1, 0, 0, 1, 42)), Eof, "zero EOF");
        Status(await d.Send(Set(id, 20, U64(6))), 0, "regrow truncated data"); await ReadEquals(d, peer, new byte[6]);
    }
    static async Task Hole()
    {
        using var root = new Root(); await using var d = root.Direct(); var id = await Open(d, "data");
        await Write(d, id, [0xaa, 0xbb], 8193); var expected = new byte[8195]; expected[8193] = 0xaa; expected[8194] = 0xbb;
        await ReadEquals(d, id, expected); Check.Equal(8195ul, RawSmb.U64(Output(await Query(d, id, 34, 56)), 40), "hole write EOF");
    }
    static async Task ZeroWrite()
    {
        using var root = new Root(); await using var d = root.Direct(); var id = await Open(d, "data"); await Write(d, id, [1, 2, 3], 0);
        foreach (var offset in new ulong[] { 0, 2, 8193 })
        {
            await Write(d, id, [], offset); Check.Equal(3ul, RawSmb.U64(Output(await Query(d, id, 5, 24)), 8), "zero write never extends EOF");
            await ReadEquals(d, id, [1, 2, 3]);
        }
    }
    static async Task AppendOnly()
    {
        using var root = new Root(); File.WriteAllBytes(root.At("data"), [1, 2, 3]);
        await using var d = root.Direct(); var appender = await Open(d, "data", access: 4); var reader = await Open(d, "data", access: 1);
        // MS-SMB2 passes the absolute wire offset to MS-FSA; local NtWriteFile's
        // implicit append positioning is not an SMB2 wire requirement.
        await Write(d, appender, [4, 5], 3); await ReadEquals(d, reader, [1, 2, 3, 4, 5]);
        await Write(d, appender, [6], 5); await ReadEquals(d, reader, [1, 2, 3, 4, 5, 6]);
    }
    static async Task AppendSentinel()
    {
        using var root = new Root(); await using var d = root.Direct(); var id = await Open(d, "data"); await Write(d, id, [1, 2, 3], 0);
        // MS-FSA 2.1.5.4 interprets negative ByteOffset at EOF; MS-SMB2's Windows
        // mapping passes ByteOffset through. This is a product-behavior adaptation.
        await Write(d, id, [4, 5], ulong.MaxValue); await ReadEquals(d, id, [1, 2, 3, 4, 5]);
    }
    static async Task FlushReopen()
    {
        using var root = new Root(); await using var d = root.Direct(); var id = await Open(d, "data"); await Write(d, id, [7, 8, 9], 0);
        Status(await d.Send(Flush(id)), 0, "FLUSH real store"); Status(await d.Send(Flush(id)), 0, "repeat FLUSH");
        Status(await d.Send(RawSmb.Close(id, 0, 1, 42)), 0, "CLOSE after FLUSH");
        Status(await d.Send(Flush(id)), Closed, "stale FLUSH does not reuse closed handle");
        var reopened = await Open(d, "data"); await ReadEquals(d, reopened, [7, 8, 9]);
        Check.That(File.ReadAllBytes(root.At("data")).SequenceEqual(new byte[] { 7, 8, 9 }), "host corroborates flushed bytes, no crash durability claim");
    }
    static async Task DirectoryEof()
    {
        using var root = new Root(); Directory.CreateDirectory(root.At("data")); await using var d = root.Direct(); var id = await Open(d, "data", true);
        Status(await d.Send(Set(id, 20, U64(1))), Invalid, "EOF is invalid for directory stream");
    }
    static async Task ReadOnlyEof()
    {
        using var root = new Root(); File.WriteAllBytes(root.At("data"), [1, 2, 3]); await using var d = root.Direct(); var id = await Open(d, "data", access: 1);
        Status(await d.Send(Set(id, 20, U64(0))), Denied, "EOF requires write data"); await ReadEquals(d, id, [1, 2, 3]);
    }
    static async Task NegativePosition()
    {
        using var root = new Root(); await using var d = root.Direct(); var id = await Open(d, "data");
        Status(await d.Send(Set(id, 14, U64(ulong.MaxValue))), Invalid, "negative file position is invalid even on async open");
    }
    static async Task LargeTransfer()
    {
        await using var host = await UpstreamLocalFixture.StartAsync(); await using var c = await AuthWire.Connect(host.Server.Endpoint);
        await c.Negotiate(0x210); await c.Login();
        var response = await c.Exchange(RawSmb.TreeConnect("\\\\localhost\\P0", 0, c.Session), 0, true); var tree = RawSmb.U32(response, 36);
        response = await c.Exchange(RawSmb.Create("large", false, 0, c.Session, tree), 0, true); var id = (RawSmb.U64(response, 128), RawSmb.U64(response, 136));
        var expected = Enumerable.Range(0, 1048576).Select(i => (byte)((i * 17 + i / 251) & 255)).ToArray();
        var write = RawSmb.Write(id, expected, 0, 0, c.Session, tree); RawSmb.Put16(write, 6, 16);
        response = await c.Exchange(write, 0, true); Check.Equal(1048576u, RawSmb.U32(response, 68), "large negotiated write count");
        var read = RawSmb.Read(id, 1048576, 0, 0, c.Session, tree, 1048576); RawSmb.Put16(read, 6, 16);
        response = await c.Exchange(read, 0, true); Check.That(expected.SequenceEqual(ReadData(response)), "large read exact independent payload");
        response = await c.Exchange(RawSmb.Read(id, 17, 1048570, 0, c.Session, tree), 0, true);
        Check.That(expected.AsSpan(1048570).SequenceEqual(ReadData(response)), "short final six-byte tail");
        await c.Exchange(RawSmb.Close(id, 0, c.Session, tree), 0, true);
    }
    static async Task NotifyFile()
    {
        using var root = new Root(); await using var d = root.Direct(); var id = await Open(d, "data");
        Status(await d.Send(P4Tests.Notify(id)), Invalid, "CHANGE_NOTIFY requires directory");
    }
    static async Task OffsetBounds(string kind)
    {
        using var root = new Root(); File.WriteAllBytes(root.At("data"), [42]); await using var d = root.Direct(); var id = await Open(d, "data");
        var request = kind switch
        {
            "read-negative-zero" => RawSmb.Read(id, 0, ulong.MaxValue, 0, 1, 42),
            "read-negative-data" => RawSmb.Read(id, 1, ulong.MaxValue, 0, 1, 42),
            "read-overflow" => RawSmb.Read(id, 2, long.MaxValue, 0, 1, 42),
            _ => RawSmb.Write(id, [7, 8], long.MaxValue, 0, 1, 42)
        };
        Status(await d.Send(request), Invalid, "MS-FSA signed byte offset/range cannot be negative or overflow MAXLONGLONG");
        await ReadEquals(d, id, [42]);
    }
    static async Task NotifyAccess()
    {
        using var root = new Root(); Directory.CreateDirectory(root.At("data")); await using var d = root.Direct(); var id = await Open(d, "data", true, 0x80);
        Status(await d.Send(P4Tests.Notify(id)), Denied, "CHANGE_NOTIFY requires FILE_LIST_DIRECTORY");
    }
    static async Task NormalizedName(SmbDialect dialect)
    {
        using var root = new Root(); await using var d = root.Direct(); d.Connection.Dialect = dialect; var id = await Open(d, "data");
        var b = RawSmb.Header(16, 40, 0, 1, 42); RawSmb.Put16(b, 64, 41); b[66] = 1; b[67] = 48; RawSmb.Put32(b, 68, 4096); RawSmb.Put64(b, 88, id.P); RawSmb.Put64(b, 96, id.V);
        Status(await d.Send(b), 0xc00000bb, "unsupported FileNormalizedNameInformation MUST return NOT_SUPPORTED (MS-SMB2 3.3.5.20.1)");
    }

    static byte[] U64(ulong value) { var b = new byte[8]; RawSmb.Put64(b, 0, value); return b; }
    static byte[] Set((ulong P, ulong V) id, byte cls, byte[] data)
    {
        var b = RawSmb.Header(17, 32 + data.Length, 0, 1, 42); RawSmb.Put16(b, 64, 33); b[66] = 1; b[67] = cls;
        RawSmb.Put32(b, 68, (uint)data.Length); RawSmb.Put16(b, 72, data.Length == 0 ? (ushort)0 : (ushort)96);
        RawSmb.Put64(b, 80, id.P); RawSmb.Put64(b, 88, id.V); data.CopyTo(b, 96); return b;
    }
    static byte[] Enum((ulong P, ulong V) id, byte cls, string pattern, byte flags, uint size)
    {
        var b = RawSmb.Enumerate(id, 0, 1, 42, pattern, flags); b[66] = cls; RawSmb.Put32(b, 92, size);
        if (pattern.Length == 0) RawSmb.Put16(b, 88, 0); return b;
    }
    static byte[] Flush((ulong P, ulong V) id)
    {
        var b = RawSmb.Header(7, 24, 0, 1, 42); RawSmb.Put16(b, 64, 24); RawSmb.Put64(b, 72, id.P); RawSmb.Put64(b, 80, id.V); return b;
    }
    static async Task<byte[]> Query(P2Tests.Direct d, (ulong P, ulong V) id, byte cls, uint size)
    {
        var b = RawSmb.Header(16, 40, 0, 1, 42); RawSmb.Put16(b, 64, 41); b[66] = 1; b[67] = cls;
        RawSmb.Put32(b, 68, size); RawSmb.Put64(b, 88, id.P); RawSmb.Put64(b, 96, id.V);
        var response = await d.Send(b); Status(response, 0, "QUERY_INFO class " + cls); return response;
    }
    static async Task<(ulong P, ulong V)> Open(P2Tests.Direct d, string path, bool directory = false, uint access = 0x10183)
    {
        var b = RawSmb.Create(path, directory, 0, 1, 42); RawSmb.Put32(b, 88, access);
        var response = await d.Send(b); Status(response, 0, "CREATE " + path); return (RawSmb.U64(response, 128), RawSmb.U64(response, 136));
    }
    static async Task Write(P2Tests.Direct d, (ulong P, ulong V) id, byte[] data, ulong offset)
    {
        var response = await d.Send(RawSmb.Write(id, data, offset, 0, 1, 42)); Status(response, 0, "WRITE"); Check.Equal((uint)data.Length, RawSmb.U32(response, 68), "WRITE Count");
    }
    static async Task ReadEquals(P2Tests.Direct d, (ulong P, ulong V) id, byte[] expected)
    {
        var response = await d.Send(RawSmb.Read(id, (uint)expected.Length + 16, 0, 0, 1, 42)); Status(response, 0, "READ short/full data");
        Check.That(expected.SequenceEqual(ReadData(response)), "independent expected content and EOF");
    }
    static byte[] ReadData(byte[] b) => RawSmb.Buffer(b, b[66], RawSmb.U32(b, 68));
    static byte[] Output(byte[] b) => RawSmb.Buffer(b, RawSmb.U16(b, 66), RawSmb.U32(b, 68));
    static void Status(byte[] b, uint expected, string why) => Check.Equal(expected, RawSmb.U32(b, 8), why);
    static void Names(IEnumerable<string> expected, IEnumerable<string> actual, string why)
    {
        var a = actual.Order(StringComparer.Ordinal).ToArray(); var e = expected.Order(StringComparer.Ordinal).ToArray();
        Check.That(e.SequenceEqual(a), why + ": expected=" + string.Join(",", e) + " actual=" + string.Join(",", a));
    }
    sealed class Root : IDisposable
    {
        readonly string path = Path.Combine(Path.GetTempPath(), "smb-microsoft-" + Guid.NewGuid().ToString("N"));
        public Root() => Directory.CreateDirectory(path);
        public string At(params string[] parts) => Path.Combine([path, .. parts]);
        public P2Tests.Direct Direct() => new(new LocalFileStore(path, false));
        public void Dispose() => Directory.Delete(path, true);
    }
}
