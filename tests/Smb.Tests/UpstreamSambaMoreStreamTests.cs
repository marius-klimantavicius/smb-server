using System.Text;
using Smb.Testing;

internal static partial class UpstreamSambaMoreTests
{
    static IEnumerable<(string Name, Func<Task> Run)> StreamCases()
    {
        foreach (var shape in new[] { "same", "new", "replace", "collision", "default", "base-prefixed" })
            yield return ($"upstream.samba.more.stream.rename.{shape}", () => StreamRename(shape));
        // Material partitions of streams.c:test_stream_names2. Ordinary ASCII
        // characters have the same absent-stream oracle; separators differ.
        foreach (var ch in new[] { '\u0001', '\u0005', '\n', ' ', '"', '*', '?', '<', '>', '|', '/', ':', '\\', '\u007e' })
            yield return ($"upstream.samba.more.stream.lookup-char.{(int)ch:x2}", () => StreamCharacter(ch));
        foreach (var shape in new[] { "directory-named", "directory-default", "directory-index", "file-index" })
            yield return ($"upstream.samba.more.stream.type.{shape}", () => StreamType(shape));
        foreach (var shape in new[] { "clear", "last-close", "base-denied", "base-pending", "rename-base-denied", "rename-base-allowed" })
            yield return ($"upstream.samba.more.stream.lifecycle.{shape}", () => StreamLifecycle(shape));
        foreach (var field in new[] { 8, 16 })
            foreach (var fromStream in new[] { false, true })
                yield return ($"upstream.samba.more.stream.time.{field}.{fromStream}", () => StreamTime(field, fromStream));
        yield return ("upstream.samba.more.stream.io-enumeration-delete", StreamIo);
        yield return ("upstream.samba.more.stream.read-attributes-denied", StreamReadAttributes);
    }
    static async Task<string[]> StreamNames(P2Tests.Direct d, (ulong P, ulong V) id)
    {
        var bytes = Output(await d.Send(Query(id, 22))); var names = new List<string>(); if (bytes.Length == 0) return [];
        var at = 0;
        while (true)
        {
            Check.That(at + 24 <= bytes.Length, "stream record bounded"); var n = RawSmb.U32(bytes, at + 4);
            Check.That((n & 1) == 0 && (ulong)at + 24 + n <= (ulong)bytes.Length, "stream name bounded");
            names.Add(Encoding.Unicode.GetString(bytes, at + 24, (int)n)); var next = RawSmb.U32(bytes, at);
            if (next == 0) break; Check.That((next & 7) == 0 && next >= 24 + n, "stream list progresses"); at += (int)next;
        }
        return names.Order(StringComparer.Ordinal).ToArray();
    }
    static async Task StreamRename(string shape)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var baseId = await Open(d, disposition: 3);
        await Write(d, baseId, [41, 42]); var source = await Open(d, "file:source", 3); await Write(d, source, Payload);
        if (shape is "replace" or "collision") { var target = await Open(d, "file:target", 3); await Write(d, target, [97]); await Close(d, target); }
        var name = shape switch { "same" => ":source:$DATA", "default" => "::$DATA", "base-prefixed" => "file:target", _ => ":target:$DATA" };
        var expected = shape == "collision" ? Collision : shape == "base-prefixed" ? Sharing : shape == "replace" ? Invalid : Ok;
        Status(await d.Send(Rename(source, name, shape is "replace" or "default" or "same")), expected, "pinned stream rename outcome");
        if (shape == "replace")
        {
            // MS-FSA 2.1.5.15.12.1 requires rejection of a nonempty target.
            // Preserve it, empty it explicitly, close it, then retry the same rename.
            await Data(d, source, Payload); var target = await Open(d, "file:target"); await Data(d, target, [97]);
            Status(await d.Send(Set(target, 20, new byte[8])), Ok, "empty replacement target"); await Close(d, target);
            Status(await d.Send(Rename(source, name, true)), Ok, "closed empty target can be replaced"); expected = Ok;
        }
        await Data(d, source, Payload);
        if (expected != Ok)
        {
            await Data(d, await Open(d, "file:source"), Payload); await Data(d, baseId, [41, 42]);
            if (shape == "collision") await Data(d, await Open(d, "file:target"), [97]);
            return;
        }
        var targetName = shape == "same" ? "file:source" : shape == "default" ? "file" : "file:target";
        await Data(d, await Open(d, targetName), Payload);
        if (shape != "same") Status(await d.Send(Create("file:source")), Missing, "old stream name absent");
        var expectedNames = shape == "same" ? new[] { "::$DATA", ":source:$DATA" } : shape == "default" ? new[] { "::$DATA" } : new[] { "::$DATA", ":target:$DATA" };
        Check.That((await StreamNames(d, baseId)).SequenceEqual(expectedNames.Order(StringComparer.Ordinal)), "enumeration reflects exact renamed stream set");
        if (shape != "default") await Data(d, baseId, [41, 42]);
    }
    static async Task StreamCharacter(char ch)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var file = await Open(d, disposition: 3); await Write(d, file, Payload);
        var path = $"file:Stream{ch}0x{(int)ch:X2}:$DATA";
        Status(await d.Send(Create(path)), ch is '/' or ':' or '\\' ? 0xc0000033u : Missing, "stream separators invalid; other ASCII names are valid but absent");
        await Data(d, file, Payload); Check.That((await StreamNames(d, file)).SequenceEqual(new[] { "::$DATA" }), "failed lookup creates no stream");
    }
    static async Task StreamType(string shape)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var directory = shape != "file-index";
        await Close(d, await Open(d, "base", 3, directory: directory));
        var path = shape switch { "directory-named" => "base:stream:$DATA", "directory-default" => "base::$DATA", _ => "base::$INDEX_ALLOCATION" };
        var b = Create(path, 3, directory: shape is "directory-named" or "directory-default");
        // Directory index streams are optional. This backend exposes directory
        // handles by ordinary CREATE and must reject an explicit index type.
        var expected = shape is "directory-named" or "directory-default" ? 0xc0000103u : 0xc0000033u;
        Status(await d.Send(b), expected, "stream type validation before host directory I/O");
    }
    static async Task StreamLifecycle(string shape)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        var file = await Open(d, disposition: 3, access: shape is "base-denied" or "rename-base-denied" ? 3u : All); await Write(d, file, [71]);
        var stream = await Open(d, "file:stream", 3, share: shape is "base-denied" or "rename-base-denied" ? 3u : 7u); await Write(d, stream, Payload);
        if (shape.StartsWith("rename-base-"))
        {
            if (shape.EndsWith("denied"))
            {
                Status(await d.Send(Create(access: 0x10081)), Sharing, "stream denies acquisition of a DELETE-capable rename handle");
                await Data(d, stream, Payload); Status(await d.Send(Create("renamed")), Missing, "failed rename-handle acquisition cannot publish a new name");
                await Close(d, stream); var renameOwner = await Open(d, access: 0x10081);
                Status(await d.Send(Rename(renameOwner, "renamed")), Ok, "stream close releases sharing blocker for a fresh rename"); await Data(d, renameOwner, [71]); return;
            }
            Status(await d.Send(Rename(file, "renamed")), Ok, "base rename honors stream delete sharing");
            await Data(d, stream, Payload);
            await Data(d, await Open(d, shape.EndsWith("denied") ? "file:stream" : "renamed:stream"), Payload); return;
        }
        if (shape == "base-denied")
        {
            Status(await d.Send(Create(access: 0x10000)), Sharing, "open for base deletion blocked by stream");
            await Data(d, stream, Payload); await Data(d, file, [71]); return;
        }
        if (shape == "base-pending")
        {
            Status(await d.Send(Set(file, 13, [1])), Ok, "arm base deletion");
            Status(await d.Send(Create("file:stream")), 0xc0000056, "base pending blocks stream opens");
            Status(await d.Send(Create()), 0xc0000056, "base pending blocks base opens");
            await Data(d, stream, Payload); await Close(d, file); await Close(d, stream);
            Status(await d.Send(Create()), Missing, "last stream close completes base deletion"); return;
        }
        var peer = await Open(d, "file:stream"); Status(await d.Send(Set(stream, 13, [1])), Ok, "arm stream deletion");
        Status(await d.Send(Create("file:stream")), 0xc0000056, "new stream open denied while pending");
        if (shape == "clear") Status(await d.Send(Set(peer, 13, [0])), Ok, "peer can clear stream deletion");
        await Close(d, stream); await Data(d, peer, Payload); await Close(d, peer);
        var reopen = await d.Send(Create("file:stream")); Status(reopen, shape == "clear" ? Ok : Missing, "last-close/clear stream lifecycle");
        if (shape == "clear") await Data(d, Id(reopen), Payload); await Data(d, file, [71]);
    }
    static async Task StreamTime(int field, bool fromStream)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var file = await Open(d, disposition: 3); var stream = await Open(d, "file:stream", 3);
        var stamp = (ulong)new DateTime(2006, 1, 2, 15, 4, 5, DateTimeKind.Utc).ToFileTimeUtc();
        var data = new byte[40]; RawSmb.Put64(data, field, stamp); Status(await d.Send(Set(fromStream ? stream : file, 4, data)), Ok, "SET shared stream timestamp");
        foreach (var id in new[] { file, stream }) Check.Equal(stamp, RawSmb.U64(Output(await d.Send(Query(id, 4))), field), "base and stream share access/write timestamp");
    }
    static async Task StreamIo()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var file = await Open(d, disposition: 3); var one = await Open(d, "file:Stream One", 3); var two = await Open(d, "file:Second Stream:$DATA", 3);
        await Write(d, file, [1, 2]); await Write(d, one, [3, 4, 5]); await Write(d, two, [6, 7, 8, 9]);
        await Data(d, file, [1, 2]); await Data(d, one, [3, 4, 5]); await Data(d, two, [6, 7, 8, 9]);
        Check.That((await StreamNames(d, file)).SequenceEqual(new[] { "::$DATA", ":Second Stream:$DATA", ":Stream One:$DATA" }.Order(StringComparer.Ordinal)), "all three exact stream names");
        Status(await d.Send(Set(one, 13, [1])), Ok, "delete one stream"); await Close(d, one);
        Status(await d.Send(Create("file:Stream One")), Missing, "deleted stream absent");
        Check.That((await StreamNames(d, file)).SequenceEqual(new[] { "::$DATA", ":Second Stream:$DATA" }.Order(StringComparer.Ordinal)), "remaining stream set");
        await Data(d, file, [1, 2]); await Data(d, two, [6, 7, 8, 9]);
    }
    static async Task StreamReadAttributes()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); await Close(d, await Open(d, disposition: 3)); await Close(d, await Open(d, "file:stream", 3));
        var id = await Open(d, "file:stream", access: 1); Status(await d.Send(Query(id, 4)), Denied, "FileBasicInformation requires READ_ATTRIBUTES on the stream open");
        Status(await d.Send(RawSmb.Read(id, 1, 0, 0, 1, 42)), Eof, "data permission remains usable");
    }
}
