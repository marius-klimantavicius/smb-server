using System.Text;
using Smb.Testing;

internal static partial class DurableRecoveryTcpTests
{
    static IEnumerable<(string Name, Func<Task> Run)> NamespaceRepairCases()
    {
        foreach (var dialect in new ushort[] { 0x202, 0x300, 0x311 })
        {
            foreach (var shape in new[] { "unknown", "first-related", "session-reset" })
                yield return ($"namespace.tcp.compound.{dialect:x}.{shape}", () => CompoundRepairTcp(dialect, shape));
            foreach (var delete in new[] { false, true }) foreach (var share in new uint[] { 0, 7 })
                yield return ($"namespace.tcp.parent-reservation.{dialect:x}.{delete}.{share}", () => ParentReservationTcp(dialect, delete, share));
            if (dialect >= 0x300)
            {
                yield return ($"namespace.tcp.replay-shapes.{dialect:x}", () => ReplayShapesTcp(dialect));
                foreach (var mode in new[] { "close", "ack", "arrival", "cancel" })
                    yield return ($"namespace.tcp.descendant-lease.{dialect:x}.{mode}", () => DescendantLeaseTcp(dialect, mode));
            }
            yield return ($"namespace.tcp.stream-alias.{dialect:x}", () => StreamAliasTcp(dialect));
            yield return ($"namespace.tcp.descendant.{dialect:x}", () => DescendantRename(dialect));
            foreach (var shape in new[] { "new", "same", "replace", "collision", "open-target", "nonempty-target", "default", "default-delete", "default-roundtrip", "default-base-rename" })
                yield return ($"namespace.tcp.stream.{dialect:x}.{shape}", () => StreamRenameTcp(dialect, shape));
            foreach (var kind in new[] { "slash", "backslash", "nul", "different-type" })
                yield return ($"namespace.tcp.stream-type.{dialect:x}.{kind}", () => StreamTypeTcp(dialect, kind));
        }
    }
    static byte[] RenameRequest((ulong P, ulong V) id, string target, bool replace = false)
    {
        var name = Encoding.Unicode.GetBytes(target); var data = new byte[20 + name.Length];
        data[0] = replace ? (byte)1 : (byte)0; RawSmb.Put32(data, 16, (uint)name.Length); name.CopyTo(data, 20); return Set(id, 10, data);
    }
    static async Task StreamTypeTcp(ushort dialect, string kind)
    {
        // MS-FSA 2.1.5.15.12.1 validates MS-FSCC 2.1.5.4 characters
        // before comparing a valid stream type against the acquired DATA stream.
        await using var f = new Fixture(); await f.Server.StartAsync();
        await using var a = await f.Connect(dialect, Guid.NewGuid());
        await using var b = await f.Connect(dialect, Guid.NewGuid());
        var source = Id(await a.Exchange(OpenRequest("file:source", 2)));
        await a.Exchange(RawSmb.Write(source, Payload, 0, 0, 0, 0));
        var old = Id(await b.Exchange(OpenRequest("file:source")));
        var type = kind switch { "slash" => "$DA/TA", "backslash" => "$DA\\TA", "nul" => "$DA\0TA", _ => "$INDEX_ALLOCATION" };
        await a.Exchange(RenameRequest(source, ":target:" + type), kind == "different-type" ? 0xc0000024u : 0xc000000du);
        await Bytes(a, source, Payload); await Bytes(b, old, Payload);
        await b.Exchange(OpenRequest("file:target"), Missing);
        await a.Exchange(RenameRequest(source, ":target:$DATA"));
        var renamed = Id(await b.Exchange(OpenRequest("file:target")));
        await Bytes(a, source, Payload); await Bytes(b, old, Payload); await Bytes(b, renamed, Payload);
        await b.Exchange(OpenRequest("file:source"), Missing);
        await a.Exchange(RawSmb.Close(source, 0, 0, 0));
        await b.Exchange(RawSmb.Close(old, 0, 0, 0)); await b.Exchange(RawSmb.Close(renamed, 0, 0, 0));
    }
    static byte[] OpenRequest(string path, uint disposition = 1, bool directory = false)
    {
        var b = RawSmb.Create(path, directory, 0, 0, 0); RawSmb.Put32(b, 88, 0x1f01ff); RawSmb.Put32(b, 100, disposition); return b;
    }
    static async Task Bytes(Peer p, (ulong P, ulong V) id, byte[] bytes)
    {
        var b = await p.Exchange(RawSmb.Read(id, (uint)bytes.Length, 0, 0, 0, 0));
        Check.That(bytes.SequenceEqual(RawSmb.Buffer(b, b[66], RawSmb.U32(b, 68))), "pinned handle bytes");
    }
    static async Task CompoundRepairTcp(ushort dialect, string shape)
    {
        await using var f = new Fixture(); await f.Server.StartAsync(); await using var a = await f.Connect(dialect, Guid.NewGuid());
        byte[][] packets; uint[] statuses; bool[] related;
        var inherit = (ulong.MaxValue, ulong.MaxValue);
        if (shape == "unknown")
        {
            var id = Id(await a.Exchange(OpenRequest("file", 2))); await a.Exchange(RawSmb.Write(id, Payload, 0, 0, 0, 0));
            packets = [RawSmb.Read(id, 1, (ulong)Payload.Length, 0, 0, 0), RawSmb.Header(0xffff, 0, 0)];
            statuses = [0xc0000011, 0xc000000d]; related = [false, true];
            await CompoundVector(a, packets, statuses, related);
            await Bytes(a, id, Payload); await a.Exchange(RawSmb.Close(id, 0, 0, 0)); return;
        }
        if (shape == "first-related")
        {
            packets = [OpenRequest("phantom", 2), RawSmb.Close(inherit, 0, 0, 0), OpenRequest("reset", 2)];
            statuses = [0xc000000d, 0xc000000d, 0]; related = [true, true, false];
        }
        else
        {
            packets = [OpenRequest("file", 2), RawSmb.Close(inherit, 0, 0, 0), RawSmb.Close(inherit, 0, ulong.MaxValue, uint.MaxValue), RawSmb.Close(inherit, 0, ulong.MaxValue, uint.MaxValue), RawSmb.Close(inherit, 0, 0, 0)];
            statuses = [0, 0, 0xc0000203, 0xc0000203, 0xc000000d]; related = [false, true, false, false, true];
        }
        var result = await CompoundVector(a, packets, statuses, related);
        if (shape == "first-related")
        {
            await a.Exchange(OpenRequest("phantom"), Missing); var id = Id(result[^1]);
            await a.Exchange(RawSmb.Write(id, Payload, 0, 0, 0, 0)); await Bytes(a, id, Payload); await a.Exchange(RawSmb.Close(id, 0, 0, 0));
        }
        else
        {
            await a.Exchange(RawSmb.Close(Id(result[0]), 0, 0, 0), 0xc0000128);
            var id = Id(await a.Exchange(OpenRequest("file"))); await a.Exchange(RawSmb.Close(id, 0, 0, 0));
        }
    }
    static async Task<byte[][]> CompoundVector(Peer a, byte[][] packets, uint[] statuses, bool[] related)
    {
        var wire = new List<byte>(); var mids = new List<ulong>();
        for (var i = 0; i < packets.Length; i++)
        {
            var b = packets[i].ToArray(); var bad = RawSmb.U64(b, 40) == ulong.MaxValue;
            a.Route(b); if (bad || related[i]) { RawSmb.Put64(b, 40, ulong.MaxValue); RawSmb.Put32(b, 36, uint.MaxValue); }
            if (related[i]) RawSmb.Put32(b, 16, 4);
            Array.Resize(ref b, (b.Length + 7) & ~7); RawSmb.Put32(b, 20, i + 1 < packets.Length ? (uint)b.Length : 0);
            a.Sign(b); mids.Add(RawSmb.U64(b, 24)); wire.AddRange(b);
        }
        await a.Send(wire.ToArray()); var reply = await a.Receive(); var parts = new List<byte[]>(); var offset = 0;
        for (var i = 0; i < packets.Length; i++)
        {
            Check.That(offset + 64 <= reply.Length, "complete compound response header"); var next = (int)RawSmb.U32(reply, offset + 20);
            var size = next == 0 ? reply.Length - offset : next; Check.That(size >= 64 && offset + size <= reply.Length && (next == 0 || next % 8 == 0), "bounded aligned component");
            var part = reply.AsSpan(offset, size).ToArray(); Check.Equal(statuses[i], RawSmb.U32(part, 8), "compound exact status vector");
            Check.Equal(mids[i], RawSmb.U64(part, 24), "compound ordered MessageIds"); Check.Equal(RawSmb.U16(packets[i], 12), RawSmb.U16(part, 12), "compound command");
            if (RawSmb.U64(part, 40) != ulong.MaxValue) Peer.Signature(part, a.ChannelKey, a.Dialect);
            parts.Add(part); offset += size; Check.Equal(i == packets.Length - 1, next == 0, "one response per component");
        }
        Check.Equal(reply.Length, offset, "all response bytes accounted for"); return parts.ToArray();
    }
    static async Task ReplayShapesTcp(ushort dialect)
    {
        await using var f = new Fixture(); await f.Server.StartAsync(); var client = Guid.NewGuid();
        await using var a = await f.Connect(dialect, client); var guid = Guid.NewGuid();
        var request = Request(false, guid); var initial = await a.Exchange(request); var id = Id(initial);
        var mismatched = Leased(Request(false, guid), 3); RawSmb.Put32(mismatched, 16, 0x20000000);
        await a.Exchange(mismatched, Denied);
        var replay = Request(false, guid); replay[67] = 0; RawSmb.Put32(replay, 16, 0x20000000);
        var result = await a.Exchange(replay); Check.Equal(id, Id(result), "failed lease-shape replay does not consume original claim");
        Check.Equal((byte)9, result[66], "MS-SMB2 replay response uses retained oplock"); Check.That(Context(result, "DH2Q") != null, "retained durable response context");
        await a.Exchange(RawSmb.Write(id, Payload, 0, 0, 0, 0)); await Bytes(a, id, Payload); await a.Exchange(RawSmb.Close(id, 0, 0, 0));
    }
    static async Task ParentReservationTcp(ushort dialect, bool delete, uint share)
    {
        await using var f = new Fixture(); await f.Server.StartAsync();
        await using var a = await f.Connect(dialect, Guid.NewGuid()); await using var b = await f.Connect(dialect, Guid.NewGuid());
        var directory = Id(await a.Exchange(OpenRequest("dir", 2, true))); await a.Exchange(RawSmb.Close(directory, 0, 0, 0));
        var request = OpenRequest("dir", directory: true); RawSmb.Put32(request, 88, delete ? 0x1701bfu : 0x1601bfu); RawSmb.Put32(request, 96, share);
        var parent = Id(await b.Exchange(request)); var file = Id(await a.Exchange(OpenRequest("dir\\file", 2))); await a.Exchange(RawSmb.Write(file, Payload, 0, 0, 0, 0));
        var expected = !delete && share == 7 ? 0u : 0xc0000043;
        await a.Exchange(RenameRequest(file, "dir\\renamed"), expected); await Bytes(a, file, Payload);
        await b.Exchange(RawSmb.Close(parent, 0, 0, 0));
        if (expected != 0) await a.Exchange(RenameRequest(file, "dir\\renamed"));
        var reopened = Id(await b.Exchange(OpenRequest("dir\\renamed"))); await Bytes(b, reopened, Payload);
        await b.Exchange(RawSmb.Close(reopened, 0, 0, 0)); await a.Exchange(RawSmb.Close(file, 0, 0, 0));
        await b.Exchange(OpenRequest("dir\\file"), Missing);
    }
    static async Task DescendantLeaseTcp(ushort dialect, string mode)
    {
        await using var f = new Fixture(); await f.Server.StartAsync();
        await using var a = await f.Connect(dialect, Guid.NewGuid()); await using var b = await f.Connect(dialect, Guid.NewGuid());
        await using var c = await f.Connect(dialect, Guid.NewGuid());
        var dir = Id(await a.Exchange(OpenRequest("dir", 2, true)));
        var opened = await b.Exchange(Leased(OpenRequest("dir\\child", 2), 3)); var child = Id(opened);
        Check.Equal(3u, RawSmb.U32(Context(opened, "RqLs")!, 16), "actual descendant RH grant");
        await b.Exchange(RawSmb.Write(child, Payload, 0, 0, 0, 0));
        var rename = RenameRequest(dir, "moved"); a.Route(rename); a.Sign(rename); await a.Send(rename);
        var pending = await a.Receive(); Check.Equal(0x103u, RawSmb.U32(pending, 8), "directory rename waits for descendant ACK");
        Check.Equal(RawSmb.U64(rename, 24), RawSmb.U64(pending, 24), "pending belongs to exact rename");
        var notice = await b.Receive();
        // MS-SMB2 3.3.4.7: lease notifications SHOULD NOT be signed and have zero routing IDs.
        if ((RawSmb.U32(notice, 16) & 8) != 0) Peer.Signature(notice, b.ChannelKey, dialect);
        Check.Equal(ulong.MaxValue, RawSmb.U64(notice, 24), "unsolicited notification MessageId");
        Check.Equal(0ul, RawSmb.U64(notice, 40), "lease notification SessionId"); Check.Equal(0u, RawSmb.U32(notice, 36), "lease notification TreeId");
        Check.Equal((ushort)44, RawSmb.U16(notice, 64), "actual lease break notification"); Check.Equal(1ul, RawSmb.U64(notice, 72), "descendant lease key");
        Check.That(Directory.Exists(Path.Combine(f.Root.Path, "dir")) && !Directory.Exists(Path.Combine(f.Root.Path, "moved")), "no namespace mutation before ACK barrier");
        (ulong P, ulong V) extra = default;
        if (mode == "arrival") extra = Id(await c.Exchange(OpenRequest("dir\\arrived", 2)));
        if (mode == "cancel")
        {
            var cancel = RawSmb.Header(12, 4, RawSmb.U64(rename, 24), a.Session); RawSmb.Put16(cancel, 64, 4);
            RawSmb.Put32(cancel, 16, 2); RawSmb.Put64(cancel, 32, RawSmb.U64(pending, 32)); a.Sign(cancel); await a.Send(cancel);
        }
        else if (mode == "ack")
        {
            var ack = RawSmb.Header(18, 36, 0); RawSmb.Put16(ack, 64, 36); RawSmb.Put64(ack, 72, 1); RawSmb.Put64(ack, 80, 2); RawSmb.Put32(ack, 88, RawSmb.U32(notice, 92));
            await b.Exchange(ack);
        }
        else await b.Exchange(RawSmb.Close(child, 0, 0, 0));
        var final = await a.Receive(); Peer.Signature(final, a.ChannelKey, dialect);
        Check.Equal(RawSmb.U64(rename, 24), RawSmb.U64(final, 24), "one final for exact rename"); Check.Equal(RawSmb.U64(pending, 32), RawSmb.U64(final, 32), "final preserves AsyncId");
        Check.Equal(mode == "close" ? 0u : mode == "cancel" ? 0xc0000120u : Denied, RawSmb.U32(final, 8), "complete directory rename outcome");
        if (mode == "cancel")
        {
            // Cancelling SET_INFO does not acknowledge the independently delivered lease break.
            var ack = RawSmb.Header(18, 36, 0); RawSmb.Put16(ack, 64, 36); RawSmb.Put64(ack, 72, 1); RawSmb.Put64(ack, 80, 2); RawSmb.Put32(ack, 88, RawSmb.U32(notice, 92));
            await b.Exchange(ack);
        }
        if (mode is "ack" or "cancel") { await Bytes(b, child, Payload); await b.Exchange(RawSmb.Close(child, 0, 0, 0)); }
        if (mode == "arrival") await c.Exchange(RawSmb.Close(extra, 0, 0, 0));
        if (mode != "close") { Check.That(Directory.Exists(Path.Combine(f.Root.Path, "dir")), "rejected rename preserves namespace"); await a.Exchange(RenameRequest(dir, "moved")); }
        var fresh = Id(await c.Exchange(OpenRequest("moved\\child"))); await Bytes(c, fresh, Payload);
        await c.Exchange(RawSmb.Close(fresh, 0, 0, 0)); await a.Exchange(RawSmb.Close(dir, 0, 0, 0));
    }
    static async Task StreamAliasTcp(ushort dialect)
    {
        await using var f = new Fixture(); await f.Server.StartAsync();
        await using var a = await f.Connect(dialect, Guid.NewGuid()); await using var b = await f.Connect(dialect, Guid.NewGuid());
        var baseFile = Id(await a.Exchange(OpenRequest("file", 2))); await a.Exchange(RawSmb.Close(baseFile, 0, 0, 0));
        var source = Id(await a.Exchange(OpenRequest("file:source", 2))); await a.Exchange(RawSmb.Write(source, Payload, 0, 0, 0, 0));
        var alias = await b.Exchange(RawSmb.TreeConnect(@"\\localhost\OTHER", 0, 0)); b.Tree = RawSmb.U32(alias, 36);
        var other = Id(await b.Exchange(OpenRequest("file:source"))); await Bytes(b, other, Payload);
        await a.Exchange(RenameRequest(source, ":renamed:$DATA")); await Bytes(b, other, Payload);
        var fresh = Id(await b.Exchange(OpenRequest("file:renamed"))); await Bytes(b, fresh, Payload);
        await a.Exchange(Lock(source, 0, 2 | 16)); await b.Exchange(Lock(fresh, 0, 2 | 16), 0xc0000055); await a.Exchange(Lock(source, 0, 4));
        foreach (var entry in new[] { (p:a,id:source), (p:b,id:other), (p:b,id:fresh) }) await entry.p.Exchange(RawSmb.Close(entry.id, 0, 0, 0));
        await b.Exchange(OpenRequest("file:source"), Missing);
    }
    static async Task DescendantRename(ushort dialect)
    {
        await using var f = new Fixture(); await f.Server.StartAsync();
        await using var a = await f.Connect(dialect, Guid.NewGuid()); await using var b = await f.Connect(dialect, Guid.NewGuid());
        var dir = Id(await a.Exchange(OpenRequest("dir", 2, true)));
        var child = Id(await b.Exchange(OpenRequest("dir\\child", 2))); await b.Exchange(RawSmb.Write(child, Payload, 0, 0, 0, 0));
        await a.Exchange(RenameRequest(dir, "moved"), Denied); await Bytes(b, child, Payload);
        var info = await b.Exchange(Query(child, 18)); var output = RawSmb.Buffer(info, RawSmb.U16(info, 66), RawSmb.U32(info, 68));
        Check.Equal("\\dir\\child", Encoding.Unicode.GetString(output, 100, (int)RawSmb.U32(output, 96)), "query retained acquired child path");
        await a.Exchange(OpenRequest("moved\\child"), Missing); // rejection publishes no destination
        await b.Exchange(RawSmb.Close(child, 0, 0, 0)); await a.Exchange(RenameRequest(dir, "moved"));
        var reopened = Id(await b.Exchange(OpenRequest("moved\\child"))); await Bytes(b, reopened, Payload);
        await b.Exchange(RawSmb.Close(reopened, 0, 0, 0)); await a.Exchange(RawSmb.Close(dir, 0, 0, 0));
    }
    static async Task StreamRenameTcp(ushort dialect, string shape)
    {
        await using var f = new Fixture(); await f.Server.StartAsync();
        await using var a = await f.Connect(dialect, Guid.NewGuid()); await using var b = await f.Connect(dialect, Guid.NewGuid());
        var file = Id(await a.Exchange(OpenRequest("file", 2))); await a.Exchange(RawSmb.Write(file, [41,42], 0, 0, 0, 0));
        var source = Id(await a.Exchange(OpenRequest("file:source", 2))); await a.Exchange(RawSmb.Write(source, Payload, 0, 0, 0, 0));
        var old = Id(await b.Exchange(OpenRequest("file:source")));
        (ulong P, ulong V) target = default;
        if (shape is "replace" or "collision" or "open-target" or "nonempty-target")
        {
            target = Id(await b.Exchange(OpenRequest("file:target", 2))); await b.Exchange(RawSmb.Write(target, [97], 0, 0, 0, 0));
            if (shape == "replace") await b.Exchange(Set(target, 20, new byte[8]));
            if (shape != "open-target") await b.Exchange(RawSmb.Close(target, 0, 0, 0));
        }
        var name = shape is "default" or "default-delete" or "default-roundtrip" or "default-base-rename" ? "::$DATA" : shape == "same" ? ":source:$DATA" : ":target:$DATA";
        var expected = shape == "collision" ? 0xc0000035u : shape is "open-target" or "nonempty-target" ? 0xc000000du : 0;
        await a.Exchange(RenameRequest(source, name, shape is "replace" or "default" or "default-delete" or "default-roundtrip" or "default-base-rename" or "open-target" or "nonempty-target"), expected);
        await Bytes(a, source, Payload); await Bytes(b, old, Payload); await Bytes(a, file, [41,42]);
        if (shape == "open-target")
        {
            await Bytes(b, target, [97]); await b.Exchange(Set(target, 20, new byte[8])); await b.Exchange(RawSmb.Close(target, 0, 0, 0));
            await a.Exchange(RenameRequest(source, name, true)); expected = 0;
        }
        var nextName = expected != 0 || shape == "same" ? "file:source" : shape is "default" or "default-delete" or "default-roundtrip" or "default-base-rename" ? "file" : "file:target";
        var fresh = Id(await b.Exchange(OpenRequest(nextName))); await Bytes(b, fresh, Payload);
        // New opens and old opens share one stream identity after rename: lock conflict is a wire oracle.
        await a.Exchange(Lock(source, 0, 2 | 16)); await b.Exchange(Lock(fresh, 0, 2 | 16), 0xc0000055);
        await a.Exchange(Lock(source, 0, 4));
        if (shape == "default-base-rename")
        {
            await b.Exchange(RenameRequest(fresh, "renamed")); await Bytes(a, source, Payload); await Bytes(b, old, Payload); await Bytes(a, file, [41,42]);
            var moved = Id(await b.Exchange(OpenRequest("renamed"))); await Bytes(b, moved, Payload); await b.Exchange(RawSmb.Close(moved, 0, 0, 0));
            await b.Exchange(OpenRequest("file"), Missing);
        }
        if (shape == "default-roundtrip")
        {
            await a.Exchange(RenameRequest(source, ":roundtrip:$DATA")); await Bytes(b, old, Payload); await Bytes(b, fresh, Payload);
            var nextDefault = Id(await b.Exchange(OpenRequest("file")));
            await b.Exchange(RawSmb.Read(nextDefault, 1, 0, 0, 0, 0), 0xc0000011);
            await b.Exchange(RawSmb.Close(nextDefault, 0, 0, 0));
            var named = Id(await b.Exchange(OpenRequest("file:roundtrip"))); await Bytes(b, named, Payload); await b.Exchange(RawSmb.Close(named, 0, 0, 0));
        }
        if (shape == "default-delete")
        {
            await a.Exchange(RawSmb.Close(file, 0, 0, 0));
            var blocked = OpenRequest("file:other", 2); RawSmb.Put32(blocked, 96, 3);
            await b.Exchange(blocked, 0xc0000043); // DELETE on the promoted default conflicts across streams
            await a.Exchange(Set(source, 13, [1]));
            await b.Exchange(OpenRequest("file"), 0xc0000056); await Bytes(b, old, Payload);
        }
        foreach (var entry in new[] { (p:a, id:source), (p:b,id:old), (p:b,id:fresh) }) await entry.p.Exchange(RawSmb.Close(entry.id, 0, 0, 0));
        if (shape != "default-delete") await a.Exchange(RawSmb.Close(file, 0, 0, 0));
        if (expected == 0 && shape != "same") await b.Exchange(OpenRequest("file:source"), Missing);
        if (shape == "default-delete") await b.Exchange(OpenRequest("file"), Missing);
    }
}
