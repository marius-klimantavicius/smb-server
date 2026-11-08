using Smb.Testing;

internal static partial class UpstreamSambaMoreTests
{
    static IEnumerable<(string Name, Func<Task> Run)> CompoundCases()
    {
        foreach (var shape in new[] { "repeated-close", "unrelated-close", "bad-ioctl", "missing-create-ioctl", "missing-create-notify", "first-related", "bad-read", "find-related", "find-unrelated", "find-close", "flush-close", "flush-flush", "write-write", "read-read", "getinfo-middle", "rename-last", "rename-middle" })
            yield return ($"upstream.samba.more.compound.{shape}", () => CompoundShape(shape));
        foreach (var length in new[] { 1, 2, 7, 8, 9, 15, 16, 17 })
            yield return ($"upstream.samba.more.compound.padding.{length}", () => CompoundPadding(length));
    }
    static byte[] Notify((ulong P, ulong V) id, uint max = 4096, uint filter = 1, bool recursive = false)
    {
        var b = RawSmb.Header(15, 32, 0, 1, 42); RawSmb.Put16(b, 64, 32); RawSmb.Put16(b, 66, recursive ? (ushort)1 : (ushort)0);
        RawSmb.Put32(b, 68, max); RawSmb.Put64(b, 72, id.P); RawSmb.Put64(b, 80, id.V); RawSmb.Put32(b, 88, filter); return b;
    }
    static async Task CompoundShape(string shape)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        byte[][] requests; uint[] expected; bool[]? related = null;
        if (shape is "repeated-close" or "unrelated-close")
        {
            requests = [Create(disposition: 3), RawSmb.Close(Inherit, 0, 1, 42), RawSmb.Close(Inherit, 0, 1, 42), RawSmb.Close(Inherit, 0, 1, 42), RawSmb.Close(Inherit, 0, 1, 42)];
            expected = [Ok, shape == "repeated-close" ? Ok : Closed, Closed, Closed, Closed];
            if (shape == "unrelated-close") related = [false, false, false, false, false];
        }
        else if (shape == "bad-ioctl")
        {
            // Chain uses IDs 100 above its preparatory ECHOs. With no earlier
            // CREATE, obtain the extra grant needed to put those IDs in-window.
            var echo = RawSmb.Header(13, 4, 0, 1, 42); RawSmb.Put16(echo, 64, 4);
            Status(await d.Send(echo), Ok, "grant credit window before missing-open IOCTL chain");
            requests = [P5Tests.Ioctl(Inherit, 0x900c0, [], 64), RawSmb.Close(Inherit, 0, 1, 42)]; expected = [Closed, Closed];
        }
        else if (shape.StartsWith("missing-create-"))
        {
            requests = [Create(), shape.EndsWith("ioctl") ? P5Tests.Ioctl(Inherit, 0x9009c, [], 64) : Notify(Inherit), RawSmb.Close(Inherit, 0, 1, 42), Query(Inherit, 4)];
            expected = [Missing, Missing, Missing, Missing];
        }
        else if (shape == "first-related")
        {
            requests = [Create(disposition: 3), Notify(Inherit), Query(Inherit, 4)]; expected = [Invalid, Invalid, Invalid]; related = [true, true, true];
        }
        else
        {
            var directory = shape.StartsWith("find-"); var id = await Open(d, directory ? "" : "file", directory: directory, disposition: directory ? 1u : 3u);
            if (!directory) await Write(d, id, Payload);
            if (shape.StartsWith("find-"))
            {
                if (shape == "find-close")
                { requests = [Enum(id), RawSmb.Close(id, 0, 1, 42)]; expected = [Ok, Ok]; }
                else
                {
                    requests = [Enum(id), Enum(shape == "find-related" ? Inherit : id, "", 0)]; expected = [Ok, 0x80000006];
                    related = [false, shape == "find-related"];
                }
            }
            else if (shape == "bad-read")
            {
                var invalid = RawSmb.Header(0xffff, 0, 0, 1, 42);
                requests = [RawSmb.Read(id, 1, (ulong)Payload.Length, 0, 1, 42), invalid]; expected = [Eof, Invalid];
            }
            else if (shape == "flush-close") { requests = [Flush(id), RawSmb.Close(Inherit, 0, 1, 42)]; expected = [Ok, Ok]; }
            else if (shape == "flush-flush") { requests = [Flush(id), Flush(Inherit)]; expected = [Ok, Ok]; }
            else if (shape == "write-write") { requests = [RawSmb.Write(id, [11, 12], 0, 0, 1, 42), RawSmb.Write(Inherit, [13, 14], 2, 0, 1, 42)]; expected = [Ok, Ok]; }
            else if (shape == "read-read") { requests = [RawSmb.Read(id, 7, 0, 0, 1, 42), RawSmb.Read(Inherit, 9, 7, 0, 1, 42)]; expected = [Ok, Ok]; }
            else if (shape == "getinfo-middle") { requests = [Create(), Query(Inherit, 18), RawSmb.Close(Inherit, 0, 1, 42)]; expected = [Ok, Ok, Ok]; }
            else if (shape == "rename-last") { requests = [Create(), Rename(Inherit, "renamed")]; expected = [Ok, Ok]; }
            else { requests = [Create(), Rename(Inherit, "renamed"), RawSmb.Close(Inherit, 0, 1, 42)]; expected = [Ok, Ok, Ok]; }
        }
        var response = Split(await Chain(d, requests, related)); Check.Equal(expected.Length, response.Count, "one response per compound command");
        for (var i = 0; i < expected.Length; i++) Status(response[i], expected[i], $"{shape} component {i}");
        if (shape == "read-read")
        {
            Check.That(RawSmb.Buffer(response[0], response[0][66], RawSmb.U32(response[0], 68)).SequenceEqual(Payload[..7]), "first read bytes");
            Check.That(RawSmb.Buffer(response[1], response[1][66], RawSmb.U32(response[1], 68)).SequenceEqual(Payload[7..16]), "second read bytes");
        }
        if (shape == "write-write") await Data(d, await Open(d), new byte[] { 11, 12, 13, 14 }.Concat(Payload[4..]).ToArray());
        if (shape.StartsWith("rename-")) { Status(await d.Send(Create()), Missing, "old name removed"); await Data(d, await Open(d, "renamed"), Payload); }
        if (shape == "getinfo-middle") Check.Equal((ulong)Payload.Length, RawSmb.U64(Output(response[1]), 48), "middle ALL_INFORMATION EOF");
        if (shape.StartsWith("missing-create-") || shape == "first-related") Check.That(!File.Exists(Path.Combine(root.Path, "file")), "rejected chain cannot create file");
    }
    static async Task CompoundPadding(int length)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var id = await Open(d, disposition: 3);
        var bytes = Enumerable.Range(0, length).Select(i => (byte)(i + 17)).ToArray(); await Write(d, id, bytes);
        var parts = Split(await Chain(d, [RawSmb.Read(id, (uint)length, 0, 0, 1, 42), Query(Inherit, 5), RawSmb.Close(Inherit, 0, 1, 42)]));
        Check.Equal(3, parts.Count, "READ/QUERY/CLOSE response count"); foreach (var part in parts) Status(part, Ok, "padding chain success");
        Check.That(RawSmb.Buffer(parts[0], parts[0][66], RawSmb.U32(parts[0], 68)).SequenceEqual(bytes), "padding excluded from READ data");
        Check.Equal((uint)((80 + length + 7) & ~7), RawSmb.U32(parts[0], 20), "READ response next offset rounds up to eight bytes");
        Check.Equal((ulong)length, RawSmb.U64(Output(parts[1]), 8), "next command's EOF intact");
        Status(await d.Send(RawSmb.Close(id, 0, 1, 42)), Closed, "related CLOSE applied to original open");
    }
}
