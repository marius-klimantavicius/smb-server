using Smb.Protocol.Enums;
using Smb.Testing;

internal static partial class UpstreamMicrosoftTests
{
    static IEnumerable<(string Name, Func<Task> Run)> CompressionCases()
    {
        foreach (var algorithm in new ushort[] { 1, 2 })
        {
            foreach (var shape in new[] { "small", "large", "incompressible", "prefix" })
                yield return ($"upstream.microsoft.compression.{algorithm}.{shape}", () => CompressedIo(algorithm, shape));
            yield return ($"upstream.microsoft.compression.{algorithm}.encrypted", () => CompressedEncrypted(algorithm));
            foreach (var compressible in new[] { false, true })
                yield return ($"upstream.microsoft.compression.{algorithm}.requested-{compressible}", () => RequestedCompression(algorithm, compressible));
        }
        foreach (var kind in new[] { "short-transform", "invalid-algorithm", "invalid-plain-id", "invalid-size" })
            yield return ("upstream.microsoft.compression.reject." + kind, () => BadCompression(kind));
        foreach (var kind in new[] { "unsupported-algorithm", "old-dialect", "short-context", "empty-algorithms", "chained-not-supported" })
            yield return ("upstream.microsoft.compression.negotiate." + kind, () => CompressionNegotiate(kind));
    }
    // SMB2/Compression/CompressionTest.cs: compressed WRITE, compressible and
    // incompressible READ, large-file and invalid-frame variants. Only the two
    // mutually encodable algorithms are selected. MS-XCA literal-only encoding
    // deliberately avoids using the server's compression helpers as an oracle.
    static async Task CompressedIo(ushort algorithm, string shape)
    {
        await using var host = await UpstreamLocalFixture.StartAsync();
        host.Server.State.Options.EnableCompression = true; host.Server.State.Options.CompressionPreference = [(SmbCompressionAlgorithm)algorithm];
        await using var c = await AuthWire.Connect(host.Server.Endpoint); await c.Negotiate(0x311, compressionAlgorithm: algorithm); await c.Login();
        var response = await c.Exchange(RawSmb.TreeConnect("\\\\localhost\\P0", 0, c.Session), 0, true); var tree = RawSmb.U32(response, 36);
        response = await c.Exchange(RawSmb.Create("compressed", false, 0, c.Session, tree), 0, true); var id = (RawSmb.U64(response, 128), RawSmb.U64(response, 136));
        var length = shape == "large" ? 131073 : shape == "small" ? 123 : 16385;
        var bytes = new byte[length]; var random = new Random(1234);
        if (shape == "incompressible") random.NextBytes(bytes); else Array.Fill(bytes, (byte)0x61);
        var write = RawSmb.Write(id, bytes, 0, 0, c.Session, tree); RawSmb.Put16(write, 6, (ushort)Math.Max(1, (length + 65535) / 65536));
        response = await c.Exchange(write, 0, true, compressionAlgorithm: algorithm, prefixLength: shape == "prefix" ? 64 : 0);
        Check.Equal((uint)length, RawSmb.U32(response, 68), "compressed wire WRITE count");
        var read = RawSmb.Read(id, (uint)length, 0, 0, c.Session, tree); RawSmb.Put16(read, 6, (ushort)Math.Max(1, (length + 65535) / 65536));
        response = await c.Exchange(read, 0, true);
        Check.That(bytes.SequenceEqual(ReadData(response)), "independently decompressed READ has original bytes");
        await c.Exchange(RawSmb.Close(id, 0, c.Session, tree), 0, true);
    }
    static async Task BadCompression(string kind)
    {
        await using var host = await UpstreamLocalFixture.StartAsync(); host.Server.State.Options.EnableCompression = true;
        host.Server.State.Options.CompressionPreference = [SmbCompressionAlgorithm.Lznt1];
        await using var c = await AuthWire.Connect(host.Server.Endpoint); await c.Negotiate(0x311, compressionAlgorithm: 1); await c.Login();
        var plain = c.Echo(); if (kind == "invalid-plain-id") plain[0] = 0x99;
        var frame = CompressLiterals(plain, 1, 0);
        if (kind == "short-transform") Array.Resize(ref frame, 12);
        if (kind == "invalid-algorithm") RawSmb.Put16(frame, 8, 0xffff);
        if (kind == "invalid-size") RawSmb.Put32(frame, 4, 32);
        await c.ExpectDisconnect(frame, raw: true);
    }
    // CompressionTest BasicSMB2Compression_Encrypted: encrypt the compression
    // transform, then independently decrypt/decompress the response. Neither
    // successful plain compression nor AEAD alone establishes this nesting.
    static async Task CompressedEncrypted(ushort algorithm)
    {
        await using var host = await UpstreamLocalFixture.StartAsync(); host.Server.State.Options.EnableCompression = true;
        host.Server.State.Options.CompressionPreference = [(SmbCompressionAlgorithm)algorithm];
        await using var c = await AuthWire.Connect(host.Server.Endpoint); await c.Negotiate(0x311, encryptionCipher: 2, compressionAlgorithm: algorithm); await c.Login();
        var tree = RawSmb.U32(await c.Encrypted(RawSmb.TreeConnect("\\\\localhost\\P0", 0, c.Session)), 36);
        var opened = await c.Encrypted(RawSmb.Create("encrypted-compressed", false, 0, c.Session, tree)); var id = (RawSmb.U64(opened, 128), RawSmb.U64(opened, 136));
        var bytes = System.Text.Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("abc", 100)));
        var written = await c.Encrypted(RawSmb.Write(id, bytes, 0, 0, c.Session, tree), compressionAlgorithm: algorithm);
        Check.Equal((uint)bytes.Length, RawSmb.U32(written, 68), "encrypted compressed WRITE count");
        var read = RawSmb.Read(id, (uint)bytes.Length, 0, 0, c.Session, tree); read[67] = 2;
        Check.That(ReadData(await c.Encrypted(read)).SequenceEqual(bytes), "encrypted compression roundtrip preserves source abc vector");
        await c.Encrypted(RawSmb.Close(id, 0, c.Session, tree));
        Check.That(!c.NonzeroEncryptedSignature, "encrypted compressed operations have zero inner SMB signatures");
    }
    // CompressionTest SMB2Compression_{In,}CompressibleReadResponse: the READ
    // flag is a distinct public input from the default plain READ path above.
    static async Task RequestedCompression(ushort algorithm, bool compressible)
    {
        await using var host = await UpstreamLocalFixture.StartAsync(); host.Server.State.Options.EnableCompression = true;
        host.Server.State.Options.CompressionPreference = [(SmbCompressionAlgorithm)algorithm];
        await using var c = await AuthWire.Connect(host.Server.Endpoint); await c.Negotiate(0x311, compressionAlgorithm: algorithm); await c.Login();
        var tree = RawSmb.U32(await c.Exchange(RawSmb.TreeConnect("\\\\localhost\\P0", 0, c.Session), 0, true), 36);
        var opened = await c.Exchange(RawSmb.Create("requested", false, 0, c.Session, tree), 0, true); var id = (RawSmb.U64(opened, 128), RawSmb.U64(opened, 136));
        var bytes = new byte[16385]; if (compressible) Array.Fill(bytes, (byte)'a'); else new Random(1234).NextBytes(bytes);
        await c.Exchange(RawSmb.Write(id, bytes, 0, 0, c.Session, tree), 0, true);
        var request = RawSmb.Read(id, (uint)bytes.Length, 0, 0, c.Session, tree); request[67] = 2;
        var read = await c.Exchange(request, 0, true);
        Check.That(ReadData(read).SequenceEqual(bytes), "REQUEST_COMPRESSED response has exact original bytes");
        Check.Equal(compressible, c.LastResponseCompressed, "upstream compressible/incompressible READ compression choice (SHOULD)");
        await c.Exchange(RawSmb.Close(id, 0, c.Session, tree), 0, true);
    }
    static async Task CompressionNegotiate(string kind)
    {
        await using var host = await UpstreamLocalFixture.StartAsync(); host.Server.State.Options.EnableCompression = true; host.Server.State.Options.CompressionPreference = [SmbCompressionAlgorithm.Lznt1];
        await using var c = await AuthWire.Connect(host.Server.Endpoint); var request = AuthWire.NegotiatePacket(0x311);
        Array.Resize(ref request, 154); RawSmb.Put16(request, 96, 3); RawSmb.Put16(request, 136, 3); RawSmb.Put16(request, 138, 10); RawSmb.Put16(request, 144, 1); RawSmb.Put16(request, 152, 1);
        if (kind == "unsupported-algorithm") RawSmb.Put16(request, 152, 0xffff);
        if (kind == "old-dialect") RawSmb.Put16(request, 100, 0x302);
        if (kind == "short-context") RawSmb.Put16(request, 138, 4);
        if (kind == "empty-algorithms") RawSmb.Put16(request, 144, 0);
        if (kind == "chained-not-supported") RawSmb.Put32(request, 148, 1);
        var response = await c.Exchange(request, kind is "short-context" or "empty-algorithms" ? Invalid : 0);
        if (kind is "short-context" or "empty-algorithms") return;
        if (kind == "old-dialect") { Check.Equal((ushort)0x302, RawSmb.U16(response, 68), "SMB302 ignores SMB311 context trailer"); return; }
        var at = (int)RawSmb.U32(response, 124); var count = RawSmb.U16(response, 70);
        for (var i = 0; i < count; i++)
        {
            Check.That(at >= 128 && at + 8 <= response.Length, "compression negotiate response context bounded");
            if (RawSmb.U16(response, at) == 3)
            {
                Check.Equal(0u, RawSmb.U32(response, at + 12), "unsupported chained flag withheld");
                Check.Equal(kind == "unsupported-algorithm" ? (ushort)0 : (ushort)1, RawSmb.U16(response, at + 8), "only common compression algorithms selected");
            }
            at += (8 + RawSmb.U16(response, at + 2) + 7) & ~7;
        }
    }
    static byte[] CompressLiterals(byte[] message, ushort algorithm, int prefix)
    {
        var payload = new List<byte>();
        for (var at = prefix; at < message.Length;)
        {
            var count = Math.Min(algorithm == 1 ? 4096 : 32, message.Length - at);
            if (algorithm == 1) { var header = (ushort)(0x3000 | count - 1); payload.Add((byte)header); payload.Add((byte)(header >> 8)); }
            else payload.AddRange(new byte[4]); // Thirty-two literal tokens, no match bits.
            payload.AddRange(message.AsSpan(at, count).ToArray()); at += count;
        }
        var b = new byte[16 + prefix + payload.Count]; new byte[] { 0xfc, 0x53, 0x4d, 0x42 }.CopyTo(b, 0);
        RawSmb.Put32(b, 4, (uint)(message.Length - prefix)); RawSmb.Put16(b, 8, algorithm); RawSmb.Put32(b, 12, (uint)prefix);
        message.AsSpan(0, prefix).CopyTo(b.AsSpan(16)); payload.ToArray().CopyTo(b, 16 + prefix); return b;
    }
    static byte[] DecodeCompression(byte[] frame)
    {
        Check.That(frame.Length >= 16 && RawSmb.U16(frame, 10) == 0, "unchained compression response");
        var algorithm = RawSmb.U16(frame, 8); var prefix = checked((int)RawSmb.U32(frame, 12)); var size = checked((int)RawSmb.U32(frame, 4));
        Check.That(prefix >= 0 && size >= 0 && prefix + size <= 2 * 1024 * 1024 && 16 + prefix <= frame.Length, "bounded decompressed size");
        var result = new List<byte>(prefix + size); result.AddRange(frame.AsSpan(16, prefix).ToArray()); var cursor = 16 + prefix;
        if (algorithm == 1)
        {
            while (result.Count < prefix + size)
            {
                Check.That(cursor + 2 <= frame.Length, "LZNT1 chunk header"); var header = RawSmb.U16(frame, cursor); cursor += 2;
                var end = cursor + (header & 4095) + 1; Check.That(end <= frame.Length, "LZNT1 chunk bound"); var start = result.Count;
                if ((header & 0x8000) == 0) { result.AddRange(frame.AsSpan(cursor, end - cursor).ToArray()); cursor = end; continue; }
                while (cursor < end)
                {
                    var flags = frame[cursor++];
                    for (var bit = 0; bit < 8 && cursor < end; bit++)
                    {
                        if ((flags & 1 << bit) == 0) result.Add(frame[cursor++]);
                        else
                        {
                            Check.That(cursor + 2 <= end, "LZNT1 token"); var token = RawSmb.U16(frame, cursor); cursor += 2;
                            var shift = 12; for (var position = result.Count - start - 1; position >= 16; position >>= 1) shift--;
                            var length = (token & (1 << shift) - 1) + 3; var distance = (token >> shift) + 1;
                            Check.That(distance <= result.Count - start, "LZNT1 backreference");
                            for (var i = 0; i < length; i++) result.Add(result[result.Count - distance]);
                        }
                        Check.That(result.Count <= prefix + size, "LZNT1 expansion bounded");
                    }
                }
            }
        }
        else if (algorithm == 2)
        {
            var bits = 0; uint flags = 0; var nibbleAt = -1;
            while (result.Count < prefix + size)
            {
                if (bits == 0) { Check.That(cursor + 4 <= frame.Length, "LZ77 flags"); flags = RawSmb.U32(frame, cursor); cursor += 4; bits = 32; }
                if ((flags & 1u << --bits) == 0) { Check.That(cursor < frame.Length, "LZ77 literal"); result.Add(frame[cursor++]); continue; }
                Check.That(cursor + 2 <= frame.Length, "LZ77 match"); var token = RawSmb.U16(frame, cursor); cursor += 2; var distance = (token >> 3) + 1; var length = token & 7;
                if (length == 7)
                {
                    if (nibbleAt < 0) { nibbleAt = cursor; Check.That(cursor < frame.Length, "LZ77 nibble"); length = frame[cursor++] & 15; }
                    else { length = frame[nibbleAt] >> 4; nibbleAt = -1; }
                    if (length == 15)
                    {
                        Check.That(cursor < frame.Length, "LZ77 length"); length = frame[cursor++];
                        if (length == 255) { Check.That(cursor + 2 <= frame.Length, "LZ77 extended length"); length = RawSmb.U16(frame, cursor); cursor += 2; if (length == 0) { length = checked((int)RawSmb.U32(frame, cursor)); cursor += 4; } length -= 22; }
                        length += 15;
                    }
                    length += 7;
                }
                length += 3; Check.That(distance <= result.Count - prefix && result.Count + length <= prefix + size, "LZ77 match bounds");
                for (var i = 0; i < length; i++) result.Add(result[result.Count - distance]);
            }
        }
        else throw new InvalidOperationException("Unrequested compression algorithm " + algorithm);
        Check.Equal(prefix + size, result.Count, "exact decompressed message size"); return result.ToArray();
    }
}
