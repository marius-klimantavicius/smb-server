using System.Security.Cryptography;
using System.Text;
using Smb.Protocol.Enums;
using Smb.Server;
using Smb.Testing;

// Independent public SMB scenarios, Samba 2816d12d5346c4e6258d8263f68eb653fd44fd5e.
// Facet-level provenance and limitations: upstream-samba-continuation.md.
internal static partial class UpstreamSambaMoreTests
{
    const uint Ok = 0, Invalid = 0xc000000d, Denied = 0xc0000022, Missing = 0xc0000034,
        Collision = 0xc0000035, Sharing = 0xc0000043, Closed = 0xc0000128, Eof = 0xc0000011;
    const uint All = 0x0013019f;
    static readonly (ulong P, ulong V) Inherit = (ulong.MaxValue, ulong.MaxValue);
    static readonly byte[] Payload = "independent Samba continuation bytes"u8.ToArray();

    public static IEnumerable<(string Name, Func<Task> Run)> Cases()
    {
        foreach (var t in CompoundCases()) yield return t;
        foreach (var t in StreamCases()) yield return t;
        foreach (var t in FileCases()) yield return t;
        foreach (var t in CacheCases()) yield return t;
        foreach (var t in OplockCases()) yield return t;
        foreach (var t in InfoCases()) yield return t;
        foreach (var t in NamespaceCases()) yield return t;
        foreach (var t in ReplayCases()) yield return t;
        foreach (var t in AdditionalCases()) yield return t;
        foreach (var t in LeaseSequenceCases()) yield return t;
        foreach (var t in ChannelCacheCases()) yield return t;
        foreach (var t in CreditNotifyCases()) yield return t;
        foreach (var t in LockReplayCases()) yield return t;
        foreach (var t in RecoveryCases()) yield return t;
        foreach (var t in SecurityCases()) yield return t;
        foreach (var t in CompletionCases()) yield return t;
        foreach (var t in LeaseCompletionCases()) yield return t;
        foreach (var t in FinalCases()) yield return t;
        foreach (var t in NamespaceCompletionCases()) yield return t;
        foreach (var t in LifecycleCases()) yield return t;
        foreach (var t in ManyChannelCases()) yield return t;
    }
    static byte[] Create(string name = "file", uint disposition = 1, uint access = All,
        uint share = 7, bool directory = false)
    {
        var b = RawSmb.Create(name, directory, 0, 1, 42);
        RawSmb.Put32(b, 88, access); RawSmb.Put32(b, 96, share); RawSmb.Put32(b, 100, disposition); return b;
    }
    static void Status(byte[] b, uint expected, string why) => Check.Equal(expected, RawSmb.U32(b, 8), why);
    static (ulong P, ulong V) Id(byte[] b) { Status(b, Ok, "CREATE"); return (RawSmb.U64(b, 128), RawSmb.U64(b, 136)); }
    static async Task<(ulong P, ulong V)> Open(P2Tests.Direct d, string name = "file", uint disposition = 1,
        uint access = All, uint share = 7, bool directory = false)
        => Id(await d.Send(Create(name, disposition, access, share, directory)));
    static async Task Close(P2Tests.Direct d, (ulong P, ulong V) id)
        => Status(await d.Send(RawSmb.Close(id, 0, 1, 42)), Ok, "CLOSE");
    static async Task Write(P2Tests.Direct d, (ulong P, ulong V) id, byte[] bytes, ulong offset = 0)
    {
        var b = await d.Send(RawSmb.Write(id, bytes, offset, 0, 1, 42)); Status(b, Ok, "WRITE");
        Check.Equal((uint)bytes.Length, RawSmb.U32(b, 68), "complete WRITE");
    }
    static async Task Data(P2Tests.Direct d, (ulong P, ulong V) id, byte[] expected)
    {
        var b = await d.Send(RawSmb.Read(id, (uint)Math.Max(1, expected.Length + 1), 0, 0, 1, 42));
        Status(b, expected.Length == 0 ? Eof : Ok, "READ");
        if (expected.Length != 0) Check.That(RawSmb.Buffer(b, b[66], RawSmb.U32(b, 68)).SequenceEqual(expected), "exact independent data");
    }
    static byte[] Query((ulong P, ulong V) id, byte cls, uint max = 4096, byte type = 1)
    {
        var b = RawSmb.Header(16, 40, 0, 1, 42); RawSmb.Put16(b, 64, 41); b[66] = type; b[67] = cls;
        RawSmb.Put32(b, 68, max); RawSmb.Put64(b, 88, id.P); RawSmb.Put64(b, 96, id.V); return b;
    }
    static byte[] Output(byte[] b) { Status(b, Ok, "QUERY_INFO"); return RawSmb.Buffer(b, RawSmb.U16(b, 66), RawSmb.U32(b, 68)); }
    static byte[] Set((ulong P, ulong V) id, byte cls, byte[] data) => P5Tests.SetPacket(id, cls, data);
    static byte[] Rename((ulong P, ulong V) id, string name, bool replace = false)
    {
        var bytes = Encoding.Unicode.GetBytes(name); var data = new byte[Math.Max(24, 20 + bytes.Length)];
        data[0] = replace ? (byte)1 : (byte)0; RawSmb.Put32(data, 16, (uint)bytes.Length); bytes.CopyTo(data, 20); return Set(id, 10, data);
    }
    static byte[] Flush((ulong P, ulong V) id)
    { var b = RawSmb.Header(7, 24, 0, 1, 42); RawSmb.Put16(b, 64, 24); RawSmb.Put64(b, 72, id.P); RawSmb.Put64(b, 80, id.V); return b; }
    static byte[] Lock((ulong P, ulong V) id, ulong at, ulong length, uint flags = 18)
    {
        var b = RawSmb.Header(10, 48, 0, 1, 42); RawSmb.Put16(b, 64, 48); RawSmb.Put16(b, 66, 1);
        RawSmb.Put64(b, 72, id.P); RawSmb.Put64(b, 80, id.V); RawSmb.Put64(b, 88, at); RawSmb.Put64(b, 96, length); RawSmb.Put32(b, 104, flags); return b;
    }
    static byte[] Enum((ulong P, ulong V) id, string pattern = "*", byte flags = 1, byte cls = 12, uint max = 4096)
    {
        var b = RawSmb.Enumerate(id, 0, 1, 42, pattern); b[66] = cls; b[67] = flags; RawSmb.Put32(b, 92, max); return b;
    }
    // Fresh message IDs are taken through signed ECHOs; compound pieces are signed
    // independently, as required by MS-SMB2, with no injected credit-window state.
    static async Task<byte[]> Chain(P2Tests.Direct d, byte[][] packets, bool[]? related = null)
    {
        var joined = new List<byte>();
        for (var i = 0; i < packets.Length; i++)
        {
            var echo = RawSmb.Header(13, 4, 0, 1, 42); RawSmb.Put16(echo, 64, 4);
            var grant = await d.Send(echo); Status(grant, Ok, "obtain actual message-ID progression");
            // Use the next unspent ID, leaving one hole between each piece.
            var b = packets[i].ToArray(); RawSmb.Put64(b, 24, RawSmb.U64(grant, 24) + 100);
            Array.Resize(ref b, (b.Length + 7) & ~7); RawSmb.Put32(b, 20, i + 1 < packets.Length ? (uint)b.Length : 0);
            var inherit = related?[i] ?? i > 0;
            if (inherit) { RawSmb.Put32(b, 16, RawSmb.U32(b, 16) | 4); RawSmb.Put64(b, 40, ulong.MaxValue); RawSmb.Put32(b, 36, uint.MaxValue); }
            RawSmb.Sign(b, d.Session.SigningKey);
            if (d.Connection.Dialect >= SmbDialect.Smb300) { b.AsSpan(48, 16).Clear(); Smb.Crypto.AesCmac.Compute(d.Session.SigningKey, b).CopyTo(b, 48); }
            joined.AddRange(b);
        }
        var response = await d.Dispatcher.ProcessMessageAsync(d.Connection, joined.ToArray()); d.Connection.ResponseSent(response); return response;
    }
    static List<byte[]> Split(byte[] b, SmbDialect dialect = SmbDialect.Smb202)
    {
        var result = new List<byte[]>(); var at = 0;
        do
        {
            var next = RawSmb.U32(b, at + 20); var n = next == 0 ? b.Length - at : checked((int)next);
            Check.That(n >= 64 && at + n <= b.Length && (next == 0 || (next & 7) == 0), "bounded aligned compound response");
            var piece = b.AsSpan(at, n).ToArray(); var sig = piece.AsSpan(48, 16).ToArray(); piece.AsSpan(48, 16).Clear();
            if ((RawSmb.U32(piece, 16) & 8) != 0)
                Check.That((dialect >= SmbDialect.Smb300 ? Smb.Crypto.AesCmac.Compute(new byte[16], piece) : HMACSHA256.HashData(new byte[16], piece)).AsSpan(0, 16).SequenceEqual(sig), "independent per-component signature");
            else Check.That(RawSmb.U64(piece, 40) == ulong.MaxValue || RawSmb.U32(piece, 8) == 0x103 && (RawSmb.U32(piece, 16) & 2) != 0, "unsigned response is an async interim or has no resolved signing context");
            sig.CopyTo(piece, 48); result.Add(piece); at += n; if (next == 0) break;
        } while (at < b.Length);
        return result;
    }
}
