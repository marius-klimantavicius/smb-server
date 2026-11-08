using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Smb.Testing;

// Independent SMB2.0.2 byte fixtures. Offsets/sizes from MS-SMB2 rev 88 §§2.2.1–2.2.34.
// Do not call server request/response serializers here. Auth tokens alone use the existing auth client.
public static class RawSmb
{
    public static ushort U16(byte[] b, int p) => BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(p, 2));
    public static uint U32(byte[] b, int p) => BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(p, 4));
    public static ulong U64(byte[] b, int p) => BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(p, 8));
    public static void Put16(byte[] b, int p, ushort v) => BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(p, 2), v);
    public static void Put32(byte[] b, int p, uint v) => BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(p, 4), v);
    public static void Put64(byte[] b, int p, ulong v) => BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(p, 8), v);
    public static byte[] Header(ushort command, int bodyLength, ulong mid, ulong session = 0, uint tree = 0)
    {
        var b = new byte[64 + bodyLength];
        b[0] = 0xfe; b[1] = (byte)'S'; b[2] = (byte)'M'; b[3] = (byte)'B';
        Put16(b, 4, 64); Put16(b, 12, command); Put16(b, 14, 32);
        Put64(b, 24, mid); Put32(b, 36, tree); Put64(b, 40, session);
        return b;
    }
    public static byte[] Negotiate(ulong mid = 0)
    {
        var b = Header(0, 38, mid); Put16(b, 64, 36); Put16(b, 66, 1); Put16(b, 68, 1);
        Convert.FromHexString("00112233445566778899AABBCCDDEEFF").CopyTo(b, 76);
        Put16(b, 100, 0x0202); return b;
    }
    public static byte[] SessionSetup(byte[] token, ulong mid, ulong session = 0)
    {
        var b = Header(1, 24 + token.Length, mid, session); Put16(b, 64, 25); b[67] = 1;
        Put16(b, 76, 88); Put16(b, 78, checked((ushort)token.Length)); token.CopyTo(b, 88); return b;
    }
    public static byte[] TreeConnect(string unc, ulong mid, ulong session)
    {
        var name = Encoding.Unicode.GetBytes(unc); var b = Header(3, 8 + name.Length, mid, session);
        Put16(b, 64, 9); Put16(b, 68, 72); Put16(b, 70, checked((ushort)name.Length)); name.CopyTo(b, 72); return b;
    }
    public static byte[] Create(string path, bool directory, ulong mid, ulong session, uint tree)
    {
        var name = Encoding.Unicode.GetBytes(path); var b = Header(5, 56 + Math.Max(name.Length, 1), mid, session, tree);
        Put16(b, 64, 57); Put32(b, 68, 2); Put32(b, 88, 3); // Impersonation; read+write data/list-directory
        Put32(b, 92, directory ? 0x10u : 0x80u); Put32(b, 96, 7); Put32(b, 100, directory ? 1u : 3u);
        Put32(b, 104, directory ? 1u : 0x40u); Put16(b, 108, 120); Put16(b, 110, checked((ushort)name.Length));
        name.CopyTo(b, 120); return b;
    }
    public static byte[] Read((ulong P, ulong V) id, uint length, ulong offset, ulong mid, ulong session, uint tree, uint minimum = 0)
    {
        var b = Header(8, 49, mid, session, tree); Put16(b, 64, 49); Put32(b, 68, length); Put64(b, 72, offset);
        Id(b, 80, id); Put32(b, 96, minimum); return b;
    }
    public static byte[] Write((ulong P, ulong V) id, byte[] data, ulong offset, ulong mid, ulong session, uint tree)
    {
        var b = Header(9, 48 + Math.Max(1, data.Length), mid, session, tree); Put16(b, 64, 49); Put16(b, 66, 112);
        Put32(b, 68, (uint)data.Length); Put64(b, 72, offset); Id(b, 80, id); data.CopyTo(b, 112); return b;
    }
    public static byte[] Close((ulong P, ulong V) id, ulong mid, ulong session, uint tree)
    {
        var b = Header(6, 24, mid, session, tree); Put16(b, 64, 24); Id(b, 72, id); return b;
    }
    public static byte[] Enumerate((ulong P, ulong V) id, ulong mid, ulong session, uint tree, string pattern = "*", byte flags = 1)
    {
        var name = Encoding.Unicode.GetBytes(pattern); var b = Header(14, 32 + name.Length, mid, session, tree);
        Put16(b, 64, 33); b[66] = 12; b[67] = flags; Id(b, 72, id); // FileNamesInformation, MS-FSCC 2.4.33
        Put16(b, 88, 96); Put16(b, 90, checked((ushort)name.Length)); Put32(b, 92, 4096); name.CopyTo(b, 96); return b;
    }
    public static byte[] TreeDisconnect(ulong mid, ulong session, uint tree)
    {
        var b = Header(4, 4, mid, session, tree); Put16(b, 64, 4); return b;
    }
    private static void Id(byte[] b, int p, (ulong P, ulong V) id) { Put64(b, p, id.P); Put64(b, p + 8, id.V); }
    public static void Sign(byte[] b, byte[] key)
    {
        Put32(b, 16, U32(b, 16) | 8); b.AsSpan(48, 16).Clear(); HMACSHA256.HashData(key, b).AsSpan(0, 16).CopyTo(b.AsSpan(48));
    }
    public static void Response(byte[] b, ushort command, ulong mid, uint status = 0, ushort? size = null)
    {
        Check.That(b.Length >= 64, "SMB2 response header truncated");
        Check.That(b.AsSpan(0, 4).SequenceEqual(new byte[] { 0xfe, 0x53, 0x4d, 0x42 }), "SMB2 signature");
        Check.Equal((ushort)64, U16(b, 4), "header StructureSize"); Check.Equal(command, U16(b, 12), "response command");
        Check.Equal(mid, U64(b, 24), "response MessageId"); Check.That((U32(b, 16) & 1) != 0, "server response flag");
        Check.Equal(status, U32(b, 8), $"NTSTATUS cmd={command}"); Check.Equal(0u, U32(b, 20), "standalone NextCommand");
        if (size is { } value) { Check.That(b.Length >= 66, "missing body"); Check.Equal(value, U16(b, 64), "body StructureSize"); }
    }
    public static byte[] Buffer(byte[] response, int offset, uint length)
    {
        Check.That(offset >= 64 && (ulong)offset + length <= (ulong)response.Length, "command-relative output bounds");
        return response.AsSpan(offset, checked((int)length)).ToArray();
    }
    public static string[] Names(byte[] buffer)
    {
        var names = new List<string>(); var cursor = 0;
        while (true)
        {
            Check.That(cursor + 12 <= buffer.Length, "FileNamesInformation fixed fields");
            var next = U32(buffer, cursor); var length = U32(buffer, cursor + 8);
            Check.That(length % 2 == 0 && (ulong)cursor + 12 + length <= (ulong)buffer.Length, "directory name bounds/UTF16");
            names.Add(Encoding.Unicode.GetString(buffer, cursor + 12, checked((int)length)));
            if (next == 0) return names.ToArray();
            Check.That(next % 8 == 0 && next >= 12 + length, "directory next offset/alignment");
            cursor = checked(cursor + (int)next);
        }
    }
}
