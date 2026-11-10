using System;
using System.Buffers.Binary;
using System.Globalization;
using System.Text;

namespace Smb.Auth.Ldap;

public static class SidConverter
{
    private const byte SidRevision = 1;

    private const int MaxSubAuthorities = 15;

    public static bool TryToString(ReadOnlySpan<byte> binary, out string sid)
    {
        sid = string.Empty;
        if (binary.Length < 8)
        {
            return false;
        }

        var value = binary[0];
        int num = binary[1];
        if (num > MaxSubAuthorities)
        {
            return false;
        }

        if (binary.Length < 8 + 4 * num)
        {
            return false;
        }

        var num2 = 0uL;
        for (var i = 2; i < 8; i++)
        {
            num2 = (num2 << 8) | binary[i];
        }

        var stringBuilder = new StringBuilder(16 + num * 11);
        stringBuilder.Append("S-").Append(value).Append('-');
        if (num2 <= uint.MaxValue)
        {
            stringBuilder.Append(num2.ToString(CultureInfo.InvariantCulture));
        }
        else
        {
            stringBuilder.Append("0x").Append(num2.ToString("X12", CultureInfo.InvariantCulture));
        }

        for (var j = 0; j < num; j++)
        {
            var num3 = BinaryPrimitives.ReadUInt32LittleEndian(binary.Slice(8 + 4 * j, 4));
            stringBuilder.Append('-').Append(num3.ToString(CultureInfo.InvariantCulture));
        }

        sid = stringBuilder.ToString();
        return true;
    }

    public static bool TryToBinary(string? sid, out byte[] binary)
    {
        binary = Array.Empty<byte>();
        if (string.IsNullOrEmpty(sid))
        {
            return false;
        }

        var array = sid.Split('-');
        if (array.Length < 3 || !array[0].Equals("S", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!byte.TryParse(array[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var result))
        {
            return false;
        }

        if (!TryParseAuthority(array[2], out var authority))
        {
            return false;
        }

        var num = array.Length - 3;
        if (num > MaxSubAuthorities)
        {
            return false;
        }

        var array2 = new uint[num];
        for (var i = 0; i < num; i++)
        {
            if (!uint.TryParse(array[3 + i], NumberStyles.Integer, CultureInfo.InvariantCulture, out array2[i]))
            {
                return false;
            }
        }

        var array3 = new byte[8 + 4 * num];
        array3[0] = result;
        array3[1] = (byte)num;
        for (var j = 0; j < 6; j++)
        {
            array3[7 - j] = (byte)((authority >> 8 * j) & 0xFF);
        }

        for (var k = 0; k < num; k++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(array3.AsSpan(8 + 4 * k, 4), array2[k]);
        }

        binary = array3;
        return true;
    }

    public static string ToLdapFilterValue(ReadOnlySpan<byte> binary)
    {
        var stringBuilder = new StringBuilder(binary.Length * 3);
        var readOnlySpan = binary;
        for (var i = 0; i < readOnlySpan.Length; i++)
        {
            var b = readOnlySpan[i];
            stringBuilder.Append('\\').Append(b.ToString("x2", CultureInfo.InvariantCulture));
        }

        return stringBuilder.ToString();
    }

    private static bool TryParseAuthority(string text, out ulong authority)
    {
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return ulong.TryParse(text.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out authority);
        }

        return ulong.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out authority);
    }
}
