using System;

namespace Smb.Crypto;

public static class Md4
{
	public static byte[] Compute(ReadOnlySpan<byte> input)
	{
		var num = 1732584193u;
		var num2 = 4023233417u;
		var num3 = 2562383102u;
		var num4 = 271733878u;
		var num5 = input.Length * 8L;
		var num6 = ((input.Length + 8) / 64 + 1) * 64;
		var array = new byte[num6];
		input.CopyTo(array);
		array[input.Length] = 128;
		for (var i = 0; i < 8; i++)
		{
			array[num6 - 8 + i] = (byte)(num5 >> 8 * i);
		}

		Span<uint> span = stackalloc uint[16];
		for (var j = 0; j < num6; j += 64)
		{
			for (var k = 0; k < 16; k++)
			{
				var num7 = j + k * 4;
				span[k] = (uint)(array[num7] | (array[num7 + 1] << 8) | (array[num7 + 2] << 16) | (array[num7 + 3] << 24));
			}

			var num8 = num;
			var num9 = num2;
			var num10 = num3;
			var num11 = num4;
			ReadOnlySpan<int> array2 = [0, 4, 8, 12];
			foreach (var num12 in array2)
			{
				num = Round1(num, num2, num3, num4, span[num12], 3);
				num4 = Round1(num4, num, num2, num3, span[num12 + 1], 7);
				num3 = Round1(num3, num4, num, num2, span[num12 + 2], 11);
				num2 = Round1(num2, num3, num4, num, span[num12 + 3], 19);
			}

			array2 = [0, 1, 2, 3];
			foreach (var num13 in array2)
			{
				num = Round2(num, num2, num3, num4, span[num13], 3);
				num4 = Round2(num4, num, num2, num3, span[num13 + 4], 5);
				num3 = Round2(num3, num4, num, num2, span[num13 + 8], 9);
				num2 = Round2(num2, num3, num4, num, span[num13 + 12], 13);
			}

			array2 = [0, 2, 1, 3];
			foreach (var num14 in array2)
			{
				num = Round3(num, num2, num3, num4, span[num14], 3);
				num4 = Round3(num4, num, num2, num3, span[num14 + 8], 9);
				num3 = Round3(num3, num4, num, num2, span[num14 + 4], 11);
				num2 = Round3(num2, num3, num4, num, span[num14 + 12], 15);
			}

			num += num8;
			num2 += num9;
			num3 += num10;
			num4 += num11;
		}

		var array3 = new byte[16];
		WriteLe(array3, 0, num);
		WriteLe(array3, 4, num2);
		WriteLe(array3, 8, num3);
		WriteLe(array3, 12, num4);
		return array3;
	}

	private static uint Round1(uint a, uint b, uint c, uint d, uint xk, int s)
	{
		return Rol(a + F(b, c, d) + xk, s);
	}

	private static uint Round2(uint a, uint b, uint c, uint d, uint xk, int s)
	{
		return Rol(a + G(b, c, d) + xk + 1518500249, s);
	}

	private static uint Round3(uint a, uint b, uint c, uint d, uint xk, int s)
	{
		return Rol(a + H(b, c, d) + xk + 1859775393, s);
	}

	private static uint F(uint x, uint y, uint z)
	{
		return (x & y) | (~x & z);
	}

	private static uint G(uint x, uint y, uint z)
	{
		return (x & y) | (x & z) | (y & z);
	}

	private static uint H(uint x, uint y, uint z)
	{
		return x ^ y ^ z;
	}

	private static uint Rol(uint v, int s)
	{
		return (v << s) | (v >> 32 - s);
	}

	private static void WriteLe(byte[] buf, int off, uint v)
	{
		buf[off] = (byte)v;
		buf[off + 1] = (byte)(v >> 8);
		buf[off + 2] = (byte)(v >> 16);
		buf[off + 3] = (byte)(v >> 24);
	}
}
