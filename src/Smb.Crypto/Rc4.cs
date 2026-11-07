using System;

namespace Smb.Crypto;

public static class Rc4
{
	public static byte[] Transform(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
	{
		Span<byte> span = stackalloc byte[256];
		for (var i = 0; i < 256; i++)
		{
			span[i] = (byte)i;
		}

		var num = 0;
		for (var j = 0; j < 256; j++)
		{
			num = (num + span[j] + key[j % key.Length]) & 0xFF;
			ref var reference = ref span[j];
			ref var reference2 = ref span[num];
			var b = span[num];
			var b2 = span[j];
			reference = b;
			reference2 = b2;
		}

		var array = new byte[data.Length];
		var num2 = 0;
		var num3 = 0;
		for (var k = 0; k < data.Length; k++)
		{
			num2 = (num2 + 1) & 0xFF;
			num3 = (num3 + span[num2]) & 0xFF;
			ref var reference = ref span[num2];
			ref var reference3 = ref span[num3];
			var b2 = span[num3];
			var b = span[num2];
			reference = b2;
			reference3 = b;
			var b3 = span[(span[num2] + span[num3]) & 0xFF];
			array[k] = (byte)(data[k] ^ b3);
		}

		return array;
	}
}
