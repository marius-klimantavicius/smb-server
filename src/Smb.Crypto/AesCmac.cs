using System;
using System.Security.Cryptography;

namespace Smb.Crypto;

public static class AesCmac
{
	private const int BlockSize = 16;

	private const byte Rb = 135;

	public static byte[] Compute(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message)
	{
		var array = new byte[BlockSize];
		Compute(key, message, array);
		return array;
	}

	public static void Compute(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> destination)
	{
		if (destination.Length < BlockSize)
		{
			throw new ArgumentException($"Destination requires at least {BlockSize} bytes.", nameof(destination));
		}

		using var aes = Aes.Create();
		aes.Mode = CipherMode.ECB;
		aes.Padding = PaddingMode.None;
		aes.Key = key.ToArray();
		Span<byte> span = stackalloc byte[BlockSize];
		Span<byte> span2 = stackalloc byte[BlockSize];
		span2.Clear();
		aes.EncryptEcb(span2, span, PaddingMode.None);
		Span<byte> span3 = stackalloc byte[BlockSize];
		Span<byte> span4 = stackalloc byte[BlockSize];
		LeftShiftWithRb(span, span3);
		LeftShiftWithRb(span3, span4);
		var num = ((message.Length == 0) ? 1 : ((message.Length + BlockSize - 1) / BlockSize));
		var flag = message.Length != 0 && message.Length % BlockSize == 0;
		Span<byte> span5 = stackalloc byte[BlockSize];
		var num2 = (num - 1) * BlockSize;
		if (flag)
		{
			Xor(message.Slice(num2, BlockSize), span3, span5);
		}
		else
		{
			var num3 = message.Length - num2;
			span5.Clear();
			message.Slice(num2, num3).CopyTo(span5);
			span5[num3] = 128;
			Xor(span5, span4, span5);
		}

		Span<byte> span6 = stackalloc byte[BlockSize];
		span6.Clear();
		Span<byte> span7 = stackalloc byte[BlockSize];
		for (var i = 0; i < num - 1; i++)
		{
			Xor(span6, message.Slice(i * BlockSize, BlockSize), span7);
			aes.EncryptEcb(span7, span6, PaddingMode.None);
		}

		Xor(span6, span5, span7);
		aes.EncryptEcb(span7, span6, PaddingMode.None);
		span6.CopyTo(destination.Slice(0, BlockSize));
	}

	private static void Xor(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> dst)
	{
		for (var i = 0; i < BlockSize; i++)
		{
			dst[i] = (byte)(a[i] ^ b[i]);
		}
	}

	private static void LeftShiftWithRb(ReadOnlySpan<byte> input, Span<byte> output)
	{
		var b = (((input[0] & 0x80) != 0) ? ((byte)1) : ((byte)0));
		for (var i = 0; i < BlockSize; i++)
		{
			var b2 = (byte)((i + 1 < BlockSize) ? ((uint)((input[i + 1] >> 7) & 1)) : 0u);
			output[i] = (byte)((input[i] << 1) | b2);
		}

		if (b == 1)
		{
			output[BlockSize - 1] ^= Rb;
		}
	}
}
