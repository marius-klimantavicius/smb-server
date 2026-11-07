using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Smb.Crypto;

public static class Sp800108CounterKdf
{
	private const int PrfOutputBytes = 32;

	public static byte[] DeriveKey(ReadOnlySpan<byte> keyDerivationKey, ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, int outputBytes)
	{
		if (outputBytes <= 0)
		{
			throw new ArgumentOutOfRangeException(nameof(outputBytes));
		}

		var value = outputBytes * 8;
		var num = (outputBytes + PrfOutputBytes - 1) / PrfOutputBytes;
		var num2 = label.Length + 1 + context.Length + 4;
		var bytesWritten = 4 + num2;
		Span<byte> span = stackalloc byte[bytesWritten];
		label.CopyTo(span.Slice(4));
		span[4 + label.Length] = 0;
		context.CopyTo(span.Slice(4 + label.Length + 1));
		BinaryPrimitives.WriteUInt32BigEndian(span.Slice(4 + label.Length + 1 + context.Length), (uint)value);
		using var hMACSHA = new HMACSHA256(keyDerivationKey.ToArray());
		var array = new byte[num * PrfOutputBytes];
		Span<byte> destination = stackalloc byte[PrfOutputBytes];
		for (var i = 1; i <= num; i++)
		{
			BinaryPrimitives.WriteUInt32BigEndian(span.Slice(0, 4), (uint)i);
			if (!hMACSHA.TryComputeHash(span, destination, out bytesWritten))
			{
				throw new CryptographicException("HMAC computation failed.");
			}

			destination.CopyTo(array.AsSpan((i - 1) * PrfOutputBytes));
		}

		if (array.Length == outputBytes)
		{
			return array;
		}

		var array2 = new byte[outputBytes];
		Array.Copy(array, array2, outputBytes);
		return array2;
	}
}
