using System;
using System.Buffers.Binary;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Compression;

public static class Lznt1
{
	public const int MinMatch = 3;

	public const int ChunkSize = 4096;

	private const ushort SignatureBits = 12288;

	private const ushort CompressedBit = 32768;

	private const ushort SizeMask = 4095;

	private const int HashBits = 13;

	private const int HashSize = 8192;

	private const int MaxChain = 64;

	public static byte[] Decompress(ReadOnlySpan<byte> input, int originalSize)
	{
		if (originalSize < 0)
		{
			throw new SmbWireFormatException("Negative original size.");
		}

		var array = new byte[originalSize];
		var num = 0;
		var num2 = 0;
		while (num2 < originalSize)
		{
			if (num + 2 > input.Length)
			{
				throw new SmbWireFormatException("Truncated LZNT1 chunk header.");
			}

			var num3 = BinaryPrimitives.ReadUInt16LittleEndian(input.Slice(num));
			num += 2;
			if (num3 == 0)
			{
				break;
			}

			var num4 = (num3 & SizeMask) + 1;
			var flag = (num3 & CompressedBit) != 0;
			if (num + num4 > input.Length)
			{
				throw new SmbWireFormatException("Truncated LZNT1 chunk.");
			}

			var chunk = input.Slice(num, num4);
			num += num4;
			if (!flag)
			{
				if (num2 + num4 > originalSize)
				{
					throw new SmbWireFormatException("LZNT1 uncompressed chunk overruns declared size.");
				}

				chunk.CopyTo(array.AsSpan(num2));
				num2 += num4;
			}
			else
			{
				num2 = DecompressChunk(chunk, array, num2, originalSize);
			}
		}

		return array;
	}

	private static int DecompressChunk(ReadOnlySpan<byte> chunk, byte[] output, int outStart, int originalSize)
	{
		var num = 0;
		var num2 = outStart;
		var num3 = 0;
		while (num < chunk.Length)
		{
			var b = chunk[num++];
			for (var i = 0; i < 8; i++)
			{
				if (num >= chunk.Length)
				{
					break;
				}

				if ((b & (1 << i)) == 0)
				{
					if (num2 >= originalSize)
					{
						throw new SmbWireFormatException("LZNT1 literal overruns declared size.");
					}

					output[num2++] = chunk[num++];
					num3++;
					continue;
				}

				if (num + 2 > chunk.Length)
				{
					throw new SmbWireFormatException("Truncated LZNT1 match token.");
				}

				var num4 = BinaryPrimitives.ReadUInt16LittleEndian(chunk.Slice(num));
				num += 2;
				var num5 = SplitFor(num3);
				var num6 = (num4 & ((1 << num5) - 1)) + MinMatch;
				var num7 = (num4 >> num5) + 1;
				if (num7 > num3)
				{
					throw new SmbWireFormatException("LZNT1 back-reference before start of chunk.");
				}

				if (num2 + num6 > originalSize)
				{
					throw new SmbWireFormatException("LZNT1 match overruns declared size.");
				}

				var num8 = num2 - num7;
				for (var j = 0; j < num6; j++)
				{
					output[num2 + j] = output[num8 + j];
				}

				num2 += num6;
				num3 += num6;
			}
		}

		return num2;
	}

	public static byte[] Compress(ReadOnlySpan<byte> input)
	{
		var growableWriter = new GrowableWriter(input.Length + input.Length / 8 + 16);
		int num;
		for (var i = 0; i < input.Length; i += num)
		{
			num = Math.Min(ChunkSize, input.Length - i);
			var readOnlySpan = input.Slice(i, num);
			var array = CompressChunk(readOnlySpan);
			if (array != null && array.Length < num)
			{
				growableWriter.WriteUInt16((ushort)(SignatureBits | CompressedBit | (array.Length - 1)));
				growableWriter.WriteBytes(array);
			}
			else
			{
				growableWriter.WriteUInt16((ushort)(SignatureBits | (num - 1)));
				growableWriter.WriteBytes(readOnlySpan);
			}
		}

		return growableWriter.ToArray();
	}

	private static byte[]? CompressChunk(ReadOnlySpan<byte> chunk)
	{
		var length = chunk.Length;
		var growableWriter = new GrowableWriter(length);
		var array = new int[HashSize];
		var prev = new int[length];
		Array.Fill(array, -1);
		var num = 0;
		while (num < length)
		{
			var position = growableWriter.Position;
			growableWriter.WriteByte(0);
			byte b = 0;
			for (var i = 0; i < 8; i++)
			{
				if (num >= length)
				{
					break;
				}

				var num2 = SplitFor(num);
				var maxDistance = 1 << 16 - num2;
				var maxLength = Math.Min((1 << num2) - 1 + MinMatch, length - num);
				var (num3, num4) = FindMatch(chunk, num, maxDistance, maxLength, array, prev);
				if (num3 >= MinMatch)
				{
					b |= (byte)(1 << i);
					growableWriter.WriteUInt16((ushort)((num4 - 1 << num2) | (num3 - MinMatch)));
					Insert(chunk, array, prev, num, num3);
					num += num3;
				}
				else
				{
					growableWriter.WriteByte(chunk[num]);
					Insert(chunk, array, prev, num, 1);
					num++;
				}

				if (growableWriter.Position >= length)
				{
					return null;
				}
			}

			growableWriter.PatchByte(position, b);
		}

		return growableWriter.ToArray();
	}

	private static int SplitFor(int chunkOutputLength)
	{
		var num = 12;
		var num2 = 16;
		while (chunkOutputLength > num2)
		{
			num--;
			num2 <<= 1;
		}

		return num;
	}

	private static int Hash(ReadOnlySpan<byte> d, int pos)
	{
		return ((d[pos] << 16) | (d[pos + 1] << 8) | d[pos + 2]) * -1640531535 >>> (32 - HashBits);
	}

	private static void Insert(ReadOnlySpan<byte> data, int[] head, int[] prev, int pos, int length)
	{
		var num = pos + length;
		for (var i = pos; i < num && i + 2 < data.Length; i++)
		{
			var num2 = Hash(data, i);
			prev[i] = head[num2];
			head[num2] = i;
		}
	}

	private static (int Length, int Distance) FindMatch(ReadOnlySpan<byte> data, int pos, int maxDistance, int maxLength, int[] head, int[] prev)
	{
		if (maxLength < MinMatch)
		{
			return (Length: 0, Distance: 0);
		}

		var num = Math.Max(0, pos - maxDistance);
		var num2 = head[Hash(data, pos)];
		var num3 = 0;
		var item = 0;
		var num4 = MaxChain;
		while (num2 >= num && num4-- > 0)
		{
			var num5 = MatchLength(data, num2, pos, maxLength);
			if (num5 > num3)
			{
				num3 = num5;
				item = pos - num2;
				if (num5 >= maxLength)
				{
					break;
				}
			}

			num2 = prev[num2];
		}

		if (num3 < MinMatch)
		{
			return (Length: 0, Distance: 0);
		}

		return (Length: num3, Distance: item);
	}

	private static int MatchLength(ReadOnlySpan<byte> data, int a, int b, int maxLength)
	{
		int i;
		for (i = 0; i < maxLength && data[a + i] == data[b + i]; i++)
		{
		}

		return i;
	}
}
