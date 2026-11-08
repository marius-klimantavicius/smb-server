using System;
using System.Buffers.Binary;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Compression;

public static class PlainLz77
{
	private ref struct HashMatcher
	{
		private const int HashBits = 15;

		private const int HashSize = 32768;

		private const int MaxChain = 32;

		private readonly ReadOnlySpan<byte> _data;

		private readonly int[] _head;

		private readonly int[] _prev;

		public HashMatcher(ReadOnlySpan<byte> data)
		{
			_data = data;
			_head = new int[HashSize];
			_prev = new int[data.Length];
			Array.Fill(_head, -1);
		}

		private static int Hash(ReadOnlySpan<byte> d, int pos)
		{
			return ((d[pos] << 16) | (d[pos + 1] << 8) | d[pos + 2]) * -1640531535 >>> (32 - HashBits);
		}

		public void Insert(int pos, int length)
		{
			var num = pos + length;
			for (var i = pos; i < num && i + 2 < _data.Length; i++)
			{
				var num2 = Hash(_data, i);
				_prev[i] = _head[num2];
				_head[num2] = i;
			}
		}

		public (int Length, int Distance) FindMatch(int pos)
		{
			if (pos + MinMatch > _data.Length)
			{
				return (Length: 0, Distance: 0);
			}

			var num = Hash(_data, pos);
			var num2 = _head[num];
			var num3 = Math.Max(0, pos - MaxDistance);
			var num4 = Math.Min(MaxMatch, _data.Length - pos);
			var num5 = 0;
			var item = 0;
			var num6 = MaxChain;
			while (num2 >= num3 && num6-- > 0)
			{
				var num7 = MatchLength(num2, pos, num4);
				if (num7 > num5)
				{
					num5 = num7;
					item = pos - num2;
					if (num7 >= num4)
					{
						break;
					}
				}

				num2 = _prev[num2];
			}

			if (num5 < MinMatch)
			{
				return (Length: 0, Distance: 0);
			}

			return (Length: num5, Distance: item);
		}

		private readonly int MatchLength(int a, int b, int maxLen)
		{
			int i;
			for (i = 0; i < maxLen && _data[a + i] == _data[b + i]; i++)
			{
			}

			return i;
		}
	}

	public const int MinMatch = 3;

	public const int MaxMatch = 264;

	public const int MaxDistance = 8192;

	public static byte[] Decompress(ReadOnlySpan<byte> input, int originalSize)
	{
		if (originalSize < 0)
		{
			throw new SmbWireFormatException("Negative original size.");
		}

		var array = new byte[originalSize];
		var num = 0;
		var num2 = 0;
		var num3 = 0u;
		var num4 = 0;
		var nibbleOffset = -1;
		while (num2 < array.Length)
		{
			if (num4 == 0)
			{
				if (num + 4 > input.Length)
				{
					throw new SmbWireFormatException("Truncated LZ77 flag group.");
				}

				num3 = BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(num));
				num += 4;
				num4 = 32;
			}

			num4--;
			if (((num3 >> num4) & 1) == 0)
			{
				if (num >= input.Length)
				{
					throw new SmbWireFormatException("Truncated LZ77 literal.");
				}

				array[num2++] = input[num++];
				continue;
			}

			if (num + 2 > input.Length)
			{
				throw new SmbWireFormatException("Truncated LZ77 match.");
			}

			var num5 = BinaryPrimitives.ReadUInt16LittleEndian(input.Slice(num));
			num += 2;
			var num6 = num5 & 7;
			var num7 = (num5 >> 3) + 1;
			if (num6 == 7)
			{
				int extended;
				if (nibbleOffset < 0)
				{
					if (num >= input.Length) throw new SmbWireFormatException("Truncated LZ77 length nibble.");
					nibbleOffset = num;
					extended = input[num++] & 15;
				}
				else { extended = input[nibbleOffset] >> 4; nibbleOffset = -1; }
				if (extended == 15)
				{
					if (num >= input.Length) throw new SmbWireFormatException("Truncated LZ77 length byte.");
					extended = input[num++];
					if (extended == 255)
					{
						if (num + 2 > input.Length) throw new SmbWireFormatException("Truncated LZ77 length word.");
						uint wide = BinaryPrimitives.ReadUInt16LittleEndian(input.Slice(num));
						num += 2;
						if (wide == 0)
						{
							if (num + 4 > input.Length) throw new SmbWireFormatException("Truncated LZ77 length dword.");
							wide = BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(num)); num += 4;
						}
						if (wide < 22 || wide > int.MaxValue - 3) throw new SmbWireFormatException("Invalid LZ77 extended length.");
						extended = (int)wide - 22;
					}
					extended += 15;
				}
				num6 = extended + 7;
			}

			num6 += MinMatch;
			if (num7 > num2)
			{
				throw new SmbWireFormatException("LZ77 distance before start of output.");
			}

			if (num6 > array.Length - num2)
			{
				throw new SmbWireFormatException("LZ77 match overruns the declared original size.");
			}

			var num10 = num2 - num7;
			for (var i = 0; i < num6; i++)
			{
				array[num2 + i] = array[num10 + i];
			}

			num2 += num6;
		}

		return array;
	}

	public static byte[] Compress(ReadOnlySpan<byte> input)
	{
		var output = new GrowableWriter(input.Length);
		var flagSlot = -1;
		var flags = 0u;
		var flagCount = 0;
		var nibbleSlot = -1;
		byte lowNibble = 0;
		var hashMatcher = new HashMatcher(input);
		var num = 0;
		while (num < input.Length)
		{
			if (flagCount == 0)
			{
				BeginGroup();
			}

			var (num2, distance) = hashMatcher.FindMatch(num);
			if (num2 >= MinMatch)
			{
				PushFlag(isMatch: true);
				WriteMatch(output, num2, distance, ref nibbleSlot, ref lowNibble);
				hashMatcher.Insert(num, num2);
				num += num2;
			}
			else
			{
				PushFlag(isMatch: false);
				output.WriteByte(input[num]);
				hashMatcher.Insert(num, 1);
				num++;
			}
		}

		if (flagSlot >= 0)
		{
			output.PatchUInt32(flagSlot, flags);
		}

		return output.ToArray();

		void BeginGroup()
		{
			flagSlot = output.Position;
			output.WriteUInt32(0u);
			flags = 0u;
			flagCount = 32;
		}

		void PushFlag(bool isMatch)
		{
			flagCount--;
			if (isMatch)
			{
				flags |= (uint)(1 << flagCount);
			}

			if (flagCount == 0)
			{
				output.PatchUInt32(flagSlot, flags);
				flagSlot = -1;
			}
		}
	}

	private static void WriteMatch(GrowableWriter output, int length, int distance, ref int nibbleSlot, ref byte lowNibble)
	{
		var num = length - MinMatch;
		var num2 = (ushort)(distance - 1 << 3);
		if (num < 7)
		{
			num2 |= (ushort)num;
			output.WriteUInt16(num2);
		}
		else
		{
			num2 |= 7;
			output.WriteUInt16(num2);
			var extended = num - 7;
			var nibble = (byte)Math.Min(15, extended);
			if (nibbleSlot < 0)
			{
				nibbleSlot = output.Position;
				lowNibble = nibble;
				output.WriteByte(nibble);
			}
			else { output.PatchByte(nibbleSlot, (byte)(lowNibble | nibble << 4)); nibbleSlot = -1; }
			if (extended >= 15) output.WriteByte((byte)(extended - 15));
		}
	}
}
