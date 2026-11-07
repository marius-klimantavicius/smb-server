using System;
using System.Buffers.Binary;

namespace Smb.Protocol.Messages;

public readonly struct LeaseKey(ulong lo, ulong hi) : IEquatable<LeaseKey>
{
	public const int Size = 16;

	private readonly ulong _lo = lo;

	private readonly ulong _hi = hi;

	public bool IsZero
	{
		get
		{
			if (_lo == 0L)
			{
				return _hi == 0;
			}

			return false;
		}
	}

	public static LeaseKey From(ReadOnlySpan<byte> bytes)
	{
		if (bytes.Length != Size)
		{
			throw new ArgumentException($"LeaseKey requires {Size} bytes, got {bytes.Length}.", nameof(bytes));
		}

		return new LeaseKey(BinaryPrimitives.ReadUInt64LittleEndian(bytes), BinaryPrimitives.ReadUInt64LittleEndian(bytes.Slice(8)));
	}

	public void WriteTo(Span<byte> dest)
	{
		if (dest.Length < Size)
		{
			throw new ArgumentException($"Destination needs at least {Size} bytes.", nameof(dest));
		}

		BinaryPrimitives.WriteUInt64LittleEndian(dest, _lo);
		BinaryPrimitives.WriteUInt64LittleEndian(dest.Slice(8), _hi);
	}

	public byte[] ToBytes()
	{
		var array = new byte[Size];
		WriteTo(array);
		return array;
	}

	public bool Equals(LeaseKey other)
	{
		if (_lo == other._lo)
		{
			return _hi == other._hi;
		}

		return false;
	}

	public override bool Equals(object? obj)
	{
		if (obj is LeaseKey other)
		{
			return Equals(other);
		}

		return false;
	}

	public override int GetHashCode()
	{
		return HashCode.Combine(_lo, _hi);
	}

	public static bool operator ==(LeaseKey left, LeaseKey right)
	{
		return left.Equals(right);
	}

	public static bool operator !=(LeaseKey left, LeaseKey right)
	{
		return !left.Equals(right);
	}

	public override string ToString()
	{
		return Convert.ToHexString(ToBytes());
	}
}
