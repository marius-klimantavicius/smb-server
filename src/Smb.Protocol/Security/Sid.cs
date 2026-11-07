using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Security;

public sealed class Sid : IEquatable<Sid>
{
	public const int MaxSubAuthorities = 15;

	private const ulong MaxAuthority = 281474976710655uL;

	private readonly uint[] _subAuthorities;

	public byte Revision { get; }

	public ulong IdentifierAuthority { get; }

	public IReadOnlyList<uint> SubAuthorities => _subAuthorities;

	public int BinaryLength => 8 + 4 * _subAuthorities.Length;

	public static Sid Create(ulong identifierAuthority, params uint[] subAuthorities)
	{
		return new Sid(1, identifierAuthority, subAuthorities);
	}

	public Sid(byte revision, ulong identifierAuthority, params uint[] subAuthorities)
	{
		ArgumentNullException.ThrowIfNull(subAuthorities);
		if (subAuthorities.Length > MaxSubAuthorities)
		{
			throw new ArgumentException($"A SID has at most {MaxSubAuthorities} sub-authorities.", nameof(subAuthorities));
		}

		if (identifierAuthority > MaxAuthority)
		{
			throw new ArgumentOutOfRangeException(nameof(identifierAuthority), "IdentifierAuthority is a 48-bit value.");
		}

		Revision = revision;
		IdentifierAuthority = identifierAuthority;
		_subAuthorities = (uint[])subAuthorities.Clone();
	}

	public static Sid Parse(ReadOnlySpan<byte> data)
	{
		return Parse(data, out _);
	}

	public static Sid Parse(ReadOnlySpan<byte> data, out int consumed)
	{
		if (data.Length < 8)
		{
			throw new SmbWireFormatException($"SID too short: {data.Length} bytes.");
		}

		var revision = data[0];
		int num = data[1];
		if (num > MaxSubAuthorities)
		{
			throw new SmbWireFormatException($"SID SubAuthorityCount {num} > {MaxSubAuthorities}.");
		}

		var num2 = 8 + 4 * num;
		if (data.Length < num2)
		{
			throw new SmbWireFormatException($"SID needs {num2} bytes, has {data.Length}.");
		}

		var num3 = 0uL;
		for (var i = 2; i < 8; i++)
		{
			num3 = (num3 << 8) | data[i];
		}

		var array = new uint[num];
		for (var j = 0; j < num; j++)
		{
			array[j] = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(8 + 4 * j, 4));
		}

		consumed = num2;
		return new Sid(revision, num3, array);
	}

	public void Write(ref SpanWriter w)
	{
		w.WriteByte(Revision);
		w.WriteByte((byte)_subAuthorities.Length);
		for (var num = 5; num >= 0; num--)
		{
			w.WriteByte((byte)((IdentifierAuthority >> 8 * num) & 0xFF));
		}

		var subAuthorities = _subAuthorities;
		foreach (var value in subAuthorities)
		{
			w.WriteUInt32(value);
		}
	}

	public byte[] ToBytes()
	{
		var array = new byte[BinaryLength];
		var w = new SpanWriter(array);
		Write(ref w);
		return array;
	}

	public override string ToString()
	{
		var stringBuilder = new StringBuilder(16 + _subAuthorities.Length * 11);
		stringBuilder.Append("S-").Append(Revision).Append('-');
		if (IdentifierAuthority <= uint.MaxValue)
		{
			stringBuilder.Append(IdentifierAuthority.ToString(CultureInfo.InvariantCulture));
		}
		else
		{
			stringBuilder.Append("0x").Append(IdentifierAuthority.ToString("X12", CultureInfo.InvariantCulture));
		}

		var subAuthorities = _subAuthorities;
		foreach (var num in subAuthorities)
		{
			stringBuilder.Append('-').Append(num.ToString(CultureInfo.InvariantCulture));
		}

		return stringBuilder.ToString();
	}

	public static Sid FromString(string sid)
	{
		if (!TryParse(sid, out var result))
		{
			throw new FormatException("Invalid SID string '" + sid + "'.");
		}

		return result;
	}

	public static bool TryParse(string? sid, [NotNullWhen(true)] out Sid? result)
	{
		result = null;
		if (string.IsNullOrEmpty(sid))
		{
			return false;
		}

		var array = sid.Split('-');
		if (array.Length < 3 || !array[0].Equals("S", StringComparison.OrdinalIgnoreCase))
		{
			return false;
		}

		if (!byte.TryParse(array[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var result2))
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

		result = new Sid(result2, authority, array2);
		return true;
	}

	private static bool TryParseAuthority(string text, out ulong authority)
	{
		if (!text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
		{
			return ulong.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out authority);
		}

		return ulong.TryParse(text.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out authority);
	}

	public bool Equals(Sid? other)
	{
		if ((object)other != null && Revision == other.Revision && IdentifierAuthority == other.IdentifierAuthority)
		{
			return _subAuthorities.AsSpan().SequenceEqual(other._subAuthorities);
		}

		return false;
	}

	public override bool Equals(object? obj)
	{
		return Equals(obj as Sid);
	}

	public override int GetHashCode()
	{
		HashCode hashCode = default;
		hashCode.Add(Revision);
		hashCode.Add(IdentifierAuthority);
		var subAuthorities = _subAuthorities;
		foreach (var value in subAuthorities)
		{
			hashCode.Add(value);
		}

		return hashCode.ToHashCode();
	}

	public static bool operator ==(Sid? left, Sid? right)
	{
		return left?.Equals(right) ?? ((object)right == null);
	}

	public static bool operator !=(Sid? left, Sid? right)
	{
		return !(left == right);
	}
}
