using System;
using System.Buffers.Binary;
using System.Text;
using Smb.Protocol.Wire;

namespace Smb.Server.Rpc;

public sealed class NdrReader
{
	private readonly ReadOnlyMemory<byte> _buf;

	private int _pos;

	public int Remaining => _buf.Length - _pos;

	private ReadOnlySpan<byte> Span => _buf.Span;

	public NdrReader(ReadOnlyMemory<byte> buffer)
	{
		_buf = buffer;
	}

	private void Require(int count)
	{
		if (_pos + count > _buf.Length)
		{
			throw new SmbWireFormatException("NDR stub truncated.");
		}
	}

	public void Align(int alignment)
	{
		while (_pos % alignment != 0)
		{
			Require(1);
			_pos++;
		}
	}

	public ushort UInt16()
	{
		Align(2);
		Require(2);
		var result = BinaryPrimitives.ReadUInt16LittleEndian(Span.Slice(_pos, 2));
		_pos += 2;
		return result;
	}

	public uint UInt32()
	{
		Align(4);
		Require(4);
		var result = BinaryPrimitives.ReadUInt32LittleEndian(Span.Slice(_pos, 4));
		_pos += 4;
		return result;
	}

	public uint ReferentId()
	{
		return UInt32();
	}

	public ReadOnlySpan<byte> Bytes(int count)
	{
		Require(count);
		var result = Span.Slice(_pos, count);
		_pos += count;
		return result;
	}

	public string FixedWideString(int lengthChars)
	{
		var bytes = Bytes(lengthChars * 2);
		var text = Encoding.Unicode.GetString(bytes);
		var num = text.IndexOf('\0');
		if (num < 0)
		{
			return text;
		}

		return text.Substring(0, num);
	}

	public string WideStringNullTerminated(int maxChars = 32768)
	{
		var num = UInt32();
		var num2 = UInt32();
		var num3 = UInt32();
		if (num2 != 0 || num3 > num || num3 > (uint)maxChars)
		{
			throw new SmbWireFormatException("NDR wide string bounds invalid.");
		}

		var num4 = checked((int)num3 * 2);
		Require(num4);
		var text = Encoding.Unicode.GetString(Span.Slice(_pos, num4));
		_pos += num4;
		Align(4);
		if (num3 != 0)
		{
			if (text[text.Length - 1] == '\0')
			{
				var text2 = text;
				return text2.Substring(0, text2.Length - 1);
			}
		}

		return text;
	}
}
