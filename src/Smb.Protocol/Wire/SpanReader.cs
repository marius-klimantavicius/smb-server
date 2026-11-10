using System;
using System.Buffers.Binary;
using System.Text;

namespace Smb.Protocol.Wire;

public ref struct SpanReader(ReadOnlySpan<byte> buffer)
{
    private readonly ReadOnlySpan<byte> _buffer = buffer;

    private int _position = 0;

    public readonly int Position => _position;

    public readonly int Remaining => _buffer.Length - _position;

    public readonly int Length => _buffer.Length;

    public void Seek(int position)
    {
        if ((uint)position > (uint)_buffer.Length)
        {
            throw new SmbWireFormatException($"Seek past end of buffer: position {position}, length {_buffer.Length}.");
        }

        _position = position;
    }

    public void Skip(int count)
    {
        EnsureAvailable(count);
        _position += count;
    }

    public byte ReadByte()
    {
        EnsureAvailable(1);
        return _buffer[_position++];
    }

    public ushort ReadUInt16()
    {
        EnsureAvailable(2);
        var result = BinaryPrimitives.ReadUInt16LittleEndian(_buffer.Slice(_position, 2));
        _position += 2;
        return result;
    }

    public short ReadInt16()
    {
        return (short)ReadUInt16();
    }

    public uint ReadUInt32()
    {
        EnsureAvailable(4);
        var result = BinaryPrimitives.ReadUInt32LittleEndian(_buffer.Slice(_position, 4));
        _position += 4;
        return result;
    }

    public int ReadInt32()
    {
        return (int)ReadUInt32();
    }

    public ulong ReadUInt64()
    {
        EnsureAvailable(8);
        var result = BinaryPrimitives.ReadUInt64LittleEndian(_buffer.Slice(_position, 8));
        _position += 8;
        return result;
    }

    public long ReadInt64()
    {
        return (long)ReadUInt64();
    }

    public ReadOnlySpan<byte> ReadBytes(int count)
    {
        EnsureAvailable(count);
        var result = _buffer.Slice(_position, count);
        _position += count;
        return result;
    }

    public byte[] ReadByteArray(int count)
    {
        return ReadBytes(count).ToArray();
    }

    public string ReadUtf16(int byteLength)
    {
        var bytes = ReadBytes(byteLength);
        return Encoding.Unicode.GetString(bytes);
    }

    public readonly ReadOnlySpan<byte> Slice(int offset, int count)
    {
        if ((uint)offset > (uint)_buffer.Length || (uint)count > (uint)(_buffer.Length - offset))
        {
            throw new SmbWireFormatException($"Slice out of range: offset {offset}, count {count}, length {_buffer.Length}.");
        }

        return _buffer.Slice(offset, count);
    }

    private readonly void EnsureAvailable(int count)
    {
        if (count < 0 || count > Remaining)
        {
            throw new SmbWireFormatException($"Read past end of buffer: needs {count}, available {Remaining} (position {_position}/{_buffer.Length}).");
        }
    }
}
