using System;
using System.Buffers.Binary;
using System.Text;

namespace Smb.Protocol.Wire;

public sealed class GrowableWriter
{
    private byte[] _buffer;

    private int _position;

    public int Position => _position;

    public Span<byte> WrittenSpan => _buffer.AsSpan(0, _position);

    public GrowableWriter(int initialCapacity = 256)
    {
        _buffer = new byte[Math.Max(16, initialCapacity)];
        _position = 0;
    }

    public void WriteByte(byte value)
    {
        EnsureCapacity(1);
        _buffer[_position++] = value;
    }

    public void WriteUInt16(ushort value)
    {
        EnsureCapacity(2);
        BinaryPrimitives.WriteUInt16LittleEndian(_buffer.AsSpan(_position, 2), value);
        _position += 2;
    }

    public void WriteUInt32(uint value)
    {
        EnsureCapacity(4);
        BinaryPrimitives.WriteUInt32LittleEndian(_buffer.AsSpan(_position, 4), value);
        _position += 4;
    }

    public void WriteUInt64(ulong value)
    {
        EnsureCapacity(8);
        BinaryPrimitives.WriteUInt64LittleEndian(_buffer.AsSpan(_position, 8), value);
        _position += 8;
    }

    public void WriteBytes(ReadOnlySpan<byte> value)
    {
        EnsureCapacity(value.Length);
        value.CopyTo(_buffer.AsSpan(_position));
        _position += value.Length;
    }

    public int WriteUtf16(string value)
    {
        var byteCount = Encoding.Unicode.GetByteCount(value);
        EnsureCapacity(byteCount);
        Encoding.Unicode.GetBytes(value, _buffer.AsSpan(_position));
        _position += byteCount;
        return byteCount;
    }

    public void WriteZeros(int count)
    {
        EnsureCapacity(count);
        _buffer.AsSpan(_position, count).Clear();
        _position += count;
    }

    public void AlignTo(int alignment, int origin = 0)
    {
        var num = (_position - origin) % alignment;
        if (num != 0)
        {
            WriteZeros(alignment - num);
        }
    }

    public void PatchByte(int offset, byte value)
    {
        _buffer[offset] = value;
    }

    public void PatchUInt16(int offset, ushort value)
    {
        BinaryPrimitives.WriteUInt16LittleEndian(_buffer.AsSpan(offset, 2), value);
    }

    public void PatchUInt32(int offset, uint value)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(_buffer.AsSpan(offset, 4), value);
    }

    public byte[] ToArray()
    {
        return _buffer.AsSpan(0, _position).ToArray();
    }

    private void EnsureCapacity(int additional)
    {
        if (_position + additional > _buffer.Length)
        {
            var newSize = Math.Max(_buffer.Length * 2, _position + additional);
            Array.Resize(ref _buffer, newSize);
        }
    }
}
