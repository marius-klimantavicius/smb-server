using System;
using System.Text;
using Smb.Protocol.Wire;

namespace Smb.Server.Rpc;

public sealed class NdrWriter
{
    private readonly GrowableWriter _w = new GrowableWriter();

    private uint _nextReferent = 131072u;

    public int Position => _w.Position;

    public void Align(int alignment)
    {
        while (_w.Position % alignment != 0)
        {
            _w.WriteByte(0);
        }
    }

    public void UInt16(ushort value)
    {
        Align(2);
        _w.WriteUInt16(value);
    }

    public void UInt32(uint value)
    {
        Align(4);
        _w.WriteUInt32(value);
    }

    public void Bytes(ReadOnlySpan<byte> value)
    {
        var readOnlySpan = value;
        for (var i = 0; i < readOnlySpan.Length; i++)
        {
            var value2 = readOnlySpan[i];
            _w.WriteByte(value2);
        }
    }

    public void FixedWideString(string value, int lengthChars)
    {
        Span<byte> span = new byte[lengthChars * 2];
        var num = Math.Min(value.Length, lengthChars - 1);
        if (num > 0)
        {
            Encoding.Unicode.GetBytes(value.AsSpan(0, num), span);
        }

        Bytes(span);
    }

    public void ReferentId()
    {
        UInt32(_nextReferent);
        _nextReferent += 4u;
    }

    public void NullPointer()
    {
        UInt32(0u);
    }

    public void WideStringNullTerminated(string value)
    {
        var text = value + "\0";
        UInt32((uint)text.Length);
        UInt32(0u);
        UInt32((uint)text.Length);
        var bytes = Encoding.Unicode.GetBytes(text);
        foreach (var value2 in bytes)
        {
            _w.WriteByte(value2);
        }

        Align(4);
    }

    public byte[] ToArray()
    {
        return _w.ToArray();
    }
}
