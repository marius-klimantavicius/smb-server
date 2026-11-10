using System;
using System.Security.Cryptography;

namespace Smb.Crypto;

public sealed class PreauthIntegrityHash
{
    private byte[] _value = new byte[64];

    public byte[] Value => (byte[])_value.Clone();

    public ReadOnlySpan<byte> ValueSpan => _value;

    public void Append(ReadOnlySpan<byte> message)
    {
        var array = new byte[_value.Length + message.Length];
        _value.CopyTo(array, 0);
        message.CopyTo(array.AsSpan(_value.Length));
        _value = SHA512.HashData(array);
    }

    public PreauthIntegrityHash Clone()
    {
        return new PreauthIntegrityHash
        {
            _value = (byte[])_value.Clone(),
        };
    }
}
