using System;

namespace Smb.Protocol.Transport;

public static class NbssFrame
{
    public const int HeaderLength = 4;

    public const byte SessionMessageType = 0;

    public const int MaxPayloadLength = 16777215;

    public static int ReadLength(ReadOnlySpan<byte> header)
    {
        if (header.Length < HeaderLength)
        {
            throw new ArgumentException($"NBSS prefix requires at least {HeaderLength} bytes.", nameof(header));
        }

        return (header[1] << 16) | (header[2] << 8) | header[3];
    }

    public static byte ReadMessageType(ReadOnlySpan<byte> header)
    {
        if (header.Length < HeaderLength)
        {
            throw new ArgumentException($"NBSS prefix requires at least {HeaderLength} bytes.", nameof(header));
        }

        return header[0];
    }

    public static void WriteHeader(Span<byte> destination, int payloadLength)
    {
        if (destination.Length < HeaderLength)
        {
            throw new ArgumentException($"Destination requires at least {HeaderLength} bytes.", nameof(destination));
        }

        if ((uint)payloadLength > (uint)MaxPayloadLength)
        {
            throw new ArgumentOutOfRangeException(nameof(payloadLength), $"NBSS payload must be at most {MaxPayloadLength} bytes.");
        }

        destination[0] = SessionMessageType;
        destination[1] = (byte)((payloadLength >> 16) & 0xFF);
        destination[2] = (byte)((payloadLength >> 8) & 0xFF);
        destination[3] = (byte)(payloadLength & 0xFF);
    }

    public static byte[] Wrap(ReadOnlySpan<byte> payload)
    {
        var array = new byte[HeaderLength + payload.Length];
        WriteHeader(array, payload.Length);
        payload.CopyTo(array.AsSpan(HeaderLength));
        return array;
    }
}
