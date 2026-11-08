using System;
using System.Text;

namespace Smb.Protocol.Wire;

public static class RequestBounds
{
	private static readonly Encoding StrictUnicode = new UnicodeEncoding(false, false, true);

	public static string ReadUnicode(ReadOnlySpan<byte> bytes, string field)
	{
		try { return StrictUnicode.GetString(bytes); }
		catch (DecoderFallbackException ex) { throw new SmbWireFormatException(field + " is not valid UTF-16.", ex); }
	}

	public static void Buffer(ReadOnlySpan<byte> command, uint offset, uint length, int minimum, string field)
	{
		if (length == 0) return;

		if (offset < minimum || offset > (uint)command.Length || length > (uint)command.Length - offset)
			throw new SmbWireFormatException(field + " is outside its command buffer.");
	}
}
