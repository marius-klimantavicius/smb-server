using System;

namespace Smb.Protocol.Wire;

public static class RequestBounds
{
	public static void Buffer(ReadOnlySpan<byte> command, uint offset, uint length, int minimum, string field)
	{
		if (length == 0) return;

		if (offset < minimum || offset > (uint)command.Length || length > (uint)command.Length - offset)
			throw new SmbWireFormatException(field + " is outside its command buffer.");
	}
}
