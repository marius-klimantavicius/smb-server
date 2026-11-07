using System;

namespace Smb.Protocol.Constants;

public static class SmbProtocolIds
{
	public static ReadOnlySpan<byte> Smb2 => [254, 83, 77, 66];

	public static ReadOnlySpan<byte> Smb2Transform => [253, 83, 77, 66];

	public static ReadOnlySpan<byte> Smb2Compression => [252, 83, 77, 66];

	public static ReadOnlySpan<byte> Smb1 => [255, 83, 77, 66];

	public static bool IsSmb2(ReadOnlySpan<byte> data)
	{
		return StartsWith(data, Smb2);
	}

	public static bool IsTransform(ReadOnlySpan<byte> data)
	{
		return StartsWith(data, Smb2Transform);
	}

	public static bool IsCompression(ReadOnlySpan<byte> data)
	{
		return StartsWith(data, Smb2Compression);
	}

	public static bool IsSmb1(ReadOnlySpan<byte> data)
	{
		return StartsWith(data, Smb1);
	}

	private static bool StartsWith(ReadOnlySpan<byte> data, ReadOnlySpan<byte> prefix)
	{
		if (data.Length >= prefix.Length)
		{
			return data.Slice(0, prefix.Length).SequenceEqual(prefix);
		}

		return false;
	}
}
