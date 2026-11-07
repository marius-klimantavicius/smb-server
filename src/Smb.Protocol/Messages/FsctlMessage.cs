using System;
using System.Collections.Generic;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public static class FsctlMessage
{
	public readonly record struct FileRange(long Offset, long Length);

	public const uint FsctlSetSparse = 590020u;

	public const uint FsctlSetZeroData = 622792u;

	public const uint FsctlQueryAllocatedRanges = 606415u;

	public const uint FsctlGetReparsePoint = 589992u;

	public const uint FsctlSetReparsePoint = 589988u;

	public const uint FsctlDeleteReparsePoint = 589996u;

	public const uint FsctlDfsGetReferrals = 393620u;

	public const uint FsctlDfsGetReferralsEx = 393648u;

	public static bool ParseSetSparse(ReadOnlySpan<byte> input)
	{
		if (input.Length != 0)
		{
			return input[0] != 0;
		}

		return true;
	}

	public static FileRange ParseZeroData(ReadOnlySpan<byte> input)
	{
		var spanReader = new SpanReader(input);
		var num = spanReader.ReadInt64();
		var num2 = spanReader.ReadInt64();
		if (num2 < num)
		{
			throw new SmbWireFormatException("FILE_ZERO_DATA_INFORMATION: BeyondFinalZero precedes FileOffset.");
		}

		return new FileRange(num, num2 - num);
	}

	public static FileRange ParseAllocatedRangeQuery(ReadOnlySpan<byte> input)
	{
		var spanReader = new SpanReader(input);
		var offset = spanReader.ReadInt64();
		var length = spanReader.ReadInt64();
		return new FileRange(offset, length);
	}

	public static byte[] BuildAllocatedRanges(IReadOnlyList<FileRange> ranges)
	{
		var array = new byte[ranges.Count * 16];
		var spanWriter = new SpanWriter(array);
		foreach (var range in ranges)
		{
			spanWriter.WriteUInt64((ulong)range.Offset);
			spanWriter.WriteUInt64((ulong)range.Length);
		}

		return array;
	}
}
