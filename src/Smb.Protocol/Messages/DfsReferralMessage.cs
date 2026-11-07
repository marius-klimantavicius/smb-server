using System;
using System.Collections.Generic;
using System.Text;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public static class DfsReferralMessage
{
	public readonly record struct Request(ushort MaxReferralLevel, string RequestFileName);

	public sealed class ReferralEntry
	{
		public required string DfsPath { get; init; }

		public required string TargetPath { get; init; }

		public uint TimeToLive { get; init; } = 300u;

		public ushort ServerType { get; init; }
	}

	public const uint HeaderFlagReferralServers = 1u;

	public const uint HeaderFlagStorageServers = 2u;

	public const uint HeaderFlagTargetFailback = 4u;

	public const ushort ServerTypeLink = 0;

	public const ushort ServerTypeRoot = 1;

	private const ushort ReferralVersion = 4;

	private const int ResponseHeaderSize = 8;

	private const int EntrySize = 34;

	public static Request ParseRequest(ReadOnlySpan<byte> input)
	{
		if (input.Length < 2)
		{
			throw new SmbWireFormatException("REQ_GET_DFS_REFERRAL is shorter than 2 bytes.");
		}

		return new Request(new SpanReader(input).ReadUInt16(), ReadUnicodeZ(input.Slice(2)));
	}

	public static Request ParseRequestEx(ReadOnlySpan<byte> input)
	{
		if (input.Length < 10)
		{
			throw new SmbWireFormatException("REQ_GET_DFS_REFERRAL_EX is shorter than 10 bytes.");
		}

		var spanReader = new SpanReader(input);
		var maxReferralLevel = spanReader.ReadUInt16();
		spanReader.ReadUInt16();
		spanReader.ReadUInt32();
		var num = spanReader.ReadUInt16();
		if (10 + num > input.Length)
		{
			throw new SmbWireFormatException("REQ_GET_DFS_REFERRAL_EX RequestFileName extends past the buffer.");
		}

		var requestFileName = ((num == 0) ? string.Empty : Encoding.Unicode.GetString(input.Slice(10, num)).TrimEnd('\0'));
		return new Request(maxReferralLevel, requestFileName);
	}

	public static byte[] BuildResponse(ushort pathConsumedBytes, uint headerFlags, IReadOnlyList<ReferralEntry> entries)
	{
		var count = entries.Count;
		var num = ResponseHeaderSize + count * EntrySize;
		var pool = new List<byte>();
		var interned = new Dictionary<string, int>(StringComparer.Ordinal);
		var array = new int[count];
		var array2 = new int[count];
		for (var i = 0; i < count; i++)
		{
			array[i] = Intern(entries[i].DfsPath);
			array2[i] = Intern(entries[i].TargetPath);
		}

		var array3 = new byte[num + pool.Count];
		var spanWriter = new SpanWriter(array3);
		spanWriter.WriteUInt16(pathConsumedBytes);
		spanWriter.WriteUInt16((ushort)count);
		spanWriter.WriteUInt32(headerFlags);
		for (var j = 0; j < count; j++)
		{
			var num2 = ResponseHeaderSize + j * EntrySize;
			var num3 = num + array[j] - num2;
			var num4 = num + array2[j] - num2;
			var spanWriter2 = new SpanWriter(array3.AsSpan(num2, EntrySize));
			spanWriter2.WriteUInt16(ReferralVersion);
			spanWriter2.WriteUInt16((ushort)EntrySize);
			spanWriter2.WriteUInt16(entries[j].ServerType);
			spanWriter2.WriteUInt16(0);
			spanWriter2.WriteUInt32(entries[j].TimeToLive);
			spanWriter2.WriteUInt16((ushort)num3);
			spanWriter2.WriteUInt16((ushort)num3);
			spanWriter2.WriteUInt16((ushort)num4);
		}

		pool.CopyTo(array3, num);
		return array3;

		int Intern(string s)
		{
			if (interned.TryGetValue(s, out var value))
			{
				return value;
			}

			var count2 = pool.Count;
			interned[s] = count2;
			pool.AddRange(Encoding.Unicode.GetBytes(s));
			pool.Add(0);
			pool.Add(0);
			return count2;
		}
	}

	private static string ReadUnicodeZ(ReadOnlySpan<byte> s)
	{
		int i;
		for (i = 0; i + 1 < s.Length && (s[i] != 0 || s[i + 1] != 0); i += 2)
		{
		}

		if (i != 0)
		{
			return Encoding.Unicode.GetString(s.Slice(0, i));
		}

		return string.Empty;
	}
}
