using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using Smb.Protocol.Constants;
using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Compression;

public static class SmbCompressor
{
	public static readonly IReadOnlyList<SmbCompressionAlgorithm> DecodableAlgorithms =
	[
		SmbCompressionAlgorithm.Lz77,
		SmbCompressionAlgorithm.Lznt1,
		SmbCompressionAlgorithm.Lz77Huffman,
	];

	public static readonly IReadOnlyList<SmbCompressionAlgorithm> EncodableAlgorithms =
	[
		SmbCompressionAlgorithm.Lz77,
		SmbCompressionAlgorithm.Lznt1,
	];

	public static bool IsDecodable(SmbCompressionAlgorithm algorithm)
	{
		return Contains(DecodableAlgorithms, algorithm);
	}

	public static bool IsEncodable(SmbCompressionAlgorithm algorithm)
	{
		return Contains(EncodableAlgorithms, algorithm);
	}

	private static bool Contains(IReadOnlyList<SmbCompressionAlgorithm> set, SmbCompressionAlgorithm algorithm)
	{
		for (var i = 0; i < set.Count; i++)
		{
			if (set[i] == algorithm)
			{
				return true;
			}
		}

		return false;
	}

	public static byte[]? TryCompressUnchained(SmbCompressionAlgorithm algorithm, ReadOnlySpan<byte> message, int minSize)
	{
		if (message.Length < minSize || message.Length == 0 || !IsEncodable(algorithm))
		{
			return null;
		}

		var array = CompressPayload(algorithm, message);
		var num = 16 + array.Length;
		if (num >= message.Length)
		{
			return null;
		}

		var array2 = new byte[num];
		new CompressionTransformHeader
		{
			OriginalCompressedSegmentSize = (uint)message.Length,
			CompressionAlgorithm = algorithm,
			Flags = SmbCompressionFlags.None,
			Offset = 0u,
		}.WriteUnchained(array2);
		array.CopyTo(array2.AsSpan(16));
		return array2;
	}

	public static byte[] Decompress(ReadOnlySpan<byte> frame)
	{
		if (frame.Length < 8 || !SmbProtocolIds.IsCompression(frame))
		{
			throw new SmbWireFormatException("Not a compression transform frame.");
		}

		var smbCompressionFlags = (SmbCompressionFlags)BinaryPrimitives.ReadUInt16LittleEndian(frame.Slice(10, 2));
		if (!smbCompressionFlags.HasFlag(SmbCompressionFlags.Chained))
		{
			return DecompressUnchained(frame);
		}

		return DecompressChained(frame);
	}

	private static byte[] DecompressUnchained(ReadOnlySpan<byte> frame)
	{
		var compressionTransformHeader = CompressionTransformHeader.ReadUnchained(frame);
		ReadOnlySpan<byte> readOnlySpan2;
		byte[] array;
		checked
		{
			var num = (int)compressionTransformHeader.Offset;
			var originalSize = (int)compressionTransformHeader.OriginalCompressedSegmentSize;
			var readOnlySpan = frame.Slice(16);
			if (num > readOnlySpan.Length)
			{
				throw new SmbWireFormatException("Compression Offset beyond frame body.");
			}

			readOnlySpan2 = readOnlySpan.Slice(0, num);
			array = DecompressPayload(data: readOnlySpan.Slice(num), algorithm: compressionTransformHeader.CompressionAlgorithm, originalSize: originalSize);
		}

		var array2 = new byte[readOnlySpan2.Length + array.Length];
		readOnlySpan2.CopyTo(array2);
		array.CopyTo(array2.AsSpan(readOnlySpan2.Length));
		return array2;
	}

	private static byte[] DecompressChained(ReadOnlySpan<byte> frame)
	{
		var num = BinaryPrimitives.ReadUInt32LittleEndian(frame.Slice(4, 4));
		var growableWriter = new GrowableWriter(checked((int)num));
		var num2 = 8;
		while (num2 < frame.Length)
		{
			if (num2 + 8 > frame.Length)
			{
				throw new SmbWireFormatException("Truncated chained compression payload header.");
			}

			var compressionPayloadHeader = CompressionPayloadHeader.Read(frame.Slice(num2, 8));
			num2 += 8;
			var num3 = checked((int)compressionPayloadHeader.Length);
			if (num2 + num3 > frame.Length)
			{
				throw new SmbWireFormatException("Truncated chained compression payload data.");
			}

			var readOnlySpan = frame.Slice(num2, num3);
			num2 += num3;
			switch (compressionPayloadHeader.CompressionAlgorithm)
			{
				case SmbCompressionAlgorithm.None:
					growableWriter.WriteBytes(readOnlySpan);
					continue;
				case SmbCompressionAlgorithm.PatternV1:
					WritePattern(growableWriter, readOnlySpan);
					continue;
			}

			if (readOnlySpan.Length < 4)
			{
				throw new SmbWireFormatException("Chained compressed link missing original size.");
			}

			var originalSize = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(readOnlySpan.Slice(0, 4)));
			growableWriter.WriteBytes(DecompressPayload(compressionPayloadHeader.CompressionAlgorithm, readOnlySpan.Slice(4), originalSize));
		}

		if (growableWriter.Position != num)
		{
			throw new SmbWireFormatException("Chained compression output size mismatch.");
		}

		return growableWriter.ToArray();
	}

	private static void WritePattern(GrowableWriter output, ReadOnlySpan<byte> data)
	{
		if (data.Length < 8)
		{
			throw new SmbWireFormatException("Pattern_V1 payload requires 8 bytes.");
		}

		var value = data[0];
		var num = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(4, 4)));
		for (var i = 0; i < num; i++)
		{
			output.WriteByte(value);
		}
	}

	private static byte[] CompressPayload(SmbCompressionAlgorithm algorithm, ReadOnlySpan<byte> data)
	{
		return algorithm switch
		{
			SmbCompressionAlgorithm.Lz77 => PlainLz77.Compress(data),
			SmbCompressionAlgorithm.Lznt1 => Lznt1.Compress(data),
			_ => throw new SmbWireFormatException($"No compressor for {algorithm}."),
		};
	}

	private static byte[] DecompressPayload(SmbCompressionAlgorithm algorithm, ReadOnlySpan<byte> data, int originalSize)
	{
		return algorithm switch
		{
			SmbCompressionAlgorithm.Lz77 => PlainLz77.Decompress(data, originalSize),
			SmbCompressionAlgorithm.Lznt1 => Lznt1.Decompress(data, originalSize),
			SmbCompressionAlgorithm.Lz77Huffman => Lz77Huffman.Decompress(data, originalSize),
			SmbCompressionAlgorithm.None => data.ToArray(),
			_ => throw new SmbWireFormatException($"No decompressor for {algorithm}."),
		};
	}
}
