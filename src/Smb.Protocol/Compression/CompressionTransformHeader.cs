using System;
using Smb.Protocol.Constants;
using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Compression;

public sealed class CompressionTransformHeader
{
	public const int UnchainedSize = 16;

	public const int PrefixSize = 8;

	public uint OriginalCompressedSegmentSize { get; init; }

	public SmbCompressionAlgorithm CompressionAlgorithm { get; init; }

	public SmbCompressionFlags Flags { get; init; }

	public uint Offset { get; init; }

	public void WriteUnchained(Span<byte> destination)
	{
		if (destination.Length < UnchainedSize)
		{
			throw new SmbWireFormatException($"Unchained compression header requires {UnchainedSize} bytes.");
		}

		var spanWriter = new SpanWriter(destination);
		spanWriter.WriteBytes(SmbProtocolIds.Smb2Compression);
		spanWriter.WriteUInt32(OriginalCompressedSegmentSize);
		spanWriter.WriteUInt16((ushort)CompressionAlgorithm);
		spanWriter.WriteUInt16((ushort)Flags);
		spanWriter.WriteUInt32(Offset);
	}

	public static CompressionTransformHeader ReadUnchained(ReadOnlySpan<byte> buffer)
	{
		if (buffer.Length < UnchainedSize)
		{
			throw new SmbWireFormatException($"Unchained compression header requires {UnchainedSize} bytes.");
		}

		if (!SmbProtocolIds.IsCompression(buffer))
		{
			throw new SmbWireFormatException("Invalid compression ProtocolId (expected FC 53 4D 42).");
		}

		var spanReader = new SpanReader(buffer);
		spanReader.Skip(4);
		var originalCompressedSegmentSize = spanReader.ReadUInt32();
		var compressionAlgorithm = (SmbCompressionAlgorithm)spanReader.ReadUInt16();
		var flags = (SmbCompressionFlags)spanReader.ReadUInt16();
		var offset = spanReader.ReadUInt32();
		return new CompressionTransformHeader
		{
			OriginalCompressedSegmentSize = originalCompressedSegmentSize,
			CompressionAlgorithm = compressionAlgorithm,
			Flags = flags,
			Offset = offset,
		};
	}
}
