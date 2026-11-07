using System;
using System.Collections.Generic;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public static class CopyChunkMessage
{
	public readonly record struct Chunk(ulong SourceOffset, ulong TargetOffset, uint Length);

	public readonly record struct CopyRequest(byte[] SourceKey, IReadOnlyList<Chunk> Chunks);

	public const uint FsctlSrvRequestResumeKey = 1310840u;

	public const uint FsctlSrvCopyChunk = 1327346u;

	public const uint FsctlSrvCopyChunkWrite = 1343730u;

	public const int ResumeKeyLength = 24;

	public const uint MaxChunks = 16u;

	public const uint MaxChunkSize = 1048576u;

	public const uint MaxTotalSize = 16777216u;

	private const int ChunkSize = 24;

	public static byte[] BuildResumeKeyResponse(ReadOnlySpan<byte> resumeKey)
	{
		if (resumeKey.Length != ResumeKeyLength)
		{
			throw new ArgumentException($"Resume key must be {ResumeKeyLength} bytes.", nameof(resumeKey));
		}

		var array = new byte[28];
		var spanWriter = new SpanWriter(array);
		spanWriter.WriteBytes(resumeKey);
		spanWriter.WriteUInt32(0u);
		return array;
	}

	public static CopyRequest ParseCopyRequest(ReadOnlySpan<byte> input)
	{
		var spanReader = new SpanReader(input);
		var sourceKey = spanReader.ReadByteArray(ResumeKeyLength);
		var num = spanReader.ReadUInt32();
		spanReader.ReadUInt32();
		if (num * (long)ChunkSize > spanReader.Remaining)
		{
			throw new SmbWireFormatException("SRV_COPYCHUNK_COPY chunk array extends past the input buffer.");
		}

		var array = new Chunk[num];
		for (var num2 = 0u; num2 < num; num2++)
		{
			var sourceOffset = spanReader.ReadUInt64();
			var targetOffset = spanReader.ReadUInt64();
			var length = spanReader.ReadUInt32();
			spanReader.ReadUInt32();
			array[num2] = new Chunk(sourceOffset, targetOffset, length);
		}

		return new CopyRequest(sourceKey, array);
	}

	public static byte[] BuildCopyResponse(uint chunksWritten, uint chunkBytesWritten, uint totalBytesWritten)
	{
		var array = new byte[12];
		var spanWriter = new SpanWriter(array);
		spanWriter.WriteUInt32(chunksWritten);
		spanWriter.WriteUInt32(chunkBytesWritten);
		spanWriter.WriteUInt32(totalBytesWritten);
		return array;
	}

	public static byte[] BuildLimitExceededResponse()
	{
		return BuildCopyResponse(MaxChunks, MaxChunkSize, MaxTotalSize);
	}
}
