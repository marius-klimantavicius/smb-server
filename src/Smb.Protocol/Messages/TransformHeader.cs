using System;
using Smb.Protocol.Constants;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public sealed class TransformHeader
{
	public const int Size = 52;

	public const int AadOffset = 20;

	public const int AadLength = 32;

	public const ushort FlagEncrypted = 1;

	public byte[] Signature { get; set; } = new byte[16];

	public byte[] Nonce { get; set; } = new byte[16];

	public uint OriginalMessageSize { get; set; }

	public ushort Flags { get; set; } = FlagEncrypted;

	public ulong SessionId { get; set; }

	public void Write(Span<byte> destination)
	{
		if (destination.Length < Size)
		{
			throw new SmbWireFormatException($"TRANSFORM_HEADER requires {Size} bytes.");
		}

		var spanWriter = new SpanWriter(destination);
		spanWriter.WriteBytes(SmbProtocolIds.Smb2Transform);
		spanWriter.WriteBytes(Signature);
		spanWriter.WriteBytes(Nonce);
		spanWriter.WriteUInt32(OriginalMessageSize);
		spanWriter.WriteUInt16(0);
		spanWriter.WriteUInt16(Flags);
		spanWriter.WriteUInt64(SessionId);
	}

	public static TransformHeader Read(ReadOnlySpan<byte> buffer)
	{
		if (buffer.Length < Size)
		{
			throw new SmbWireFormatException($"TRANSFORM_HEADER requires {Size} bytes.");
		}

		if (!SmbProtocolIds.IsTransform(buffer))
		{
			throw new SmbWireFormatException("Invalid transform ProtocolId (expected FD 53 4D 42).");
		}

		var spanReader = new SpanReader(buffer);
		spanReader.Skip(4);
		var transformHeader = new TransformHeader
		{
			Signature = spanReader.ReadByteArray(16),
			Nonce = spanReader.ReadByteArray(16),
			OriginalMessageSize = spanReader.ReadUInt32(),
		};
		spanReader.Skip(2);
		transformHeader.Flags = spanReader.ReadUInt16();
		transformHeader.SessionId = spanReader.ReadUInt64();
		return transformHeader;
	}
}
