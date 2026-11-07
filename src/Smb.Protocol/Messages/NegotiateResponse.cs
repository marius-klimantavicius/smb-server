using System;
using System.Collections.Generic;
using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public sealed class NegotiateResponse
{
	public const ushort StructureSize = 65;

	public SmbSecurityMode SecurityMode { get; init; }

	public SmbDialect DialectRevision { get; init; }

	public byte[] ServerGuid { get; init; } = new byte[16];

	public Smb2Capabilities Capabilities { get; init; }

	public uint MaxTransactSize { get; init; }

	public uint MaxReadSize { get; init; }

	public uint MaxWriteSize { get; init; }

	public long SystemTime { get; init; }

	public long ServerStartTime { get; init; }

	public byte[] SecurityBuffer { get; init; } = Array.Empty<byte>();

	public IReadOnlyList<NegotiateContext> NegotiateContexts { get; init; } = Array.Empty<NegotiateContext>();

	public byte[] ToBody(int headerSize = 64)
	{
		var growableWriter = new GrowableWriter(128 + SecurityBuffer.Length);
		growableWriter.WriteUInt16(StructureSize);
		growableWriter.WriteUInt16((ushort)SecurityMode);
		growableWriter.WriteUInt16((ushort)DialectRevision);
		growableWriter.WriteUInt16((ushort)NegotiateContexts.Count);
		if (ServerGuid.Length != 16)
		{
			throw new SmbWireFormatException("ServerGuid must be 16 bytes.");
		}

		growableWriter.WriteBytes(ServerGuid);
		growableWriter.WriteUInt32((uint)Capabilities);
		growableWriter.WriteUInt32(MaxTransactSize);
		growableWriter.WriteUInt32(MaxReadSize);
		growableWriter.WriteUInt32(MaxWriteSize);
		growableWriter.WriteUInt64((ulong)SystemTime);
		growableWriter.WriteUInt64((ulong)ServerStartTime);
		var position = growableWriter.Position;
		growableWriter.WriteUInt16(0);
		growableWriter.WriteUInt16((ushort)SecurityBuffer.Length);
		var position2 = growableWriter.Position;
		growableWriter.WriteUInt32(0u);
		var position3 = growableWriter.Position;
		if (SecurityBuffer.Length != 0)
		{
			growableWriter.WriteBytes(SecurityBuffer);
			growableWriter.PatchUInt16(position, (ushort)(headerSize + position3));
		}
		else
		{
			growableWriter.PatchUInt16(position, 0);
		}

		if (NegotiateContexts.Count > 0)
		{
			PadToAbsolute8(growableWriter, headerSize);
			growableWriter.PatchUInt32(position2, (uint)(headerSize + growableWriter.Position));
			for (var i = 0; i < NegotiateContexts.Count; i++)
			{
				if (i > 0)
				{
					PadToAbsolute8(growableWriter, headerSize);
				}

				NegotiateContexts[i].Write(growableWriter);
			}
		}
		else
		{
			growableWriter.PatchUInt32(position2, 0u);
		}

		return growableWriter.ToArray();
	}

	private static void PadToAbsolute8(GrowableWriter w, int headerSize)
	{
		var num = headerSize + w.Position;
		var num2 = (8 - num % 8) % 8;
		if (num2 > 0)
		{
			w.WriteZeros(num2);
		}
	}
}
