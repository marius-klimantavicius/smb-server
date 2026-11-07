using System;
using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public static class LeaseBreakMessage
{
	public readonly record struct Acknowledgment(uint Flags, LeaseKey Key, LeaseState State);

	public const ushort NotificationStructureSize = 44;

	public const ushort AcknowledgmentStructureSize = 36;

	public const ushort ResponseStructureSize = 36;

	public const uint FlagAckRequired = 1u;

	public static byte[] BuildNotificationBody(LeaseKey key, LeaseState currentState, LeaseState newState, ushort newEpoch, bool ackRequired)
	{
		var array = new byte[NotificationStructureSize];
		var spanWriter = new SpanWriter(array);
		spanWriter.WriteUInt16(NotificationStructureSize);
		spanWriter.WriteUInt16(newEpoch);
		spanWriter.WriteUInt32(ackRequired ? FlagAckRequired : 0u);
		spanWriter.WriteBytes(key.ToBytes());
		spanWriter.WriteUInt32((uint)currentState);
		spanWriter.WriteUInt32((uint)newState);
		spanWriter.WriteUInt32(0u);
		spanWriter.WriteUInt32(0u);
		spanWriter.WriteUInt32(0u);
		return array;
	}

	public static Acknowledgment ParseAcknowledgment(ReadOnlySpan<byte> message, int bodyOffset)
	{
		var spanReader = new SpanReader(message.Slice(bodyOffset));
		var num = spanReader.ReadUInt16();
		if (num != AcknowledgmentStructureSize)
		{
			throw new SmbWireFormatException($"LEASE_BREAK Ack StructureSize {num} ≠ {AcknowledgmentStructureSize}.");
		}

		spanReader.Skip(2);
		var flags = spanReader.ReadUInt32();
		var key = LeaseKey.From(spanReader.ReadBytes(16));
		var state = (LeaseState)spanReader.ReadUInt32();
		spanReader.ReadUInt64();
		return new Acknowledgment(flags, key, state);
	}

	public static byte[] BuildResponseBody(LeaseKey key, LeaseState state)
	{
		var array = new byte[ResponseStructureSize];
		var spanWriter = new SpanWriter(array);
		spanWriter.WriteUInt16(ResponseStructureSize);
		spanWriter.WriteUInt16(0);
		spanWriter.WriteUInt32(0u);
		spanWriter.WriteBytes(key.ToBytes());
		spanWriter.WriteUInt32((uint)state);
		spanWriter.WriteUInt64(0uL);
		return array;
	}
}
