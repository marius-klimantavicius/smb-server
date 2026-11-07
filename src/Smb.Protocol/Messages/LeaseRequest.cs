using System;
using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public sealed class LeaseRequest
{
	public const int V1Size = 32;

	public const int V2Size = 52;

	public required LeaseKey Key { get; init; }

	public required LeaseState RequestedState { get; init; }

	public LeaseFlags Flags { get; init; }

	public LeaseKey ParentKey { get; init; }

	public ushort Epoch { get; init; }

	public bool IsV2 { get; init; }

	public static LeaseRequest ParseData(ReadOnlySpan<byte> data)
	{
		var length = data.Length;
		if (length != V1Size && length != V2Size)
		{
			throw new SmbWireFormatException($"Lease context data length {data.Length} ∉ {{{V1Size}, {V2Size}}}.");
		}

		var flag = data.Length == V2Size;
		var spanReader = new SpanReader(data);
		var key = LeaseKey.From(spanReader.ReadBytes(16));
		var requestedState = (LeaseState)spanReader.ReadUInt32();
		var flags = (LeaseFlags)spanReader.ReadUInt32();
		spanReader.ReadUInt64();
		LeaseKey parentKey = default;
		ushort epoch = 0;
		if (flag)
		{
			parentKey = LeaseKey.From(spanReader.ReadBytes(16));
			epoch = spanReader.ReadUInt16();
			spanReader.ReadUInt16();
		}

		return new LeaseRequest
		{
			Key = key,
			RequestedState = requestedState,
			Flags = flags,
			ParentKey = parentKey,
			Epoch = epoch,
			IsV2 = flag,
		};
	}

	public byte[] SerializeResponse(LeaseState grantedState, ushort grantedEpoch, LeaseFlags flags = LeaseFlags.None)
	{
		var array = new byte[IsV2 ? V2Size : V1Size];
		var spanWriter = new SpanWriter(array);
		spanWriter.WriteBytes(Key.ToBytes());
		spanWriter.WriteUInt32((uint)grantedState);
		spanWriter.WriteUInt32((uint)flags);
		spanWriter.WriteUInt64(0uL);
		if (IsV2)
		{
			spanWriter.WriteBytes(ParentKey.ToBytes());
			spanWriter.WriteUInt16(grantedEpoch);
			spanWriter.WriteUInt16(0);
		}

		return array;
	}

	public static LeaseRequest FromContext(CreateContext context)
	{
		return ParseData(context.Data);
	}
}
