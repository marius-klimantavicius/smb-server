using System;
using Smb.Protocol.Constants;
using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public sealed class Smb2Header
{
	public const int Size = 64;

	public const ushort HeaderStructureSize = 64;

	public const ulong RelatedFileIdSentinel = ulong.MaxValue;

	public ushort CreditCharge { get; set; }

	public uint StatusOrChannelSequence { get; set; }

	public SmbCommand Command { get; set; }

	public ushort CreditRequestResponse { get; set; }

	public Smb2HeaderFlags Flags { get; set; }

	public uint NextCommand { get; set; }

	public ulong MessageId { get; set; }

	public ulong AsyncId { get; set; }

	public uint TreeId { get; set; }

	public ulong SessionId { get; set; }

	public byte[] Signature { get; set; } = new byte[16];

	public bool IsAsync => Flags.HasFlag(Smb2HeaderFlags.AsyncCommand);

	public bool IsResponse => Flags.HasFlag(Smb2HeaderFlags.ServerToRedir);

	public NtStatus Status
	{
		get
		{
			return (NtStatus)StatusOrChannelSequence;
		}
		set
		{
			StatusOrChannelSequence = (uint)value;
		}
	}

	public ushort ChannelSequence => (ushort)(StatusOrChannelSequence & 0xFFFF);

	public static Smb2Header Read(ReadOnlySpan<byte> buffer)
	{
		if (buffer.Length < Size)
		{
			throw new SmbWireFormatException($"SMB2 header requires {Size} bytes, has {buffer.Length}.");
		}

		if (!SmbProtocolIds.IsSmb2(buffer))
		{
			throw new SmbWireFormatException("Invalid SMB2 ProtocolId (expected FE 53 4D 42).");
		}

		var spanReader = new SpanReader(buffer);
		spanReader.Skip(4);
		var num = spanReader.ReadUInt16();
		if (num != HeaderStructureSize)
		{
			throw new SmbWireFormatException($"SMB2 header StructureSize {num} ≠ {HeaderStructureSize}.");
		}

		var smb2Header = new Smb2Header
		{
			CreditCharge = spanReader.ReadUInt16(),
			StatusOrChannelSequence = spanReader.ReadUInt32(),
			Command = (SmbCommand)spanReader.ReadUInt16(),
			CreditRequestResponse = spanReader.ReadUInt16(),
			Flags = (Smb2HeaderFlags)spanReader.ReadUInt32(),
			NextCommand = spanReader.ReadUInt32(),
			MessageId = spanReader.ReadUInt64(),
		};
		if (smb2Header.IsAsync)
		{
			smb2Header.AsyncId = spanReader.ReadUInt64();
		}
		else
		{
			spanReader.Skip(4);
			smb2Header.TreeId = spanReader.ReadUInt32();
		}

		smb2Header.SessionId = spanReader.ReadUInt64();
		smb2Header.Signature = spanReader.ReadByteArray(16);
		return smb2Header;
	}

	public void Write(Span<byte> destination)
	{
		if (destination.Length < Size)
		{
			throw new SmbWireFormatException($"Destination requires {Size} bytes for the SMB2 header.");
		}

		var spanWriter = new SpanWriter(destination);
		spanWriter.WriteBytes(SmbProtocolIds.Smb2);
		spanWriter.WriteUInt16(HeaderStructureSize);
		spanWriter.WriteUInt16(CreditCharge);
		spanWriter.WriteUInt32(StatusOrChannelSequence);
		spanWriter.WriteUInt16((ushort)Command);
		spanWriter.WriteUInt16(CreditRequestResponse);
		spanWriter.WriteUInt32((uint)Flags);
		spanWriter.WriteUInt32(NextCommand);
		spanWriter.WriteUInt64(MessageId);
		if (IsAsync)
		{
			spanWriter.WriteUInt64(AsyncId);
		}
		else
		{
			spanWriter.WriteZeros(4);
			spanWriter.WriteUInt32(TreeId);
		}

		spanWriter.WriteUInt64(SessionId);
		if (Signature.Length != 16)
		{
			throw new SmbWireFormatException("Signature must be exactly 16 bytes.");
		}

		spanWriter.WriteBytes(Signature);
	}

	public byte[] ToArray()
	{
		var array = new byte[Size];
		Write(array);
		return array;
	}

	public Smb2Header CreateResponse(NtStatus status)
	{
		var smb2HeaderFlags = Smb2HeaderFlags.ServerToRedir;
		if (IsAsync)
		{
			smb2HeaderFlags |= Smb2HeaderFlags.AsyncCommand;
		}

		return new Smb2Header
		{
			Command = Command,
			MessageId = MessageId,
			SessionId = SessionId,
			TreeId = TreeId,
			AsyncId = AsyncId,
			CreditCharge = CreditCharge,
			Flags = smb2HeaderFlags,
			Status = status,
			Signature = new byte[16],
		};
	}
}
