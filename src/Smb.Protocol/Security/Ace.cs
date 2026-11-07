using System;
using System.Buffers.Binary;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Security;

public sealed class Ace
{
	private const int HeaderSize = 4;

	public required AceType Type { get; init; }

	public AceFlags Flags { get; init; }

	public uint AccessMask { get; init; }

	public Sid? Sid { get; init; }

	public byte[]? RawData { get; init; }

	public bool IsBasic
	{
		get
		{
			var type = Type;
			if (type <= AceType.SystemAlarm)
			{
				return true;
			}

			return false;
		}
	}

	public int BinaryLength => HeaderSize + (IsBasic ? (4 + Sid!.BinaryLength) : (RawData?.Length ?? 0));

	public static Ace Allow(Sid sid, uint accessMask, AceFlags flags = AceFlags.None)
	{
		return new Ace
		{
			Type = AceType.AccessAllowed,
			Flags = flags,
			AccessMask = accessMask,
			Sid = sid,
		};
	}

	public static Ace Deny(Sid sid, uint accessMask, AceFlags flags = AceFlags.None)
	{
		return new Ace
		{
			Type = AceType.AccessDenied,
			Flags = flags,
			AccessMask = accessMask,
			Sid = sid,
		};
	}

	public static Ace Audit(Sid sid, uint accessMask, AceFlags flags)
	{
		return new Ace
		{
			Type = AceType.SystemAudit,
			Flags = flags,
			AccessMask = accessMask,
			Sid = sid,
		};
	}

	public static Ace Parse(ReadOnlySpan<byte> data, out int consumed)
	{
		if (data.Length < HeaderSize)
		{
			throw new SmbWireFormatException($"ACE header needs {HeaderSize} bytes, has {data.Length}.");
		}

		var aceType = (AceType)data[0];
		var flags = (AceFlags)data[1];
		int num = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(2, 2));
		if (num < HeaderSize || num > data.Length)
		{
			throw new SmbWireFormatException($"ACE size {num} invalid (buffer {data.Length}).");
		}

		var readOnlySpan = data.Slice(HeaderSize, num - HeaderSize);
		consumed = num;
		if (aceType <= AceType.SystemAlarm)
		{
			if (readOnlySpan.Length < 4)
			{
				throw new SmbWireFormatException("ACE body too short for AccessMask.");
			}

			var accessMask = BinaryPrimitives.ReadUInt32LittleEndian(readOnlySpan.Slice(0, 4));
			var sid = Sid.Parse(readOnlySpan.Slice(4));
			return new Ace
			{
				Type = aceType,
				Flags = flags,
				AccessMask = accessMask,
				Sid = sid,
			};
		}

		return new Ace
		{
			Type = aceType,
			Flags = flags,
			RawData = readOnlySpan.ToArray(),
		};
	}

	public void Write(ref SpanWriter w)
	{
		var binaryLength = BinaryLength;
		w.WriteByte((byte)Type);
		w.WriteByte((byte)Flags);
		w.WriteUInt16((ushort)binaryLength);
		if (IsBasic)
		{
			w.WriteUInt32(AccessMask);
			Sid!.Write(ref w);
			return;
		}

		var rawData = RawData;
		if (rawData != null && rawData.Length > 0)
		{
			w.WriteBytes(RawData);
		}
	}

	public byte[] ToBytes()
	{
		var array = new byte[BinaryLength];
		var w = new SpanWriter(array);
		Write(ref w);
		return array;
	}
}
