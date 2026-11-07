using System;
using System.Buffers.Binary;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Security;

public sealed class SecurityDescriptor
{
	private const int HeaderSize = 20;

	public byte Revision { get; init; } = 1;

	public SecurityDescriptorControl Control { get; init; }

	public Sid? Owner { get; init; }

	public Sid? Group { get; init; }

	public Acl? Dacl { get; init; }

	public Acl? Sacl { get; init; }

	public static SecurityDescriptor Create(Sid? owner, Sid? group, Acl? dacl, Acl? sacl = null, SecurityDescriptorControl extraControl = SecurityDescriptorControl.None)
	{
		var securityDescriptorControl = extraControl | SecurityDescriptorControl.SelfRelative;
		if (dacl != null)
		{
			securityDescriptorControl |= SecurityDescriptorControl.DaclPresent;
		}

		if (sacl != null)
		{
			securityDescriptorControl |= SecurityDescriptorControl.SaclPresent;
		}

		return new SecurityDescriptor
		{
			Owner = owner,
			Group = group,
			Dacl = dacl,
			Sacl = sacl,
			Control = securityDescriptorControl,
		};
	}

	public static SecurityDescriptor Parse(ReadOnlySpan<byte> data)
	{
		if (data.Length < HeaderSize)
		{
			throw new SmbWireFormatException($"Security descriptor header needs {HeaderSize} bytes, has {data.Length}.");
		}

		var revision = data[0];
		var securityDescriptorControl = (SecurityDescriptorControl)BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(2, 2));
		var num = (int)BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(4, 4));
		var num2 = (int)BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(8, 4));
		var num3 = (int)BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(12, 4));
		var num4 = (int)BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(16, 4));
		var owner = ((num != 0) ? Sid.Parse(SliceFrom(data, num)) : null);
		var sid = ((num2 != 0) ? Sid.Parse(SliceFrom(data, num2)) : null);
		var sacl = (securityDescriptorControl.HasFlag(SecurityDescriptorControl.SaclPresent) && num3 != 0) ? Acl.Parse(SliceFrom(data, num3), out _) : null;
		var dacl = (securityDescriptorControl.HasFlag(SecurityDescriptorControl.DaclPresent) && num4 != 0) ? Acl.Parse(SliceFrom(data, num4), out _) : null;
		return new SecurityDescriptor
		{
			Revision = revision,
			Control = securityDescriptorControl,
			Owner = owner,
			Group = sid,
			Sacl = sacl,
			Dacl = dacl,
		};
	}

	public byte[] ToBytes()
	{
		var num = HeaderSize;
		var num2 = 0;
		var num3 = 0;
		var num4 = 0;
		var num5 = 0;
		if ((object)Owner != null)
		{
			num2 = num;
			num += Owner.BinaryLength;
		}

		if ((object)Group != null)
		{
			num3 = num;
			num += Group.BinaryLength;
		}

		if (Control.HasFlag(SecurityDescriptorControl.SaclPresent) && Sacl != null)
		{
			num4 = num;
			num += Sacl.BinaryLength;
		}

		if (Control.HasFlag(SecurityDescriptorControl.DaclPresent) && Dacl != null)
		{
			num5 = num;
			num += Dacl.BinaryLength;
		}

		var array = new byte[num];
		var w = new SpanWriter(array);
		w.WriteByte(Revision);
		w.WriteByte(0);
		w.WriteUInt16((ushort)(Control | SecurityDescriptorControl.SelfRelative));
		w.WriteUInt32((uint)num2);
		w.WriteUInt32((uint)num3);
		w.WriteUInt32((uint)num4);
		w.WriteUInt32((uint)num5);
		if (num2 != 0)
		{
			w.Seek(num2);
			Owner!.Write(ref w);
		}

		if (num3 != 0)
		{
			w.Seek(num3);
			Group!.Write(ref w);
		}

		if (num4 != 0)
		{
			w.Seek(num4);
			Sacl!.Write(ref w);
		}

		if (num5 != 0)
		{
			w.Seek(num5);
			Dacl!.Write(ref w);
		}

		return array;
	}

	private static ReadOnlySpan<byte> SliceFrom(ReadOnlySpan<byte> data, int offset)
	{
		if ((uint)offset >= (uint)data.Length)
		{
			throw new SmbWireFormatException($"Security descriptor offset {offset} out of range ({data.Length}).");
		}

		return data.Slice(offset);
	}
}
