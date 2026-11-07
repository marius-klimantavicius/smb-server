using System;
using System.Collections.Generic;
using System.Formats.Asn1;

namespace Smb.Auth.Kerberos;

public static class KerberosGssToken
{
	private const byte Application0 = 96;

	public static ReadOnlySpan<byte> TokIdApReq => [1, 0];

	public static ReadOnlySpan<byte> TokIdApRep => [2, 0];

	public static bool TryReadApReq(ReadOnlySpan<byte> gssToken, out byte[] apReq)
	{
		apReq = Array.Empty<byte>();
		if (gssToken.Length < 2 || gssToken[0] != Application0)
		{
			return false;
		}

		var pos = 1;
		if (!TryReadLength(gssToken, ref pos, out var length))
		{
			return false;
		}

		if (pos + length > gssToken.Length)
		{
			return false;
		}

		var data = gssToken.Slice(pos, length);
		if (data.Length < 2 || data[0] != 6)
		{
			return false;
		}

		var pos2 = 1;
		if (!TryReadLength(data, ref pos2, out var length2))
		{
			return false;
		}

		if (pos2 + length2 > data.Length)
		{
			return false;
		}

		if (!IsKerberosOid(data.Slice(0, pos2 + length2)))
		{
			return false;
		}

		pos2 += length2;
		if (pos2 + 2 > data.Length)
		{
			return false;
		}

		if (!data.Slice(pos2, 2).SequenceEqual(TokIdApReq))
		{
			return false;
		}

		pos2 += 2;
		apReq = data.Slice(pos2).ToArray();
		return true;
	}

	public static byte[] WrapApRep(ReadOnlySpan<byte> apRep)
	{
		return Wrap(TokIdApRep, apRep);
	}

	public static byte[] WrapApReq(ReadOnlySpan<byte> apReq)
	{
		return Wrap(TokIdApReq, apReq);
	}

	private static byte[] Wrap(ReadOnlySpan<byte> tokId, ReadOnlySpan<byte> inner)
	{
		var array = EncodeOidTlv("1.2.840.113554.1.2.2");
		var num = array.Length + tokId.Length + inner.Length;
		var array2 = EncodeLength(num);
		var array3 = new byte[1 + array2.Length + num];
		var num2 = 0;
		array3[num2++] = Application0;
		array2.CopyTo(array3, num2);
		num2 += array2.Length;
		array.CopyTo(array3, num2);
		num2 += array.Length;
		tokId.CopyTo(array3.AsSpan(num2));
		num2 += tokId.Length;
		inner.CopyTo(array3.AsSpan(num2));
		return array3;
	}

	private static bool IsKerberosOid(ReadOnlySpan<byte> oidTlv)
	{
		try
		{
			var text = new AsnReader(oidTlv.ToArray(), AsnEncodingRules.DER).ReadObjectIdentifier();
			return text == "1.2.840.113554.1.2.2" || text == "1.2.840.48018.1.2.2";
		}
		catch (AsnContentException)
		{
			return false;
		}
	}

	private static byte[] EncodeOidTlv(string oid)
	{
		var asnWriter = new AsnWriter(AsnEncodingRules.DER);
		asnWriter.WriteObjectIdentifier(oid);
		return asnWriter.Encode();
	}

	private static bool TryReadLength(ReadOnlySpan<byte> data, ref int pos, out int length)
	{
		length = 0;
		if (pos >= data.Length)
		{
			return false;
		}

		var b = data[pos++];
		if ((b & 0x80) == 0)
		{
			length = b;
			return true;
		}

		var num = b & 0x7F;
		if (num == 0 || num > 4 || pos + num > data.Length)
		{
			return false;
		}

		var num2 = 0;
		for (var i = 0; i < num; i++)
		{
			num2 = (num2 << 8) | data[pos++];
		}

		if (num2 < 0)
		{
			return false;
		}

		length = num2;
		return true;
	}

	private static byte[] EncodeLength(int length)
	{
		if (length < 128)
		{
			return [(byte)length];
		}

		var list = new List<byte>(4);
		for (var num = length; num > 0; num >>= 8)
		{
			list.Insert(0, (byte)(num & 0xFF));
		}

		var array = new byte[1 + list.Count];
		array[0] = (byte)(0x80 | list.Count);
		list.CopyTo(array, 1);
		return array;
	}
}
