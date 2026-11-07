using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Smb.Crypto;

public static class NtlmCryptography
{
	private static ReadOnlySpan<byte> ClientSignMagic => "session key to client-to-server signing key magic constant\0"u8;
	private static ReadOnlySpan<byte> ServerSignMagic => "session key to server-to-client signing key magic constant\0"u8;
	private static ReadOnlySpan<byte> ClientSealMagic => "session key to client-to-server sealing key magic constant\0"u8;
	private static ReadOnlySpan<byte> ServerSealMagic => "session key to server-to-client sealing key magic constant\0"u8;

	public static byte[] NtHash(string password)
	{
		return Md4.Compute(Encoding.Unicode.GetBytes(password));
	}

	public static byte[] NtowfV2(byte[] ntHash, string user, string domain)
	{
		var bytes = Encoding.Unicode.GetBytes(user.ToUpperInvariant() + domain);
		using var hMACMD = new HMACMD5(ntHash);
		return hMACMD.ComputeHash(bytes);
	}

	public static byte[] NtowfV2FromPassword(string password, string user, string domain)
	{
		return NtowfV2(NtHash(password), user, domain);
	}

	public static byte[] NtProofString(byte[] ntowfV2, ReadOnlySpan<byte> serverChallenge, ReadOnlySpan<byte> temp)
	{
		var array = new byte[serverChallenge.Length + temp.Length];
		serverChallenge.CopyTo(array);
		temp.CopyTo(array.AsSpan(serverChallenge.Length));
		using var hMACMD = new HMACMD5(ntowfV2);
		return hMACMD.ComputeHash(array);
	}

	public static byte[] SessionBaseKey(byte[] ntowfV2, ReadOnlySpan<byte> ntProofStr)
	{
		using var hMACMD = new HMACMD5(ntowfV2);
		return hMACMD.ComputeHash(ntProofStr.ToArray());
	}

	public static byte[] ExportedSessionKey(byte[] sessionBaseKey, bool keyExchange, ReadOnlySpan<byte> encryptedRandomSessionKey)
	{
		if (!keyExchange || encryptedRandomSessionKey.IsEmpty)
		{
			return sessionBaseKey;
		}

		return Rc4.Transform(sessionBaseKey, encryptedRandomSessionKey);
	}

	public static byte[] ComputeMic(byte[] exportedSessionKey, ReadOnlySpan<byte> negotiate, ReadOnlySpan<byte> challenge, ReadOnlySpan<byte> authenticateWithZeroMic)
	{
		var array = new byte[negotiate.Length + challenge.Length + authenticateWithZeroMic.Length];
		negotiate.CopyTo(array);
		challenge.CopyTo(array.AsSpan(negotiate.Length));
		authenticateWithZeroMic.CopyTo(array.AsSpan(negotiate.Length + challenge.Length));
		using var hMACMD = new HMACMD5(exportedSessionKey);
		return hMACMD.ComputeHash(array);
	}

	public static byte[] NtlmSignKey(byte[] exportedSessionKey, bool client)
	{
		return Md5Concat(exportedSessionKey, client ? ClientSignMagic : ServerSignMagic);
	}

	public static byte[] NtlmSealKey(byte[] exportedSessionKey, bool client)
	{
		return Md5Concat(exportedSessionKey, client ? ClientSealMagic : ServerSealMagic);
	}

	private static byte[] Md5Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
	{
		var array = new byte[a.Length + b.Length];
		a.CopyTo(array.AsSpan(0));
		b.CopyTo(array.AsSpan(a.Length));
		return MD5.HashData(array);
	}

	public static byte[] NtlmMechListMic(byte[] exportedSessionKey, bool client, ReadOnlySpan<byte> message)
	{
		var key = NtlmSignKey(exportedSessionKey, client);
		var array = NtlmSealKey(exportedSessionKey, client);
		var array2 = new byte[4 + message.Length];
		message.CopyTo(array2.AsSpan(4));
		byte[] array3;
		using (var hmac = new HMACMD5(key))
		{
			array3 = hmac.ComputeHash(array2);
		}

		var array4 = Rc4.Transform(array, array3.AsSpan(0, 8));
		var array5 = new byte[16];
		BinaryPrimitives.WriteUInt32LittleEndian(array5.AsSpan(0), 1u);
		array4.CopyTo(array5, 4);
		BinaryPrimitives.WriteUInt32LittleEndian(array5.AsSpan(12), 0u);
		return array5;
	}
}
