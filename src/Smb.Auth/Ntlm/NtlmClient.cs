using System;
using System.Security.Cryptography;
using System.Text;
using Smb.Crypto;
using Smb.Protocol.Wire;

namespace Smb.Auth.Ntlm;

public sealed class NtlmClient
{
	private readonly string _domain;

	private readonly string _user;

	private readonly string _password;

	private byte[] _negotiate = Array.Empty<byte>();

	private byte[] _challenge = Array.Empty<byte>();

	public byte[] ExportedSessionKey { get; private set; } = Array.Empty<byte>();

	public NtlmClient(string domain, string user, string password)
	{
		_domain = domain;
		_user = user;
		_password = password;
	}

	public byte[] BuildNegotiate()
	{
		var value = NtlmNegotiateFlags.NegotiateUnicode | NtlmNegotiateFlags.RequestTarget | NtlmNegotiateFlags.NegotiateNtlm | NtlmNegotiateFlags.NegotiateAlwaysSign | NtlmNegotiateFlags.NegotiateExtendedSessionSecurity | NtlmNegotiateFlags.Negotiate128 | NtlmNegotiateFlags.NegotiateKeyExchange | NtlmNegotiateFlags.Negotiate56;
		var growableWriter = new GrowableWriter(40);
		growableWriter.WriteBytes(NtlmConstants.Signature);
		growableWriter.WriteUInt32(1u);
		growableWriter.WriteUInt32((uint)value);
		growableWriter.WriteUInt64(0uL);
		growableWriter.WriteUInt64(0uL);
		_negotiate = growableWriter.ToArray();
		return _negotiate;
	}

	public byte[] BuildAuthenticate(ReadOnlySpan<byte> challengeToken, bool withMic = false)
	{
		_challenge = challengeToken.ToArray();
		var (array, array2) = ParseChallenge(challengeToken);
		if (withMic)
		{
			array2 = AddMsvAvFlags(array2, 2u);
		}

		var ntowfV = NtlmCryptography.NtowfV2(NtlmCryptography.NtHash(_password), _user, _domain);
		var value = ExtractTimestamp(array2) ?? DateTime.UtcNow.ToFileTimeUtc();
		var bytes = RandomNumberGenerator.GetBytes(8);
		var growableWriter = new GrowableWriter(64 + array2.Length);
		growableWriter.WriteByte(1);
		growableWriter.WriteByte(1);
		growableWriter.WriteUInt16(0);
		growableWriter.WriteUInt32(0u);
		growableWriter.WriteUInt64((ulong)value);
		growableWriter.WriteBytes(bytes);
		growableWriter.WriteUInt32(0u);
		growableWriter.WriteBytes(array2);
		growableWriter.WriteUInt32(0u);
		var array3 = growableWriter.ToArray();
		var array4 = NtlmCryptography.NtProofString(ntowfV, array, array3);
		var array5 = new byte[array4.Length + array3.Length];
		array4.CopyTo(array5, 0);
		array3.CopyTo(array5, array4.Length);
		var array6 = NtlmCryptography.SessionBaseKey(ntowfV, array4);
		ExportedSessionKey = RandomNumberGenerator.GetBytes(16);
		var encryptedSessionKey = Rc4.Transform(array6, ExportedSessionKey);
		var array7 = BuildAuthenticateMessage(array5, encryptedSessionKey);
		if (withMic)
		{
			NtlmCryptography.ComputeMic(ExportedSessionKey, _negotiate, _challenge, array7).CopyTo(array7, 72);
		}

		return array7;
	}

	private static byte[] AddMsvAvFlags(byte[] targetInfo, uint flags)
	{
		var list = NtlmAvPairs.Decode(targetInfo);
		list.RemoveAll(p => p.Id == NtlmAvId.Flags);
		list.Add(new NtlmAvPair(NtlmAvId.Flags, BitConverter.GetBytes(flags)));
		return NtlmAvPairs.Encode(list);
	}

	private byte[] BuildAuthenticateMessage(byte[] ntResponse, byte[] encryptedSessionKey)
	{
		var bytes = Encoding.Unicode.GetBytes(_domain);
		var bytes2 = Encoding.Unicode.GetBytes(_user);
		var bytes3 = Encoding.Unicode.GetBytes("CLIENT");
		var array = new byte[24];
		var value = NtlmNegotiateFlags.NegotiateUnicode | NtlmNegotiateFlags.RequestTarget | NtlmNegotiateFlags.NegotiateNtlm | NtlmNegotiateFlags.NegotiateAlwaysSign | NtlmNegotiateFlags.NegotiateExtendedSessionSecurity | NtlmNegotiateFlags.NegotiateTargetInfo | NtlmNegotiateFlags.Negotiate128 | NtlmNegotiateFlags.NegotiateKeyExchange | NtlmNegotiateFlags.Negotiate56;
		int offset;
		int offset2;
		int offset3;
		int offset4;
		int offset5;
		int offset6;
		var growableWriter = new GrowableWriter((offset = (offset2 = (offset3 = (offset4 = (offset5 = (offset6 = 88) + array.Length) + ntResponse.Length) + bytes.Length) + bytes2.Length) + bytes3.Length) + encryptedSessionKey.Length);
		growableWriter.WriteBytes(NtlmConstants.Signature);
		growableWriter.WriteUInt32(3u);
		WriteField(growableWriter, array.Length, offset6);
		WriteField(growableWriter, ntResponse.Length, offset5);
		WriteField(growableWriter, bytes.Length, offset4);
		WriteField(growableWriter, bytes2.Length, offset3);
		WriteField(growableWriter, bytes3.Length, offset2);
		WriteField(growableWriter, encryptedSessionKey.Length, offset);
		growableWriter.WriteUInt32((uint)value);
		growableWriter.WriteUInt64(0uL);
		growableWriter.WriteBytes(new byte[16]);
		growableWriter.WriteBytes(array);
		growableWriter.WriteBytes(ntResponse);
		growableWriter.WriteBytes(bytes);
		growableWriter.WriteBytes(bytes2);
		growableWriter.WriteBytes(bytes3);
		growableWriter.WriteBytes(encryptedSessionKey);
		return growableWriter.ToArray();
	}

	private static void WriteField(GrowableWriter w, int length, int offset)
	{
		w.WriteUInt16((ushort)length);
		w.WriteUInt16((ushort)length);
		w.WriteUInt32((uint)offset);
	}

	private static (byte[] serverChallenge, byte[] targetInfo) ParseChallenge(ReadOnlySpan<byte> data)
	{
		if (!NtlmConstants.IsNtlmSsp(data))
		{
			throw new FormatException("Not an NTLMSSP token.");
		}

		var spanReader = new SpanReader(data);
		spanReader.Skip(8);
		spanReader.ReadUInt32();
		spanReader.Skip(8);
		spanReader.ReadUInt32();
		var item = spanReader.ReadByteArray(8);
		spanReader.Skip(8);
		int num = spanReader.ReadUInt16();
		spanReader.Skip(2);
		var start = (int)spanReader.ReadUInt32();
		var item2 = ((num == 0) ? Array.Empty<byte>() : data.Slice(start, num).ToArray());
		return (serverChallenge: item, targetInfo: item2);
	}

	private static long? ExtractTimestamp(byte[] targetInfo)
	{
		foreach (var item in NtlmAvPairs.Decode(targetInfo))
		{
			if (item.Id == NtlmAvId.Timestamp && item.Value.Length == 8)
			{
				return BitConverter.ToInt64(item.Value);
			}
		}

		return null;
	}
}
