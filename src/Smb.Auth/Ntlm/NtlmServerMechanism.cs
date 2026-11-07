using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Smb.Crypto;
using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Auth.Ntlm;

public sealed class NtlmServerMechanism : IGssMechanism
{
	private enum Stage
	{
		ExpectNegotiate,
		ExpectAuthenticate,
		Done,
	}

	private readonly IIdentityBackend _backend;

	private readonly NtlmServerOptions _options;

	private Stage _stage;

	private byte[] _serverChallenge = Array.Empty<byte>();

	private byte[] _negotiateMessage = Array.Empty<byte>();

	private byte[] _challengeMessage = Array.Empty<byte>();

	public string MechOid => "1.3.6.1.4.1.311.2.2.10";

	public bool IsComplete => _stage == Stage.Done;

	public NtlmServerMechanism(IIdentityBackend backend, NtlmServerOptions options)
	{
		_backend = backend;
		_options = options;
	}

	public GssResult Accept(ReadOnlySpan<byte> inToken)
	{
		return _stage switch
		{
			Stage.ExpectNegotiate => HandleNegotiate(inToken),
			Stage.ExpectAuthenticate => HandleAuthenticate(inToken),
			_ => GssResult.Failed(NtStatus.AccessDenied),
		};
	}

	private GssResult HandleNegotiate(ReadOnlySpan<byte> inToken)
	{
		_negotiateMessage = inToken.ToArray();
		_serverChallenge = RandomNumberGenerator.GetBytes(8);
		var targetInfo = NtlmAvPairs.Encode([
			new NtlmAvPair(NtlmAvId.NbDomainName, Encoding.Unicode.GetBytes(_options.NetbiosDomainName)),
			new NtlmAvPair(NtlmAvId.NbComputerName, Encoding.Unicode.GetBytes(_options.NetbiosComputerName)),
			new NtlmAvPair(NtlmAvId.DnsDomainName, Encoding.Unicode.GetBytes(_options.DnsDomainName)),
			new NtlmAvPair(NtlmAvId.DnsComputerName, Encoding.Unicode.GetBytes(_options.DnsComputerName)),
			new NtlmAvPair(NtlmAvId.Timestamp, BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc())),
		]);
		var ntlmChallengeMessage = new NtlmChallengeMessage
		{
			ServerChallenge = _serverChallenge,
			TargetName = _options.NetbiosDomainName,
			Flags = (NtlmNegotiateFlags.NegotiateUnicode | NtlmNegotiateFlags.RequestTarget | NtlmNegotiateFlags.NegotiateNtlm | NtlmNegotiateFlags.NegotiateAlwaysSign | NtlmNegotiateFlags.TargetTypeDomain | NtlmNegotiateFlags.NegotiateExtendedSessionSecurity | NtlmNegotiateFlags.NegotiateTargetInfo | NtlmNegotiateFlags.Negotiate128 | NtlmNegotiateFlags.NegotiateKeyExchange | NtlmNegotiateFlags.Negotiate56),
			TargetInfo = targetInfo,
		};
		_stage = Stage.ExpectAuthenticate;
		_challengeMessage = ntlmChallengeMessage.ToArray();
		return GssResult.Continue(_challengeMessage);
	}

	private GssResult HandleAuthenticate(ReadOnlySpan<byte> inToken)
	{
		_stage = Stage.Done;
		NtlmAuthenticateMessage ntlmAuthenticateMessage;
		try
		{
			ntlmAuthenticateMessage = NtlmAuthenticateMessage.Parse(inToken);
		}
		catch (Exception ex) when (ex is FormatException || ex is SmbWireFormatException)
		{
			return GssResult.Failed(NtStatus.InvalidParameter);
		}

		if (ntlmAuthenticateMessage.NtChallengeResponse.Length < 16)
		{
			return GssResult.Failed();
		}

		if (!_backend.TryGetNtHash(ntlmAuthenticateMessage.DomainName, ntlmAuthenticateMessage.UserName, out var ntHash))
		{
			return GssResult.Failed();
		}

		var ntowfV = NtlmCryptography.NtowfV2(ntHash, ntlmAuthenticateMessage.UserName, ntlmAuthenticateMessage.DomainName);
		var array = NtlmCryptography.NtProofString(ntowfV, _serverChallenge, ntlmAuthenticateMessage.ClientChallengeBlob);
		if (!CryptographicOperations.FixedTimeEquals(array, ntlmAuthenticateMessage.NtProofString))
		{
			return GssResult.Failed();
		}

		var sessionBaseKey = NtlmCryptography.SessionBaseKey(ntowfV, array);
		var keyExchange = ntlmAuthenticateMessage.Flags.HasFlag(NtlmNegotiateFlags.NegotiateKeyExchange);
		var array2 = NtlmCryptography.ExportedSessionKey(sessionBaseKey, keyExchange, ntlmAuthenticateMessage.EncryptedRandomSessionKey);
		var flag = ClientAnnouncedMic(ntlmAuthenticateMessage.ClientChallengeBlob);
		if (flag || _options.RequireMessageIntegrity)
		{
			if (!flag)
			{
				return GssResult.Failed();
			}

			if (!VerifyMic(array2, inToken, ntlmAuthenticateMessage.Mic))
			{
				return GssResult.Failed();
			}
		}

		SecurityIdentity identity;
		try
		{
			identity = _backend.Resolve(ntlmAuthenticateMessage.DomainName, ntlmAuthenticateMessage.UserName);
		}
		catch (KeyNotFoundException)
		{
			return GssResult.Failed();
		}

		return GssResult.Succeeded(array2, identity);
	}

	private static bool ClientAnnouncedMic(ReadOnlySpan<byte> clientChallengeBlob)
	{
		if (clientChallengeBlob.Length <= 28)
		{
			return false;
		}

		foreach (var item in NtlmAvPairs.Decode(clientChallengeBlob.Slice(28)))
		{
			if (item.Id == NtlmAvId.Flags && item.Value.Length >= 4)
			{
				return (BitConverter.ToUInt32(item.Value, 0) & 2) != 0;
			}
		}

		return false;
	}

	private bool VerifyMic(byte[] exportedSessionKey, ReadOnlySpan<byte> authenticateMessage, byte[] receivedMic)
	{
		if (_negotiateMessage.Length == 0 || _challengeMessage.Length == 0)
		{
			return false;
		}

		if (authenticateMessage.Length < 88)
		{
			return false;
		}

		var array = authenticateMessage.ToArray();
		Array.Clear(array, 72, 16);
		return CryptographicOperations.FixedTimeEquals(NtlmCryptography.ComputeMic(exportedSessionKey, _negotiateMessage, _challengeMessage, array), receivedMic);
	}
}
