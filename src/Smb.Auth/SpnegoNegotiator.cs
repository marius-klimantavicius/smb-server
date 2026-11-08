using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Smb.Auth.Ntlm;
using Smb.Auth.Oids;
using Smb.Crypto;
using Smb.Protocol.Enums;

namespace Smb.Auth;

public sealed class SpnegoNegotiator : ISpnegoNegotiator
{
	private sealed class Context : ISpnegoServerContext
	{
		private readonly IReadOnlyList<IGssMechanismFactory> _factories;

		private readonly bool _requireMechListMic;

		private IGssMechanism? _mech;

		private bool _raw;

		private bool _supportedMechEmitted;

		private string? _selectedOid;

		private byte[]? _mechListBytes;

		public Context(IReadOnlyList<IGssMechanismFactory> factories, bool requireMechListMic)
		{
			_factories = factories;
			_requireMechListMic = requireMechListMic;
		}

		public GssResult Accept(ReadOnlySpan<byte> token)
		{
			if (_mech == null && NtlmConstants.IsNtlmSsp(token))
			{
				var gssMechanismFactory = Find("1.3.6.1.4.1.311.2.2.10");
				if (gssMechanismFactory == null)
				{
					return GssResult.Failed(NtStatus.InvalidParameter);
				}

				_mech = gssMechanismFactory.Create();
				_selectedOid = gssMechanismFactory.MechOid;
				_raw = true;
				return _mech.Accept(token);
			}

			if (_raw && _mech != null)
			{
				return _mech.Accept(token);
			}

			SpnegoParseResult spnegoParseResult;
			try
			{
				spnegoParseResult = SpnegoTokens.Parse(token);
			}
			catch (Exception)
			{
				return GssResult.Failed(NtStatus.InvalidParameter);
			}

			if (_mech == null)
			{
				_mechListBytes = spnegoParseResult.MechListBytes;
				return SelectAndAccept(spnegoParseResult);
			}

			return Wrap(_mech.Accept(spnegoParseResult.MechToken ?? Array.Empty<byte>()), spnegoParseResult.MechListMic);
		}

		private GssResult SelectAndAccept(SpnegoParseResult parsed)
		{
			if (parsed.MechTypes.Count > 0)
			{
				var gssMechanismFactory = Find(parsed.MechTypes[0]);
				if (gssMechanismFactory != null)
				{
					_mech = gssMechanismFactory.Create();
					_selectedOid = gssMechanismFactory.MechOid;
					return Wrap(_mech.Accept(parsed.MechToken ?? Array.Empty<byte>()), parsed.MechListMic);
				}

				foreach (var mechType in parsed.MechTypes)
				{
					var gssMechanismFactory2 = Find(mechType);
					if (gssMechanismFactory2 != null)
					{
						_mech = gssMechanismFactory2.Create();
						_selectedOid = gssMechanismFactory2.MechOid;
						_supportedMechEmitted = true;
						return GssResult.Continue(SpnegoTokens.CreateNegTokenResp(1, gssMechanismFactory2.MechOid));
					}
				}

				return Reject(NtStatus.LogonFailure);
			}

			if (_factories.Count == 1)
			{
				_mech = _factories[0].Create();
				_selectedOid = _factories[0].MechOid;
				return Wrap(_mech.Accept(parsed.MechToken ?? Array.Empty<byte>()), parsed.MechListMic);
			}

			return Reject(NtStatus.InvalidParameter);
		}

		private GssResult Wrap(GssResult inner, byte[]? mechListMic)
		{
			if (_raw)
			{
				return inner;
			}

			var supportedMech = _supportedMechEmitted ? null : _selectedOid;
			_supportedMechEmitted = true;
			if (inner.NeedsMoreProcessing)
			{
				return GssResult.Continue(SpnegoTokens.CreateNegTokenResp(1, supportedMech, inner.OutToken));
			}

			if (inner.IsSuccess)
			{
				var ntStatus = VerifyMechListMic(inner.SessionKey, mechListMic);
				if (ntStatus != NtStatus.Success)
				{
					return Reject(ntStatus);
				}

				// RFC 4178 section 5: when the initiator supplies a MIC,
				// verify it and return the acceptor's MIC over the original DER list.
				var replyMic = (mechListMic != null || _requireMechListMic) && _mechListBytes != null &&
					_mech is NtlmServerMechanism ntlm
					? ntlm.MechanismListMic(inner.SessionKey!, client: false, _mechListBytes) : null;
				var outToken = SpnegoTokens.CreateNegTokenResp(0, supportedMech, inner.OutToken, replyMic);
				return GssResult.Succeeded(inner.SessionKey!, inner.Identity!, outToken);
			}

			return new GssResult
			{
				Status = inner.Status,
				OutToken = SpnegoTokens.CreateNegTokenResp(2),
			};
		}

		private NtStatus VerifyMechListMic(byte[]? sessionKey, byte[]? mechListMic)
		{
			if (!_requireMechListMic && mechListMic == null)
			{
				return NtStatus.Success;
			}

			if (_selectedOid != "1.3.6.1.4.1.311.2.2.10")
			{
				return NtStatus.Success;
			}

			if (_mechListBytes == null)
			{
				return NtStatus.Success;
			}

			if (mechListMic == null || sessionKey == null)
			{
				return NtStatus.AccessDenied;
			}

			var array = _mech is NtlmServerMechanism ntlm
				? ntlm.MechanismListMic(sessionKey, client: true, _mechListBytes)
				: NtlmCryptography.NtlmMechListMic(sessionKey, client: true, _mechListBytes);
			if (array.Length != 16 || array.Length != mechListMic.Length || !CryptographicOperations.FixedTimeEquals(array, mechListMic))
			{
				return NtStatus.AccessDenied;
			}

			return NtStatus.Success;
		}

		private static GssResult Reject(NtStatus status)
		{
			return new GssResult
			{
				Status = status,
				OutToken = SpnegoTokens.CreateNegTokenResp(2),
			};
		}

		private IGssMechanismFactory? Find(string oid)
		{
			foreach (var factory in _factories)
			{
				if (factory.MechOid == oid)
				{
					return factory;
				}
			}

			return null;
		}
	}

	private readonly IReadOnlyList<IGssMechanismFactory> _factories;

	public bool RequireMechListMic { get; init; }

	public SpnegoNegotiator(params IGssMechanismFactory[] factories)
		: this((IReadOnlyList<IGssMechanismFactory>)factories)
	{
	}

	public SpnegoNegotiator(IReadOnlyList<IGssMechanismFactory> factories)
	{
		if (factories == null || factories.Count == 0)
		{
			throw new ArgumentException("At least one GSS mechanism factory is required.", nameof(factories));
		}

		_factories = factories;
	}

	public byte[] CreateInitialServerToken()
	{
		var list = new List<string>(_factories.Count);
		foreach (var factory in _factories)
		{
			if (!list.Contains(factory.MechOid))
			{
				list.Add(factory.MechOid);
			}
		}

		return SpnegoTokens.CreateNegTokenInit2(list);
	}

	public ISpnegoServerContext CreateServerContext()
	{
		return new Context(_factories, RequireMechListMic);
	}
}
