using Smb.Protocol.Enums;

namespace Smb.Auth.Kerberos;

public sealed class KerberosValidationResult
{
	public required NtStatus Status { get; init; }

	public byte[]? SessionKey { get; init; }

	public SecurityIdentity? Identity { get; init; }

	public byte[]? ApRep { get; init; }

	public bool IsSuccess => Status == NtStatus.Success;

	public static KerberosValidationResult Succeeded(byte[] sessionKey, SecurityIdentity identity, byte[]? apRep = null)
	{
		return new KerberosValidationResult
		{
			Status = NtStatus.Success,
			SessionKey = sessionKey,
			Identity = identity,
			ApRep = apRep,
		};
	}

	public static KerberosValidationResult Failed(NtStatus status = NtStatus.LogonFailure)
	{
		return new KerberosValidationResult
		{
			Status = status,
		};
	}
}
