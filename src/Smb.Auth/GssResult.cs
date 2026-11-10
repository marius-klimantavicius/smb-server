using Smb.Protocol.Enums;

namespace Smb.Auth;

public sealed class GssResult
{
    public required NtStatus Status { get; init; }

    public byte[]? OutToken { get; init; }

    public byte[]? SessionKey { get; init; }

    public SecurityIdentity? Identity { get; init; }

    public bool IsSuccess => Status == NtStatus.Success;

    public bool NeedsMoreProcessing => Status == NtStatus.MoreProcessingRequired;

    public static GssResult Continue(byte[] outToken)
    {
        return new GssResult
        {
            Status = NtStatus.MoreProcessingRequired,
            OutToken = outToken,
        };
    }

    public static GssResult Succeeded(byte[] sessionKey, SecurityIdentity identity, byte[]? outToken = null)
    {
        return new GssResult
        {
            Status = NtStatus.Success,
            SessionKey = sessionKey,
            Identity = identity,
            OutToken = outToken,
        };
    }

    public static GssResult Failed(NtStatus status = NtStatus.LogonFailure, byte[]? outToken = null)
    {
        return new GssResult
        {
            Status = status,
            OutToken = outToken,
        };
    }
}
