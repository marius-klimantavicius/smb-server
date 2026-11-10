using Smb.Protocol.Security;

namespace Smb.Protocol.Messages;

public readonly record struct FileQuotaInformation(Sid Sid, long ChangeTime, long QuotaUsed, long QuotaThreshold, long QuotaLimit)
{
    public const long Unlimited = -1L;
}
