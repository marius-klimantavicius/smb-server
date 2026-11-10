namespace Smb.Protocol.Enums;

public static class NtStatusExtensions
{
    public static bool IsSuccess(this NtStatus status)
    {
        return (uint)status >> 30 == 0;
    }

    public static bool IsError(this NtStatus status)
    {
        return (uint)status >> 30 == 3;
    }
}
