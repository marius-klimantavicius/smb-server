using System;
using Smb.Protocol.Enums;

namespace Smb.Server;

public static class CreditManager
{
    private const int CreditUnit = 65536;

    public static ushort ComputeCreditCharge(SmbDialect dialect, int sendPayload, int expectedReceivePayload)
    {
        if (dialect == SmbDialect.Smb202)
        {
            return 0;
        }

        var num = Math.Max(sendPayload, expectedReceivePayload);
        if (num <= 0)
        {
            return 1;
        }

        var val = ((long)num + CreditUnit - 1) / CreditUnit;
        return (ushort)Math.Max(1, val);
    }

    public static ushort ComputeCreditGrant(ushort requested, ushort cap)
    {
        int num = requested;
        if (num > cap)
        {
            num = cap;
        }


        return (ushort)num;
    }

    public static bool IsWithinWindow(ulong messageId, ulong windowStart, ulong windowSize)
    {
        if (messageId >= windowStart)
        {
            return messageId - windowStart < windowSize;
        }

        return false;
    }
}
