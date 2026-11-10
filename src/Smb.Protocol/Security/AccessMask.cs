namespace Smb.Protocol.Security;

public static class AccessMask
{
    public const uint FileReadData = 1u;

    public const uint FileWriteData = 2u;

    public const uint FileAppendData = 4u;

    public const uint FileReadEa = 8u;

    public const uint FileWriteEa = 16u;

    public const uint FileExecute = 32u;

    public const uint FileDeleteChild = 64u;

    public const uint FileReadAttributes = 128u;

    public const uint FileWriteAttributes = 256u;

    public const uint Delete = 65536u;

    public const uint ReadControl = 131072u;

    public const uint WriteDac = 262144u;

    public const uint WriteOwner = 524288u;

    public const uint Synchronize = 1048576u;

    public const uint MaximumAllowed = 33554432u;

    public const uint GenericAll = 268435456u;

    public const uint GenericExecute = 536870912u;

    public const uint GenericWrite = 1073741824u;

    public const uint GenericRead = 2147483648u;

    public const uint WriteAccess = 6u;

    public const uint FileGenericRead = 1179785u;

    public const uint FileGenericWrite = 1179926u;

    public const uint FileGenericExecute = 1179808u;

    public const uint FileAllAccess = 2032127u;

    public static uint MapGenericToSpecific(uint mask)
    {
        var num = mask & 0xFFFFFFF;
        if ((mask & GenericRead) != 0)
        {
            num |= FileGenericRead;
        }

        if ((mask & GenericWrite) != 0)
        {
            num |= FileGenericWrite;
        }

        if ((mask & GenericExecute) != 0)
        {
            num |= FileGenericExecute;
        }

        if ((mask & GenericAll) != 0)
        {
            num |= FileAllAccess;
        }

        return num;
    }
}
