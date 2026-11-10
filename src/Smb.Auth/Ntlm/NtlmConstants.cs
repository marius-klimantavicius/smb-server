using System;

namespace Smb.Auth.Ntlm;

public static class NtlmConstants
{
    public const uint MessageTypeNegotiate = 1u;

    public const uint MessageTypeChallenge = 2u;

    public const uint MessageTypeAuthenticate = 3u;

    public static ReadOnlySpan<byte> Signature => "NTLMSSP\0"u8;

    public static bool IsNtlmSsp(ReadOnlySpan<byte> token)
    {
        if (token.Length >= 8)
        {
            return token.Slice(0, 8).SequenceEqual(Signature);
        }

        return false;
    }
}
