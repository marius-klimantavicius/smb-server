using System;

namespace Smb.Auth.Ntlm;

[Flags]
public enum NtlmNegotiateFlags : uint
{
    NegotiateUnicode = 1u,
    NegotiateOem = 2u,
    RequestTarget = 4u,
    NegotiateSign = 0x10u,
    NegotiateSeal = 0x20u,
    NegotiateNtlm = 0x200u,
    NegotiateAlwaysSign = 0x8000u,
    TargetTypeDomain = 0x10000u,
    TargetTypeServer = 0x20000u,
    NegotiateExtendedSessionSecurity = 0x80000u,
    NegotiateTargetInfo = 0x800000u,
    NegotiateVersion = 0x2000000u,
    Negotiate128 = 0x20000000u,
    NegotiateKeyExchange = 0x40000000u,
    Negotiate56 = 0x80000000u,
}
