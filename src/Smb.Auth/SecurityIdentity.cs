using System;
using System.Collections.Generic;

namespace Smb.Auth;

public sealed class SecurityIdentity
{
    public required string DomainName { get; init; }

    public required string UserName { get; init; }

    public string? UserPrincipalName { get; init; }

    public string? UserSid { get; init; }

    public IReadOnlyList<string> GroupSids { get; init; } = Array.Empty<string>();

    public bool IsAnonymous { get; init; }

    public bool IsGuest { get; init; }

    public override string ToString()
    {
        if (!IsAnonymous)
        {
            return DomainName + "\\" + UserName;
        }

        return "<anonymous>";
    }
}
