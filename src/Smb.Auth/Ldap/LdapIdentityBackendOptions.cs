using System;

namespace Smb.Auth.Ldap;

public sealed class LdapIdentityBackendOptions
{
    public required string SearchBase { get; init; }

    public string UserByNameFilterFormat { get; init; } = "(&(objectClass=user)(sAMAccountName={0}))";

    public string ObjectBySidFilterFormat { get; init; } = "(objectSid={0})";

    public string SamAccountNameAttribute { get; init; } = "sAMAccountName";

    public string ObjectSidAttribute { get; init; } = "objectSid";

    public string UserPrincipalNameAttribute { get; init; } = "userPrincipalName";

    public string TokenGroupsAttribute { get; init; } = "tokenGroups";

    public string MemberOfAttribute { get; init; } = "memberOf";

    public bool UseTokenGroups { get; init; } = true;

    public TimeSpan CacheTtl { get; init; } = TimeSpan.FromMinutes(5L);
}
