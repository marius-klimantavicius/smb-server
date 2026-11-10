using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Smb.Crypto;

namespace Smb.Auth;

public sealed class InMemoryIdentityBackend : IIdentityBackend
{
    private sealed record UserEntry(string Domain, string User, byte[] NtHash, SecurityIdentity Identity);

    private readonly ConcurrentDictionary<string, UserEntry> _users = new ConcurrentDictionary<string, UserEntry>(StringComparer.OrdinalIgnoreCase);

    public InMemoryIdentityBackend AddUser(string domain, string user, string password, string? userSid = null, IReadOnlyList<string>? groupSids = null)
    {
        return AddUserWithHash(domain, user, NtlmCryptography.NtHash(password), userSid, groupSids);
    }

    public InMemoryIdentityBackend AddUserWithHash(string domain, string user, byte[] ntHash, string? userSid = null, IReadOnlyList<string>? groupSids = null)
    {
        var identity = new SecurityIdentity
        {
            DomainName = domain,
            UserName = user,
            UserSid = userSid,
            GroupSids = (groupSids ?? Array.Empty<string>()),
        };
        _users[Key(domain, user)] = new UserEntry(domain, user, ntHash, identity);
        return this;
    }

    public bool TryGetNtHash(string domain, string user, out byte[] ntHash)
    {
        if (TryFind(domain, user, out var entry))
        {
            ntHash = entry.NtHash;
            return true;
        }

        ntHash = Array.Empty<byte>();
        return false;
    }

    public SecurityIdentity Resolve(string domain, string user)
    {
        if (!TryFind(domain, user, out var entry))
        {
            throw new KeyNotFoundException($"Unknown user {domain}\\{user}.");
        }

        return entry.Identity;
    }

    private bool TryFind(string domain, string user, [NotNullWhen(true)] out UserEntry? entry)
    {
        if (_users.TryGetValue(Key(domain, user), out entry))
        {
            return true;
        }

        foreach (var value in _users.Values)
        {
            if (string.Equals(value.User, user, StringComparison.OrdinalIgnoreCase))
            {
                entry = value;
                return true;
            }
        }

        return false;
    }

    private static string Key(string domain, string user)
    {
        return domain + "\\" + user;
    }
}
