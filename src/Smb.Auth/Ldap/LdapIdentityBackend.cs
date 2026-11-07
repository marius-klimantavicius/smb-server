using System;
using System.Collections.Generic;
using System.Globalization;

namespace Smb.Auth.Ldap;

public sealed class LdapIdentityBackend : IIdentityBackend, ISidResolver
{
	private readonly ILdapSearcher _searcher;

	private readonly LdapIdentityBackendOptions _options;

	private readonly TtlCache<string, SecurityIdentity> _identityCache;

	private readonly TtlCache<string, string> _accountBySidCache;

	private readonly TtlCache<string, string> _sidByAccountCache;

	public LdapIdentityBackend(ILdapSearcher searcher, LdapIdentityBackendOptions options, TimeProvider? timeProvider = null)
	{
		_searcher = searcher ?? throw new ArgumentNullException(nameof(searcher));
		_options = options ?? throw new ArgumentNullException(nameof(options));
		if (string.IsNullOrWhiteSpace(_options.SearchBase))
		{
			throw new ArgumentException("SearchBase is required.", nameof(options));
		}

		var clock = timeProvider ?? TimeProvider.System;
		_identityCache = new TtlCache<string, SecurityIdentity>(_options.CacheTtl, clock, StringComparer.OrdinalIgnoreCase);
		_accountBySidCache = new TtlCache<string, string>(_options.CacheTtl, clock, StringComparer.OrdinalIgnoreCase);
		_sidByAccountCache = new TtlCache<string, string>(_options.CacheTtl, clock, StringComparer.OrdinalIgnoreCase);
	}

	public void ClearCache()
	{
		_identityCache.Clear();
		_accountBySidCache.Clear();
		_sidByAccountCache.Clear();
	}

	public bool TryGetNtHash(string domain, string user, out byte[] ntHash)
	{
		ntHash = Array.Empty<byte>();
		return false;
	}

	public SecurityIdentity Resolve(string domain, string user)
	{
		return _identityCache.GetOrAdd(domain + "\\" + user, () => ResolveUncached(domain, user));
	}

	private SecurityIdentity ResolveUncached(string domain, string user)
	{
		var ldapEntry = FindUser(user) ?? throw new KeyNotFoundException($"Unknown user {domain}\\{user}.");
		string userSid = null;
		var bytes = ldapEntry.GetBytes(_options.ObjectSidAttribute);
		if (bytes != null && SidConverter.TryToString(bytes, out var sid))
		{
			userSid = sid;
		}

		var userName = ldapEntry.GetString(_options.SamAccountNameAttribute) ?? user;
		var userPrincipalName = ldapEntry.GetString(_options.UserPrincipalNameAttribute);
		return new SecurityIdentity
		{
			DomainName = domain,
			UserName = userName,
			UserSid = userSid,
			UserPrincipalName = userPrincipalName,
			GroupSids = ResolveGroupSids(ldapEntry),
		};
	}

	public bool TryGetAccountName(string sid, out string accountName)
	{
		accountName = string.Empty;
		if (!SidConverter.TryToBinary(sid, out var binary))
		{
			return false;
		}

		var orAdd = _accountBySidCache.GetOrAdd(sid, () =>
		{
			var filter = string.Format(CultureInfo.InvariantCulture, _options.ObjectBySidFilterFormat, SidConverter.ToLdapFilterValue(binary));
			var readOnlyList = _searcher.Search(_options.SearchBase, filter, LdapSearchScope.Subtree, [_options.SamAccountNameAttribute]);
			return (readOnlyList.Count <= 0) ? string.Empty : (readOnlyList[0].GetString(_options.SamAccountNameAttribute) ?? string.Empty);
		});
		if (string.IsNullOrEmpty(orAdd))
		{
			return false;
		}

		accountName = orAdd;
		return true;
	}

	public bool TryGetSid(string accountName, out string sid)
	{
		sid = string.Empty;
		var orAdd = _sidByAccountCache.GetOrAdd(accountName, () =>
		{
			var array = FindUser(accountName)?.GetBytes(_options.ObjectSidAttribute);
			return (array == null || !SidConverter.TryToString(array, out var sid2)) ? string.Empty : sid2;
		});
		if (string.IsNullOrEmpty(orAdd))
		{
			return false;
		}

		sid = orAdd;
		return true;
	}

	private LdapEntry? FindUser(string user)
	{
		var filter = string.Format(CultureInfo.InvariantCulture, _options.UserByNameFilterFormat, LdapFilter.Escape(user));
		var attributes = ((!_options.UseTokenGroups) ? (string[])[_options.SamAccountNameAttribute, _options.ObjectSidAttribute, _options.UserPrincipalNameAttribute, _options.MemberOfAttribute] : [ _options.SamAccountNameAttribute, _options.ObjectSidAttribute, _options.UserPrincipalNameAttribute ]);
		var readOnlyList = _searcher.Search(_options.SearchBase, filter, LdapSearchScope.Subtree, attributes);
		if (readOnlyList.Count <= 0)
		{
			return null;
		}

		return readOnlyList[0];
	}

	private IReadOnlyList<string> ResolveGroupSids(LdapEntry entry)
	{
		if (_options.UseTokenGroups)
		{
			return ReadTokenGroups(entry.DistinguishedName);
		}

		var list = new List<string>();
		foreach (var @string in entry.GetStrings(_options.MemberOfAttribute))
		{
			var text = LookupSidByDn(@string);
			if (text != null)
			{
				list.Add(text);
			}
		}

		return list;
	}

	private IReadOnlyList<string> ReadTokenGroups(string userDn)
	{
		var readOnlyList = _searcher.Search(userDn, "(objectClass=*)", LdapSearchScope.Base, [_options.TokenGroupsAttribute]);
		if (readOnlyList.Count == 0)
		{
			return Array.Empty<string>();
		}

		var list = new List<string>();
		foreach (var byteValue in readOnlyList[0].GetByteValues(_options.TokenGroupsAttribute))
		{
			if (SidConverter.TryToString(byteValue, out var sid))
			{
				list.Add(sid);
			}
		}

		return list;
	}

	private string? LookupSidByDn(string distinguishedName)
	{
		var readOnlyList = _searcher.Search(distinguishedName, "(objectClass=*)", LdapSearchScope.Base, [_options.ObjectSidAttribute]);
		if (readOnlyList.Count == 0)
		{
			return null;
		}

		var bytes = readOnlyList[0].GetBytes(_options.ObjectSidAttribute);
		if (bytes == null || !SidConverter.TryToString(bytes, out var sid))
		{
			return null;
		}

		return sid;
	}
}
