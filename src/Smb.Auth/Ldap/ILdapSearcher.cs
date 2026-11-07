using System.Collections.Generic;

namespace Smb.Auth.Ldap;

public interface ILdapSearcher
{
	IReadOnlyList<LdapEntry> Search(string baseDn, string filter, LdapSearchScope scope, IReadOnlyList<string> attributes);
}
