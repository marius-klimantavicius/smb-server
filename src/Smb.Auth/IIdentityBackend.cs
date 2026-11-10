namespace Smb.Auth;

public interface IIdentityBackend
{
    bool TryGetNtHash(string domain, string user, out byte[] ntHash);

    SecurityIdentity Resolve(string domain, string user);
}
