namespace Smb.Auth;

public interface ISidResolver
{
    bool TryGetAccountName(string sid, out string accountName);

    bool TryGetSid(string accountName, out string sid);
}
