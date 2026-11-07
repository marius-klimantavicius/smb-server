namespace Smb.Server.Authorization;

public sealed class AllowAllSharePolicy : IShareAccessPolicy
{
	public bool IsVisible(ShareAccessContext context)
	{
		return true;
	}

	public ShareAccessResult AuthorizeConnect(ShareAccessContext context)
	{
		return ShareAccessResult.Grant();
	}
}
