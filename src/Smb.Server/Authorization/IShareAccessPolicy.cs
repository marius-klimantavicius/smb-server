using System.Threading.Tasks;

namespace Smb.Server.Authorization;

public interface IShareAccessPolicy
{
	bool IsVisible(ShareAccessContext context);

	ShareAccessResult AuthorizeConnect(ShareAccessContext context);

	ValueTask<bool> IsVisibleAsync(ShareAccessContext context)
	{
		return new ValueTask<bool>(IsVisible(context));
	}

	ValueTask<ShareAccessResult> AuthorizeConnectAsync(ShareAccessContext context)
	{
		return new ValueTask<ShareAccessResult>(AuthorizeConnect(context));
	}
}
