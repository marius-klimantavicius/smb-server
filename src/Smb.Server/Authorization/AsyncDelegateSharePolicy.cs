using System;
using System.Threading.Tasks;

namespace Smb.Server.Authorization;

public sealed class AsyncDelegateSharePolicy : IShareAccessPolicy
{
	private readonly Func<ShareAccessContext, ValueTask<ShareAccessResult>> _authorize;

	private readonly Func<ShareAccessContext, ValueTask<bool>> _isVisible;

	public AsyncDelegateSharePolicy(Func<ShareAccessContext, ValueTask<ShareAccessResult>> authorizeConnect, Func<ShareAccessContext, ValueTask<bool>>? isVisible = null)
	{
		_authorize = authorizeConnect ?? throw new ArgumentNullException(nameof(authorizeConnect));
		_isVisible = isVisible ?? (_ => new ValueTask<bool>(result: true));
	}

	public ValueTask<ShareAccessResult> AuthorizeConnectAsync(ShareAccessContext context)
	{
		return _authorize(context);
	}

	public ValueTask<bool> IsVisibleAsync(ShareAccessContext context)
	{
		return _isVisible(context);
	}

	public ShareAccessResult AuthorizeConnect(ShareAccessContext context)
	{
		return _authorize(context).AsTask().GetAwaiter().GetResult();
	}

	public bool IsVisible(ShareAccessContext context)
	{
		return _isVisible(context).AsTask().GetAwaiter().GetResult();
	}
}
