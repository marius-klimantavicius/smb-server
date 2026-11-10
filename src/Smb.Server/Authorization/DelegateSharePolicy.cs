using System;

namespace Smb.Server.Authorization;

public sealed class DelegateSharePolicy : IShareAccessPolicy
{
    private readonly Func<ShareAccessContext, bool> _isVisible;

    private readonly Func<ShareAccessContext, ShareAccessResult> _authorize;

    public DelegateSharePolicy(Func<ShareAccessContext, ShareAccessResult> authorize, Func<ShareAccessContext, bool>? isVisible = null)
    {
        _authorize = authorize;
        _isVisible = isVisible ?? (_ => true);
    }

    public bool IsVisible(ShareAccessContext context)
    {
        return _isVisible(context);
    }

    public ShareAccessResult AuthorizeConnect(ShareAccessContext context)
    {
        return _authorize(context);
    }
}
