using Smb.Auth;
using Smb.FileSystem;
using Smb.Server.State;

namespace Smb.Server.Authorization;

public sealed class ShareAccessContext
{
	public required SecurityIdentity Identity { get; init; }

	public required IShare Share { get; init; }

	public SmbConnection? Connection { get; init; }

	public string ShareName => Share.Name;
}
