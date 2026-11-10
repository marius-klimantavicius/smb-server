using Smb.Auth;
using Smb.Crypto;

namespace Smb.Server.State;

public sealed class ChannelBindInProgress
{
    public required ISpnegoServerContext AuthContext { get; init; }

    public PreauthIntegrityHash? PreauthHash { get; init; }
}
