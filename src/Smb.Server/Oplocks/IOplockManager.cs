using Smb.Protocol.Enums;
using Smb.Server.State;

namespace Smb.Server.Oplocks;

public interface IOplockManager
{
    OplockGrant RequestOplock(SmbOpen open, OplockLevel requested);

    OplockLevel Acknowledge(SmbOpen open, OplockLevel newLevel);

    void ReleaseOwner(SmbOpen open);
}
