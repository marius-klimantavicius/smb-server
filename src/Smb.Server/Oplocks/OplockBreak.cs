using Smb.Protocol.Enums;
using Smb.Server.State;

namespace Smb.Server.Oplocks;

public readonly record struct OplockBreak(SmbOpen Holder, OplockLevel NewLevel);
