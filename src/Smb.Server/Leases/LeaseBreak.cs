using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server.State;

namespace Smb.Server.Leases;

public readonly record struct LeaseBreak(LeaseKey Key, LeaseState FromState, LeaseState ToState, ushort Epoch, SmbOpen Holder);
