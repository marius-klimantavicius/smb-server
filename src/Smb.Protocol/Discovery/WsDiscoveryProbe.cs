using System.Collections.Generic;

namespace Smb.Protocol.Discovery;

public readonly record struct WsDiscoveryProbe(string MessageId, IReadOnlyList<string> Types);
