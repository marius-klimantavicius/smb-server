using System.Collections.Generic;

namespace Smb.Server.Dfs;

public sealed class DfsReferralResult
{
    public required string ConsumedPath { get; init; }

    public required IReadOnlyList<DfsTarget> Targets { get; init; }

    public uint TimeToLiveSeconds { get; init; } = 300u;

    public bool IsRootReferral { get; init; }
}
