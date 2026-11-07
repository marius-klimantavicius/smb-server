using System.Collections.Generic;

namespace Smb.Server.Diagnostics;

public sealed record MetricsSnapshot
{
	public long ConnectionsAccepted { get; init; }

	public long ActiveConnections { get; init; }

	public long ActiveSessions { get; init; }

	public long ActiveTreeConnects { get; init; }

	public long OpenHandles { get; init; }

	public long AuthenticationSuccesses { get; init; }

	public long AuthenticationFailures { get; init; }

	public long RequestCount { get; init; }

	public long BytesRead { get; init; }

	public long BytesWritten { get; init; }

	public long LockContentionCount { get; init; }

	public long OplockBreaksSent { get; init; }

	public long OplockBreakTimeouts { get; init; }

	public long PendingBreaks { get; init; }

	public double RequestLatencyP50Ms { get; init; }

	public double RequestLatencyP95Ms { get; init; }

	public double RequestLatencyP99Ms { get; init; }

	public IReadOnlyDictionary<string, (long Read, long Written)> BytesPerShare { get; init; } = new Dictionary<string, (long, long)>();
}
