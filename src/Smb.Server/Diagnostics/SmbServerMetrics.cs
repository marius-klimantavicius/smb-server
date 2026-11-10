using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;
using Smb.Protocol.Enums;

namespace Smb.Server.Diagnostics;

public class SmbServerMetrics
{
    private long _connectionsAccepted;

    private long _authSuccess;

    private long _authFailure;

    private long _requestCount;

    private long _bytesRead;

    private long _bytesWritten;

    private long _lockContention;

    private long _oplockBreaksSent;

    private long _oplockBreakTimeouts;

    private long _activeConnections;

    private long _activeSessions;

    private long _activeTreeConnects;

    private long _openHandles;

    private long _pendingBreaks;

    private readonly ConcurrentDictionary<string, long[]> _perShareBytes = new ConcurrentDictionary<string, long[]>(StringComparer.OrdinalIgnoreCase);

    private readonly LatencyHistogram _latency = new LatencyHistogram();

    public long ConnectionsAccepted => Interlocked.Read(in _connectionsAccepted);

    public long AuthenticationSuccesses => Interlocked.Read(in _authSuccess);

    public long AuthenticationFailures => Interlocked.Read(in _authFailure);

    public long RequestCount => Interlocked.Read(in _requestCount);

    public long BytesRead => Interlocked.Read(in _bytesRead);

    public long BytesWritten => Interlocked.Read(in _bytesWritten);

    public long LockContentionCount => Interlocked.Read(in _lockContention);

    public long OplockBreaksSent => Interlocked.Read(in _oplockBreaksSent);

    public long OplockBreakTimeouts => Interlocked.Read(in _oplockBreakTimeouts);

    public long ActiveConnections => Interlocked.Read(in _activeConnections);

    public long ActiveSessions => Interlocked.Read(in _activeSessions);

    public long ActiveTreeConnects => Interlocked.Read(in _activeTreeConnects);

    public long OpenHandles => Interlocked.Read(in _openHandles);

    public long PendingBreaks => Interlocked.Read(in _pendingBreaks);

    public virtual void OnConnectionAccepted()
    {
        Interlocked.Increment(ref _connectionsAccepted);
        Interlocked.Increment(ref _activeConnections);
    }

    public virtual void OnConnectionClosed()
    {
        Interlocked.Decrement(ref _activeConnections);
    }

    public virtual void OnAuthenticationSucceeded()
    {
        Interlocked.Increment(ref _authSuccess);
        Interlocked.Increment(ref _activeSessions);
    }

    public virtual void OnAuthenticationFailed()
    {
        Interlocked.Increment(ref _authFailure);
    }

    public virtual void OnSessionClosed()
    {
        Interlocked.Decrement(ref _activeSessions);
    }

    public virtual void OnTreeConnected()
    {
        Interlocked.Increment(ref _activeTreeConnects);
    }

    public virtual void OnTreeDisconnected()
    {
        Interlocked.Decrement(ref _activeTreeConnects);
    }

    public virtual void OnHandleOpened()
    {
        Interlocked.Increment(ref _openHandles);
    }

    public virtual void OnHandleClosed()
    {
        Interlocked.Decrement(ref _openHandles);
    }

    public virtual void OnLockContention()
    {
        Interlocked.Increment(ref _lockContention);
    }

    public virtual void OnOplockBreakSent()
    {
        Interlocked.Increment(ref _oplockBreaksSent);
        Interlocked.Increment(ref _pendingBreaks);
    }

    public virtual void OnOplockBreakResolved(bool timedOut)
    {
        Interlocked.Decrement(ref _pendingBreaks);
        if (timedOut)
        {
            Interlocked.Increment(ref _oplockBreakTimeouts);
        }
    }

    public virtual void OnRequestCompleted(double milliseconds)
    {
        Interlocked.Increment(ref _requestCount);
        _latency.Record(milliseconds);
    }

    public virtual ISmbCommandTrace? BeginCommand(SmbCommand command)
    {
        return null;
    }

    public virtual void OnBytesRead(string share, long count)
    {
        Interlocked.Add(ref _bytesRead, count);
        Interlocked.Add(ref PerShare(share)[0], count);
    }

    public virtual void OnBytesWritten(string share, long count)
    {
        Interlocked.Add(ref _bytesWritten, count);
        Interlocked.Add(ref PerShare(share)[1], count);
    }

    public (long Read, long Written) BytesForShare(string share)
    {
        if (!_perShareBytes.TryGetValue(share, out var value))
        {
            return (Read: 0L, Written: 0L);
        }

        return (Read: Interlocked.Read(in value[0]), Written: Interlocked.Read(in value[1]));
    }

    private long[] PerShare(string share)
    {
        return _perShareBytes.GetOrAdd(share, _ => new long[2]);
    }

    public MetricsSnapshot Snapshot()
    {
        var bytesPerShare = _perShareBytes.ToArray().ToDictionary(kv => kv.Key, kv => (Interlocked.Read(in kv.Value[0]), Interlocked.Read(in kv.Value[1])));
        var (requestLatencyP50Ms, requestLatencyP95Ms, requestLatencyP99Ms) = _latency.Percentiles();
        return new MetricsSnapshot
        {
            ConnectionsAccepted = ConnectionsAccepted,
            ActiveConnections = ActiveConnections,
            ActiveSessions = ActiveSessions,
            ActiveTreeConnects = ActiveTreeConnects,
            OpenHandles = OpenHandles,
            AuthenticationSuccesses = AuthenticationSuccesses,
            AuthenticationFailures = AuthenticationFailures,
            RequestCount = RequestCount,
            BytesRead = BytesRead,
            BytesWritten = BytesWritten,
            LockContentionCount = LockContentionCount,
            OplockBreaksSent = OplockBreaksSent,
            OplockBreakTimeouts = OplockBreakTimeouts,
            PendingBreaks = PendingBreaks,
            RequestLatencyP50Ms = requestLatencyP50Ms,
            RequestLatencyP95Ms = requestLatencyP95Ms,
            RequestLatencyP99Ms = requestLatencyP99Ms,
            BytesPerShare = bytesPerShare,
        };
    }
}
