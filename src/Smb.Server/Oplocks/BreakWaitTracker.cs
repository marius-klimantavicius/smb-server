using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Smb.Protocol.Messages;
using Smb.Server.Diagnostics;
using Smb.Server.State;

namespace Smb.Server.Oplocks;

internal sealed class BreakWaitTracker
{
    private readonly record struct BreakKey(SmbOpen? Open, LeaseKey Lease)
    {
        public static BreakKey ForOplock(SmbOpen holder)
        {
            return new BreakKey(holder, default);
        }

        public static BreakKey ForLease(LeaseKey key)
        {
            return new BreakKey(null, key);
        }
    }

    private sealed class Entry
    {
        public readonly TaskCompletionSource<BreakOutcome> Completion = new TaskCompletionSource<BreakOutcome>(TaskCreationOptions.RunContinuationsAsynchronously);

        public ITimer? Timer;
    }

    private readonly TimeProvider _time;

    private readonly TimeSpan _timeout;

    private readonly SmbServerMetrics _metrics;

    private readonly Lock _gate = new Lock();

    private readonly Dictionary<BreakKey, Entry> _pending = new Dictionary<BreakKey, Entry>();

    public BreakWaitTracker(TimeProvider time, TimeSpan timeout, SmbServerMetrics metrics)
    {
        _time = time;
        _timeout = timeout;
        _metrics = metrics;
    }

    public Task<BreakOutcome> RegisterOplockBreak(SmbOpen holder)
    {
        return Register(BreakKey.ForOplock(holder));
    }

    public Task<BreakOutcome> RegisterLeaseBreak(LeaseKey key)
    {
        return Register(BreakKey.ForLease(key));
    }

    public void CompleteOplockBreak(SmbOpen holder)
    {
        Complete(BreakKey.ForOplock(holder), BreakOutcome.Acknowledged);
    }

    public void CompleteLeaseBreak(LeaseKey key)
    {
        Complete(BreakKey.ForLease(key), BreakOutcome.Acknowledged);
    }

    private Task<BreakOutcome> Register(BreakKey key)
    {
        var entry = new Entry();
        lock (_gate)
        {
            if (_pending.TryGetValue(key, out var value))
            {
                return value.Completion.Task;
            }

            _pending[key] = entry;
            _metrics.OnOplockBreakSent();
            entry.Timer = _time.CreateTimer(state =>
            {
                var (breakWaitTracker, key2) = ((BreakWaitTracker, BreakKey))state!;
                breakWaitTracker.Complete(key2, BreakOutcome.TimedOut);
            }, (this, key), _timeout, Timeout.InfiniteTimeSpan);
        }

        return entry.Completion.Task;
    }

    private void Complete(BreakKey key, BreakOutcome outcome)
    {
        Entry value;
        lock (_gate)
        {
            if (!_pending.Remove(key, out value))
            {
                return;
            }
        }

        value.Timer?.Dispose();
        _metrics.OnOplockBreakResolved(outcome == BreakOutcome.TimedOut);
        value.Completion.TrySetResult(outcome);
    }
}
