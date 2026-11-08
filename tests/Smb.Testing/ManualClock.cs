namespace Smb.Testing;

// Deterministic TimeProvider usable by Task.Delay(..., provider, token). Callbacks run outside the gate.
public sealed class ManualClock : TimeProvider
{
    private readonly object _gate = new object();
    private readonly List<Timer> _timers = [];
    private DateTimeOffset _now = new DateTimeOffset(2026, 11, 7, 0, 0, 0, TimeSpan.Zero);
    private long _ticks;
    public override DateTimeOffset GetUtcNow() { lock (_gate) return _now; }
    public override long GetTimestamp() { lock (_gate) return _ticks; }
    public override long TimestampFrequency => TimeSpan.TicksPerSecond;
    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        lock (_gate)
        {
            var timer = new Timer(this, callback, state);
            _timers.Add(timer); timer.Change(dueTime, period); return timer;
        }
    }
    public int ActiveTimers { get { lock (_gate) return _timers.Count; } }
    public void Advance(TimeSpan amount)
    {
        if (amount < TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(amount));
        List<Timer> due;
        lock (_gate)
        {
            _now += amount; _ticks += amount.Ticks;
            due = _timers.Where(t => t.Due <= _ticks).ToList();
            foreach (var timer in due) timer.Due = timer.Period > 0 ? checked(_ticks + timer.Period) : long.MaxValue;
        }
        foreach (var timer in due) timer.Callback(timer.State);
    }
    private sealed class Timer(ManualClock clock, TimerCallback callback, object? state) : ITimer
    {
        internal readonly TimerCallback Callback = callback;
        internal readonly object? State = state;
        internal long Due = long.MaxValue;
        internal long Period;
        private bool _disposed;
        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            if (dueTime < Timeout.InfiniteTimeSpan || period < Timeout.InfiniteTimeSpan) throw new ArgumentOutOfRangeException();
            lock (clock._gate)
            {
                if (_disposed) return false;
                Due = dueTime == Timeout.InfiniteTimeSpan ? long.MaxValue : checked(clock._ticks + dueTime.Ticks);
                Period = period.Ticks; return true;
            }
        }
        public void Dispose() { lock (clock._gate) { _disposed = true; clock._timers.Remove(this); } }
        public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
    }
}
