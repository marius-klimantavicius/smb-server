using System;
using System.Collections.Generic;
using System.Threading;

namespace Smb.Auth.Ldap;

internal sealed class TtlCache<TKey, TValue> where TKey : notnull
{
    private readonly record struct Entry(TValue Value, DateTimeOffset Expiry);

    private readonly Dictionary<TKey, Entry> _map;

    private readonly TimeProvider _clock;

    private readonly TimeSpan _ttl;

    private readonly Lock _gate = new Lock();

    public TtlCache(TimeSpan ttl, TimeProvider clock, IEqualityComparer<TKey>? comparer = null)
    {
        _ttl = ttl;
        _clock = clock;
        _map = new Dictionary<TKey, Entry>(comparer);
    }

    public TValue GetOrAdd(TKey key, Func<TValue> factory)
    {
        if (_ttl <= TimeSpan.Zero)
        {
            return factory();
        }

        var utcNow = _clock.GetUtcNow();
        lock (_gate)
        {
            if (_map.TryGetValue(key, out var value) && value.Expiry > utcNow)
            {
                return value.Value;
            }
        }

        var val = factory();
        lock (_gate)
        {
            _map[key] = new Entry(val, utcNow + _ttl);
            return val;
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            _map.Clear();
        }
    }
}
