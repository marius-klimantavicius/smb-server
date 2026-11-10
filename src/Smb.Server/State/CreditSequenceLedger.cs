using System;
using System.Collections.Generic;
using System.Threading;

namespace Smb.Server.State;

/// <summary>Per-transport available sequence intervals. Consumed values can never re-enter.</summary>
public sealed class CreditSequenceLedger
{
    private readonly Lock gate = new Lock();
    private readonly List<(ulong First, ulong Last)> available = [(0, 0)];
    private ulong lastGranted;
    private int count = 1;
    public bool Exhausted { get; private set; }

    public int AvailableCount
    {
        get
        {
            lock (gate) return count;
        }
    }

    public bool TryConsume(ulong first, ushort charge)
    {
        ulong width = Math.Max(charge, (ushort)1);
        if (first == ulong.MaxValue || width - 1 >= ulong.MaxValue - first) return false;

        var last = first + width - 1;
        lock (gate)
        {
            for (var i = 0; i < available.Count; i++)
            {
                var r = available[i];
                if (first < r.First) return false;

                if (first > r.Last) continue;

                if (last > r.Last) return false;

                available.RemoveAt(i);
                if (r.First < first) available.Insert(i++, (r.First, first - 1));
                if (last < r.Last) available.Insert(i, (last + 1, r.Last));
                count -= (int)width;
                return true;
            }

            return false;
        }
    }

    /// <summary>Reserve exactly the grant serialized in a response, once, before exposing it to the sender.</summary>
    public ushort Grant(ushort desired)
    {
        lock (gate)
        {
            var requested = Math.Max(desired, count == 0 ? 1 : 0);
            var firstAvailable = available.Count == 0 ? lastGranted + 1 : available[0].First;
            var span = lastGranted + 1 - firstAvailable;
            var grant = (int)Math.Min((ulong)requested, 65536UL - Math.Min(span, 65536UL));
            var remaining = ulong.MaxValue - lastGranted - 1; // all-ones is reserved
            if ((ulong)grant > remaining)
            {
                grant = (int)Math.Min((ulong)grant, remaining);
                Exhausted = true;
            }

            if (grant == 0) return 0;

            var end = lastGranted + (ulong)grant;
            if (available.Count > 0 && available[^1].Last == lastGranted)
                available[^1] = (available[^1].First, end);
            else available.Add((lastGranted + 1, end));
            lastGranted = end;
            count += grant;
            return (ushort)grant;
        }
    }
}
