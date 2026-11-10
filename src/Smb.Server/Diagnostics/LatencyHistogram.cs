using System;
using System.Threading;

namespace Smb.Server.Diagnostics;

internal sealed class LatencyHistogram
{
    private static readonly double[] Bounds =
    [
        1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0,
        2500.0, 5000.0,
    ];

    private readonly long[] _buckets = new long[Bounds.Length + 1];

    public void Record(double milliseconds)
    {
        int i;
        for (i = 0; i < Bounds.Length && milliseconds > Bounds[i]; i++)
        {
        }

        Interlocked.Increment(ref _buckets[i]);
    }

    public (double P50, double P95, double P99) Percentiles()
    {
        return (P50: Percentile(0.5), P95: Percentile(0.95), P99: Percentile(0.99));
    }

    private double Percentile(double q)
    {
        var num = 0L;
        for (var i = 0; i < _buckets.Length; i++)
        {
            num += Interlocked.Read(in _buckets[i]);
        }

        if (num == 0L)
        {
            return 0.0;
        }

        var num2 = (long)Math.Ceiling(q * num);
        var num3 = 0L;
        for (var j = 0; j < _buckets.Length; j++)
        {
            num3 += Interlocked.Read(in _buckets[j]);
            if (num3 >= num2)
            {
                if (j >= Bounds.Length)
                {
                    return double.PositiveInfinity;
                }

                return Bounds[j];
            }
        }

        return double.PositiveInfinity;
    }
}
