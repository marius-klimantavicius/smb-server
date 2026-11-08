using System.Collections.Concurrent;
using Smb.Protocol.Enums;

namespace Smb.Testing;

public sealed record OperationStep(AsyncBarrier? Barrier = null, NtStatus? Status = null, Exception? Error = null, bool IgnoreCancellation = false);

// Queue steps before starting an operation. Each step and invocation counter is consumed exactly once.
public sealed class OperationControl
{
    private readonly ConcurrentDictionary<string, ConcurrentQueue<OperationStep>> _steps = new ConcurrentDictionary<string, ConcurrentQueue<OperationStep>>();
    private readonly ConcurrentDictionary<string, int> _counts = new ConcurrentDictionary<string, int>();
    public int Count(string operation) => _counts.GetValueOrDefault(operation);
    public void Enqueue(string operation, OperationStep step) => _steps.GetOrAdd(operation, _ => new ConcurrentQueue<OperationStep>()).Enqueue(step);
    public async ValueTask<NtStatus?> BeforeAsync(string operation, CancellationToken token = default)
    {
        _counts.AddOrUpdate(operation, 1, (_, count) => count + 1);
        token.ThrowIfCancellationRequested();
        if (!_steps.TryGetValue(operation, out var queue) || !queue.TryDequeue(out var step)) return null;
        if (step.Barrier is not null) await step.Barrier.WaitAsync(step.IgnoreCancellation ? default : token);
        if (step.Error is not null) throw step.Error;
        return step.Status;
    }
}
