namespace Smb.Testing;

public static class Check
{
    public static void That(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
    public static void Equal<T>(T expected, T actual, string message) where T : notnull =>
        That(EqualityComparer<T>.Default.Equals(expected, actual), $"{message}: expected {expected}, actual {actual}");
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);
}

// One-shot rendezvous. All waits are bounded; cancellation/release cannot inline continuations.
public sealed class AsyncBarrier
{
    private readonly TaskCompletionSource _entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _released = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    public Task Entered => _entered.Task.WaitAsync(Check.Timeout);
    public bool IsReleased => _released.Task.IsCompleted;
    public async ValueTask WaitAsync(CancellationToken cancellationToken = default)
    {
        _entered.TrySetResult();
        await _released.Task.WaitAsync(Check.Timeout, cancellationToken);
    }
    public void Release() => _released.TrySetResult();
}
