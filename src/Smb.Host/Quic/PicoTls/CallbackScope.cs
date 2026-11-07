using System;
using System.Runtime.ExceptionServices;

namespace Managed.Security;

/// <summary>Required scope around each translated picotls entry that can invoke
/// provider callbacks. Call ThrowIfFailed before returning any resulting bytes.
/// Nested scopes propagate their first failure to the parent when disposed.</summary>
public sealed class CallbackScope : IDisposable
{
    [ThreadStatic] private static CallbackScope? current;
    [ThreadStatic] private static ExceptionDispatchInfo? orphanFailure;
    private readonly CallbackScope? parent;
    private readonly int threadId = Environment.CurrentManagedThreadId;
    private ExceptionDispatchInfo? failure;
    private bool disposed;

    private CallbackScope()
    {
        parent = current;
        current = this;
        // An unscoped raw call must not silently poison or escape a later scope.
        // Carry its recorded error into this next explicit boundary.
        failure = parent?.failure ?? orphanFailure;
        orphanFailure = null;
    }
    public static CallbackScope Enter() => new();
    public static bool HasFailure => current?.failure != null || orphanFailure != null;
    public static void RequireActive()
    {
        if (current == null) throw new InvalidOperationException("BCL picotls callbacks require CallbackScope.Enter().");
    }
    public static void Capture(Exception exception)
    {
        var captured = ExceptionDispatchInfo.Capture(exception);
        if (current is { } scope) scope.failure ??= captured;
        else orphanFailure ??= captured;
    }
    /// <summary>Explicitly inspect and consume a failure from unscoped raw calls.
    /// Raw calls without a scope fail before cryptographic operations run.</summary>
    public static void ThrowPendingUnscopedFailure()
    {
        var captured = orphanFailure;
        orphanFailure = null;
        captured?.Throw();
    }
    public void ThrowIfFailed()
    {
        VerifyCurrent();
        failure?.Throw();
    }
    private void VerifyCurrent()
    {
        if (disposed || threadId != Environment.CurrentManagedThreadId || current != this)
            throw new InvalidOperationException("Callback scopes must be used and disposed in stack order on their creating thread.");
    }
    public void Dispose()
    {
        if (disposed) return;
        VerifyCurrent();
        current = parent;
        if (failure != null && parent != null) parent.failure ??= failure;
        disposed = true;
    }
}
