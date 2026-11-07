using System;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("ProviderVectors")]

namespace Managed.Security;

// Deterministic ownership failure tests. Production leaves current null; no
// public injection API, process-global state, or allocator replacement exists.
internal static class ProviderFaultInjection
{
    [ThreadStatic] private static FailureScope? _current;
    internal static FailureScope FailAllocation(int ordinal) => new FailureScope(ordinal);

    internal static void BeforeAllocation()
    {
        if (_current is { } scope && ++scope.AllocationsAttempted == scope.Ordinal)
        {
            var error = new OutOfMemoryException("Injected provider allocation failure.");
            scope.InjectedFailure = error;
            throw error;
        }
    }

    internal static void StateDisposed()
    {
        if (_current is { } scope)
            scope.DisposedStates++;
    }

    internal static void HashCloneFailed()
    {
        if (_current is { } scope)
            scope.FailedHashClones++;
    }

    internal sealed class FailureScope : IDisposable
    {
        private readonly FailureScope? _parent;
        private readonly int _thread = Environment.CurrentManagedThreadId;
        private bool _disposed;

        internal readonly int Ordinal;
        internal int AllocationsAttempted, DisposedStates, FailedHashClones;
        internal OutOfMemoryException? InjectedFailure;

        internal FailureScope(int ordinal)
        {
            if (ordinal <= 0)
                throw new ArgumentOutOfRangeException(nameof(ordinal));

            Ordinal = ordinal;
            _parent = _current;
            _current = this;
        }

        public void Dispose()
        {
            if (_disposed) return;

            if (_thread != Environment.CurrentManagedThreadId || _current != this)
                throw new InvalidOperationException("Provider fault scopes require stack-order disposal on their creating thread.");

            _current = _parent;
            _disposed = true;
        }
    }
}