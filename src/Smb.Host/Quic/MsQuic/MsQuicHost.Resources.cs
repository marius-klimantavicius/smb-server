using System;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Threading;

namespace Managed.Transport.Hosting;

public sealed unsafe partial class MsQuicHost
{
    private static readonly ConcurrentDictionary<nint, MsQuicHost> _contexts = new ConcurrentDictionary<IntPtr, MsQuicHost>();
    private static long _nextToken;
    private readonly ConcurrentDictionary<nint, IDisposable> _resources = new ConcurrentDictionary<IntPtr, IDisposable>();
    private readonly Lock _resourceGate = new Lock();
    private nint _contextToken;
    private int _resourcesClosed;

    internal void* ContextPointer => (void*)_contextToken;
    internal int OutstandingResources => _resources.Count;

    // Shared by the production constructor and compile-linked isolated service tests.
    private void InitializeResources()
    {
        if (_contextToken != 0)
            FatalInvariant("Host context initialized twice.");

        _contextToken = NewToken();
        if (!_contexts.TryAdd(_contextToken, this))
            FatalInvariant("Duplicate host context token.");
    }

    private static nint NewToken()
    {
        var value = Interlocked.Increment(ref _nextToken);
        if (IntPtr.Size != 8 || value <= 0)
            FatalInvariant("Host token identity space exhausted or unsupported pointer width.");

        return (nint)value;
    }

    private static MsQuicHost FromContext(void* context)
    {
        MsQuicHost? host = null;
        if (context == null || !_contexts.TryGetValue((nint)context, out host))
            FatalInvariant("Unknown or retired host context.");

        return host!;
    }

    private void* AddResource<T>(T owner) where T : class, IDisposable
    {
        ArgumentNullException.ThrowIfNull(owner);
        lock (_resourceGate)
        {
            if (_resourcesClosed != 0)
                throw new ObjectDisposedException(nameof(MsQuicHost));

            var token = NewToken();
            if (!_resources.TryAdd(token, owner))
                FatalInvariant("Duplicate resource token.");

            return (void*)token;
        }
    }

    private T Resource<T>(void* token) where T : class, IDisposable
    {
        IDisposable? owner = null;
        if (token == null || !_resources.TryGetValue((nint)token, out owner) || owner is not T)
            FatalInvariant("Unknown, retired, foreign-host, or incorrectly typed resource token: " + typeof(T).Name);

        return (T)owner!;
    }

    private void ReleaseResource<T>(void* token) where T : class, IDisposable
    {
        // Do not remove a different resource type when diagnosing a bad callback.
        var owner = Resource<T>(token);
        if (!_resources.TryRemove(new System.Collections.Generic.KeyValuePair<nint, IDisposable>((nint)token, owner)))
            FatalInvariant("Resource released concurrently more than once: " + typeof(T).Name);

        owner.Dispose();
    }

    // Core shutdown must first quiesce producers and release their resources.
    // Keeping the context rooted on failure prevents a late callback from observing
    // reclaimed managed state; the owner can finish draining and retry disposal.
    private void ReleaseContext()
    {
        lock (_resourceGate)
        {
            if (!_resources.IsEmpty)
                throw new InvalidOperationException("Host resources must drain before releasing the context.");

            _resourcesClosed = 1;
            if (_contextToken == 0)
                return;

            if (!_contexts.TryRemove(_contextToken, out var owner) || !ReferenceEquals(owner, this))
                FatalInvariant("Host context released inconsistently.");

            _contextToken = 0;
        }
    }

    [DoesNotReturn]
    private static void FatalInvariant(string message)
    {
        Environment.FailFast("MsQuic managed host invariant: " + message);
        throw new InvalidOperationException(message);
    }
}