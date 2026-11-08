using Smb.Server.Notification;

namespace Smb.Testing;

public sealed class FakeWatcher : IDirectoryWatcher
{
    public sealed class Subscription(string path, bool subtree, ChangeNotifyFilter filter, Action<IReadOnlyList<FileNotifyEvent>> callback) : IDisposable
    {
        private int _disposed;
        public string Path { get; } = path;
        public bool Subtree { get; } = subtree;
        public ChangeNotifyFilter Filter { get; } = filter;
        public bool IsDisposed => Volatile.Read(ref _disposed) != 0;
        public int DisposeCalls;
        public Action<Smb.Protocol.Enums.NtStatus>? Error;
        public void Fail(Smb.Protocol.Enums.NtStatus status) { if (!IsDisposed) Error?.Invoke(status); }
        public void Emit(params FileNotifyEvent[] changes) { if (!IsDisposed) callback(changes); }
        public void Dispose() { Interlocked.Increment(ref DisposeCalls); Interlocked.Exchange(ref _disposed, 1); }
    }
    private readonly List<Subscription> _subscriptions = [];
    public Action<Subscription>? OnWatch { get; set; } // May synchronously fire inside Watch for registration races.
    public Subscription[] Subscriptions { get { lock (_subscriptions) return _subscriptions.ToArray(); } }
    public int ActiveCount => Subscriptions.Count(s => !s.IsDisposed);
    public IDisposable Watch(string directoryFullPath, bool watchSubtree, ChangeNotifyFilter filter, Action<IReadOnlyList<FileNotifyEvent>> onChanges)
    {
        var s = new Subscription(directoryFullPath, watchSubtree, filter, onChanges);
        lock (_subscriptions) _subscriptions.Add(s);
        OnWatch?.Invoke(s);
        return s;
    }
    public IDisposable Watch(string path, bool subtree, ChangeNotifyFilter filter, Action<IReadOnlyList<FileNotifyEvent>> changes, Action<Smb.Protocol.Enums.NtStatus> error)
    {
        var s = (Subscription)Watch(path, subtree, filter, changes); s.Error = error; return s;
    }
    // Current production IDirectoryWatcher has no error/overflow callback. P4 must decide that API.
}
