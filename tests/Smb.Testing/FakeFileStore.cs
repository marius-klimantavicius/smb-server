using System.Collections.Concurrent;
using System.IO.Enumeration;
using Smb.FileSystem;
using Smb.Protocol.Enums;

namespace Smb.Testing;

// In-memory ordinary I/O fixture. No access to host paths, shares or original package DLLs.
public sealed class FakeFileStore : IFileStore
{
    internal sealed class Node(string path, bool directory, byte[] data)
    {
        internal readonly object Gate = new object();
        internal string Path = path;
        internal readonly bool Directory = directory;
        internal byte[] Data = data;
        internal bool Delete;
    }
    private readonly ConcurrentDictionary<string, Node> _nodes = new ConcurrentDictionary<string, Node>(StringComparer.Ordinal);
    private readonly ConcurrentBag<FakeFileHandle> _handles = new ConcurrentBag<FakeFileHandle>();
    public OperationControl Control { get; } = new OperationControl();
    public int MaxWriteCount { get; set; } = int.MaxValue;
    public IReadOnlyList<FakeFileHandle> Handles => _handles.ToArray();
    public int ActiveHandles => _handles.Count(h => !h.IsDisposed);
    public FakeFileStore() => Seed("", [], true);
    public void Seed(string path, byte[] data, bool directory = false) => _nodes[path] = new Node(path, directory, data.ToArray());
    public byte[] Contents(string path) { var n = _nodes[path]; lock (n.Gate) return n.Data.ToArray(); }
    public async ValueTask<FileStoreResult<FileCreateResult>> CreateAsync(string path, FileAccessIntent access, CreateDispositionIntent disposition, bool directoryRequired, bool nonDirectoryRequired, CancellationToken cancellationToken = default)
    {
        var fault = await Control.BeforeAsync("Create", cancellationToken);
        if (fault is { } status) return FileStoreResult<FileCreateResult>.Fail(status);
        var exists = _nodes.TryGetValue(path, out var node);
        if (!exists && disposition is CreateDispositionIntent.Open or CreateDispositionIntent.Overwrite)
            return FileStoreResult<FileCreateResult>.Fail(NtStatus.ObjectNameNotFound);
        if (exists && disposition == CreateDispositionIntent.Create)
            return FileStoreResult<FileCreateResult>.Fail(NtStatus.ObjectNameCollision);
        node ??= _nodes.GetOrAdd(path, p => new Node(p, directoryRequired, []));
        if ((directoryRequired && !node.Directory) || (nonDirectoryRequired && node.Directory))
            return FileStoreResult<FileCreateResult>.Fail(NtStatus.InvalidParameter);
        if (exists && disposition is CreateDispositionIntent.Overwrite or CreateDispositionIntent.OverwriteIf or CreateDispositionIntent.Supersede)
            lock (node.Gate) node.Data = [];
        var handle = new FakeFileHandle(node, Control);
        _handles.Add(handle);
        return FileStoreResult<FileCreateResult>.Ok(new FileCreateResult(handle, exists ? CreateOutcome.Opened : CreateOutcome.Created));
    }
    public async ValueTask<FileStoreResult<int>> ReadAsync(IFileHandle handle, long offset, Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var fault = await Control.BeforeAsync("Read", cancellationToken);
        if (fault is { } status) return FileStoreResult<int>.Fail(status);
        var n = Get(handle);
        lock (n.Gate)
        {
            if (offset < 0) return FileStoreResult<int>.Fail(NtStatus.InvalidParameter);
            var count = (int)Math.Min(buffer.Length, Math.Max(0, n.Data.LongLength - offset));
            if (count > 0) n.Data.AsMemory((int)offset, count).CopyTo(buffer);
            return FileStoreResult<int>.Ok(count);
        }
    }
    public async ValueTask<FileStoreResult<int>> WriteAsync(IFileHandle handle, long offset, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
    {
        var fault = await Control.BeforeAsync("Write", cancellationToken);
        if (fault is { } status) return FileStoreResult<int>.Fail(status);
        var n = Get(handle);
        data = data[..Math.Min(data.Length, MaxWriteCount)];
        lock (n.Gate)
        {
            if (offset < 0 || offset + data.Length > 16 * 1024 * 1024) return FileStoreResult<int>.Fail(NtStatus.InvalidParameter);
            if (offset + data.Length > n.Data.Length) Array.Resize(ref n.Data, checked((int)offset + data.Length));
            data.CopyTo(n.Data.AsMemory((int)offset));
            return FileStoreResult<int>.Ok(data.Length);
        }
    }
    public async ValueTask<FileStoreResult<IReadOnlyList<FileEntryInfo>>> QueryDirectoryAsync(IFileHandle handle, string searchPattern, CancellationToken cancellationToken = default)
    {
        var fault = await Control.BeforeAsync("QueryDirectory", cancellationToken);
        if (fault is { } status) return FileStoreResult<IReadOnlyList<FileEntryInfo>>.Fail(status);
        var n = Get(handle);
        var prefix = n.Path.Length == 0 ? "" : n.Path + "\\";
        return FileStoreResult<IReadOnlyList<FileEntryInfo>>.Ok(_nodes.Values
            .Where(x => x.Path.StartsWith(prefix, StringComparison.Ordinal) && x.Path.Length > prefix.Length)
            .Where(x => !x.Path.AsSpan(prefix.Length).Contains('\\'))
            .Where(x => FileSystemName.MatchesSimpleExpression(searchPattern.AsSpan(), x.Path.AsSpan(prefix.Length)))
            .OrderBy(x => x.Path, StringComparer.Ordinal).Select(x => Info(x, x.Path[prefix.Length..])).ToArray());
    }
    public async ValueTask<NtStatus> SetEndOfFileAsync(IFileHandle handle, long length, CancellationToken cancellationToken = default)
    {
        var fault = await Control.BeforeAsync("SetEndOfFile", cancellationToken);
        if (fault is { } status) return status;
        var n = Get(handle);
        if (length < 0 || length > 16 * 1024 * 1024) return NtStatus.InvalidParameter;
        lock (n.Gate) Array.Resize(ref n.Data, (int)length);
        return NtStatus.Success;
    }
    public async ValueTask<NtStatus> RenameAsync(IFileHandle handle, string newPath, bool replaceIfExists, CancellationToken cancellationToken = default)
    {
        var fault = await Control.BeforeAsync("Rename", cancellationToken);
        if (fault is { } status) return status;
        var n = Get(handle);
        if (!replaceIfExists && _nodes.ContainsKey(newPath)) return NtStatus.ObjectNameCollision;
        _nodes.TryRemove(n.Path, out _); n.Path = newPath; _nodes[newPath] = n;
        return NtStatus.Success;
    }
    public async ValueTask<NtStatus> SetDeleteOnCloseAsync(IFileHandle handle, bool delete, CancellationToken cancellationToken = default)
    {
        var fault = await Control.BeforeAsync("SetDeleteOnClose", cancellationToken);
        if (fault is { } status) return status;
        Get(handle).Delete = delete;
        return NtStatus.Success;
    }
    public async ValueTask<NtStatus> FlushAsync(IFileHandle handle, CancellationToken cancellationToken = default)
    {
        var fault = await Control.BeforeAsync("Flush", cancellationToken);
        Get(handle); return fault ?? NtStatus.Success;
    }
    public async ValueTask<FileStoreResult<Smb.Protocol.Security.SecurityDescriptor>> GetSecurityAsync(IFileHandle handle, CancellationToken cancellationToken = default)
    {
        await Control.BeforeAsync("GetSecurity", cancellationToken);
        return FileStoreResult<Smb.Protocol.Security.SecurityDescriptor>.Fail(NtStatus.NotSupported);
    }
    private static Node Get(IFileHandle handle)
    {
        var h = (FakeFileHandle)handle;
        ObjectDisposedException.ThrowIf(h.IsDisposed, h);
        return h.Node;
    }
    internal static FileEntryInfo Info(Node n, string name)
    {
        lock (n.Gate) return new FileEntryInfo { Name = name, Attributes = n.Directory ? SmbFileAttributes.Directory : SmbFileAttributes.Normal,
            EndOfFile = n.Data.Length, AllocationSize = n.Data.Length, CreationTime = 132537600000000000, LastWriteTime = 132537600000000000 };
    }
}

public sealed class FakeFileHandle : IFileHandle
{
    internal FakeFileStore.Node Node { get; }
    public OperationControl Control { get; }
    private int _disposed;
    public int DisposeCalls;
    public bool IsDisposed => Volatile.Read(ref _disposed) != 0;
    public string Path => Node.Path;
    public bool IsDirectory => Node.Directory;
    public string PhysicalPath => "/fake/" + Path; // IDirectoryWatcher input only; never touches disk.
    internal FakeFileHandle(FakeFileStore.Node node, OperationControl control) { Node = node; Control = control; }
    public FileEntryInfo GetInfo() => GetInfoAsync().AsTask().GetAwaiter().GetResult();
    public async ValueTask<FileEntryInfo> GetInfoAsync(CancellationToken cancellationToken = default)
    {
        await Control.BeforeAsync("GetInfo", cancellationToken);
        ObjectDisposedException.ThrowIf(IsDisposed, this);
        return FakeFileStore.Info(Node, Path);
    }
    public void Dispose()
    {
        Interlocked.Increment(ref DisposeCalls);
        Interlocked.Exchange(ref _disposed, 1);
    }
    public async ValueTask DisposeAsync()
    {
        await Control.BeforeAsync("Dispose");
        Dispose();
    }
}
