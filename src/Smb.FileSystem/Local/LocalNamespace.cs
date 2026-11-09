using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Smb.Protocol.Enums;

namespace Smb.FileSystem.Local;

public sealed partial class LocalFileStore
{
    internal IFileHandle OpenStreamBase(string fullPath)
        => CreateCore(Path.GetRelativePath(_root, fullPath), FileAccessIntent.Read, CreateDispositionIntent.Open, false, true, out _).Value;

    private bool HasDefaultStream(string fullPath)
    {
        if (LocalIdentity.Resolve(fullPath) is not { } id) return false;
        lock (_adsLock) return _streams.ContainsKey(id.ObjectId + "\0");
    }

    public override ValueTask<FileStoreResult<FileCreateResult>> CreateAsync(string path, FileAccessIntent access, CreateDispositionIntent disposition, bool directoryRequired, bool nonDirectoryRequired, CancellationToken cancellationToken = default)
    {
        lock (LocalObjects.Gate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!directoryRequired && TryResolve(path, out var full) && HasDefaultStream(full))
                return OpenNamedStreamCore(path, "", access, disposition, cancellationToken);
            return base.CreateAsync(path, access, disposition, directoryRequired, nonDirectoryRequired, cancellationToken);
        }
    }

    private static List<FileIdentity> Descendants(LocalFileHandle directory)
    {
        var result = new List<FileIdentity>();
        // Inspect the acquired parents' identities rather than comparing share-relative names.
        foreach (var obj in LocalObjects.Objects.Values)
            foreach (var handle in obj.Handles)
            {
                for (var path = Path.GetDirectoryName(handle.FullPath); path != null; path = Path.GetDirectoryName(path))
                    if (LocalIdentity.Resolve(path) == directory.Identity)
                    { result.Add(handle.Identity!.Value); break; }
            }
        return result.Distinct().ToList();
    }

    public ValueTask<IReadOnlyList<FileIdentity>> GetOpenDescendantsAsync(IFileHandle directory, CancellationToken cancellationToken = default)
    {
        lock (LocalObjects.Gate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return new((IReadOnlyList<FileIdentity>)Descendants((LocalFileHandle)directory));
        }
    }

    public ValueTask<NtStatus> RenameDirectoryAsync(IFileHandle directory, string newPath, bool replaceIfExists, CancellationToken cancellationToken = default)
    {
        lock (LocalObjects.Gate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Descendants((LocalFileHandle)directory).Count != 0) return new(NtStatus.AccessDenied);
            return new(RenameCore(directory, newPath, replaceIfExists));
        }
    }

    public ValueTask<NtStatus> RenameStreamAsync(IFileHandle source, string newStreamName, bool replaceIfExists, CancellationToken cancellationToken = default)
    {
        lock (LocalObjects.Gate)
        lock (_adsLock)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_readOnly) return new(NtStatus.AccessDenied);
            if (source is not NamedStreamHandle handle) return new(NtStatus.NotSupported);
            if (handle.IsClosed) return new(NtStatus.FileClosed);
            if (handle.DeletePending || handle.BaseHandle.DeletePending) return new((NtStatus)0xc0000056);
            if (!newStreamName.StartsWith(':') || newStreamName.EndsWith(':')) return new(NtStatus.InvalidParameter);
            var parts = newStreamName[1..].Split(':');
            if (parts.Length > 2 || parts[0].Length > 255 || parts[0].IndexOfAny(['\\', '/', '\0']) >= 0 ||
                parts.Length == 2 && parts[1].IndexOfAny(['\\', '/', '\0']) >= 0 || parts is [""])
                return new(NtStatus.InvalidParameter);
            if (parts.Length == 2 && !parts[1].Equals("$DATA", StringComparison.OrdinalIgnoreCase)) return new((NtStatus)0xc0000024);
            var name = parts[0]; var data = handle.Data;
            if (name.Equals(data.Name, StringComparison.OrdinalIgnoreCase)) return new(NtStatus.Success);
            var targetKey = StreamKey(handle.BaseFullPath, name);
            if (_streams.TryGetValue(targetKey, out var target))
            {
                if (!replaceIfExists) return new(NtStatus.ObjectNameCollision);
                if (target.Opens != 0 || target.Content.Length != 0) return new(NtStatus.InvalidParameter);
                // Windows-compatible replacement retains no handles to the replaced stream.
            }
            // Publish the existing data object; every acquired source handle still points to it.
            // For ::$DATA the old native unnamed extent stays pinned to its existing handles.
            foreach (var key in _streams.Where(pair => ReferenceEquals(pair.Value, data)).Select(pair => pair.Key).ToArray()) _streams.Remove(key);
            if (data.Name.Length == 0)
                _streams[StreamKey(handle.BaseFullPath, "")] = new StreamData { Name = "" };
            data.Name = name; _streams[targetKey] = data;
            return new(NtStatus.Success);
        }
    }
}
