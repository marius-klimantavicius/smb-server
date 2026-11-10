using System;
using System.Collections.Generic;
using System.IO;

namespace Smb.Server.Notification;

public sealed class FileSystemDirectoryWatcher : IDirectoryWatcher
{
    public IDisposable? Watch(string directoryFullPath, bool watchSubtree, ChangeNotifyFilter filter, Action<IReadOnlyList<FileNotifyEvent>> onChanges)
        => Watch(directoryFullPath, watchSubtree, filter, onChanges, _ => { });

    public IDisposable? Watch(string directoryFullPath, bool watchSubtree, ChangeNotifyFilter filter, Action<IReadOnlyList<FileNotifyEvent>> onChanges, Action<Protocol.Enums.NtStatus> onError)
    {
        if (MapFilter(filter) == 0) return Directory.Exists(directoryFullPath) ? new EmptySubscription() : null;

        if (string.IsNullOrEmpty(directoryFullPath) || !Directory.Exists(directoryFullPath))
        {
            return null;
        }

        FileSystemWatcher fileSystemWatcher = null;
        string root;
        try
        {
            root = Path.GetFullPath(directoryFullPath);
            fileSystemWatcher = new FileSystemWatcher(root)
            {
                IncludeSubdirectories = watchSubtree,
                NotifyFilter = MapFilter(filter),
            };
            fileSystemWatcher.Created += (_, e) =>
            {
                Emit(FileNotifyAction.Added, e.FullPath);
            };
            fileSystemWatcher.Deleted += (_, e) =>
            {
                Emit(FileNotifyAction.Removed, e.FullPath);
            };
            fileSystemWatcher.Changed += (_, e) =>
            {
                Emit(FileNotifyAction.Modified, e.FullPath);
            };
            fileSystemWatcher.Renamed += (_, e) =>
            {
                onChanges(
                [
                    new FileNotifyEvent(FileNotifyAction.RenamedOldName, Relative(root, e.OldFullPath)),
                    new FileNotifyEvent(FileNotifyAction.RenamedNewName, Relative(root, e.FullPath)),
                ]);
            };
            fileSystemWatcher.Error += (_, _) => onError(Protocol.Enums.NtStatus.NotifyEnumDir);
            fileSystemWatcher.EnableRaisingEvents = true;
            return fileSystemWatcher;
        }
        catch
        {
            fileSystemWatcher?.Dispose();
            return null;
        }

        void Emit(FileNotifyAction action, string fullPath)
        {
            onChanges([new FileNotifyEvent(action, Relative(root, fullPath))]);
        }
    }

    private sealed class EmptySubscription : IDisposable
    {
        public void Dispose() { }
    }

    private static NotifyFilters MapFilter(ChangeNotifyFilter f)
    {
        var notifyFilters = (NotifyFilters)0;
        if (f.HasFlag(ChangeNotifyFilter.FileName))
        {
            notifyFilters |= NotifyFilters.FileName;
        }

        if (f.HasFlag(ChangeNotifyFilter.DirName))
        {
            notifyFilters |= NotifyFilters.DirectoryName;
        }

        if (f.HasFlag(ChangeNotifyFilter.Attributes))
        {
            notifyFilters |= NotifyFilters.Attributes;
        }

        if (f.HasFlag(ChangeNotifyFilter.Size))
        {
            notifyFilters |= NotifyFilters.Size;
        }

        if (f.HasFlag(ChangeNotifyFilter.LastWrite))
        {
            notifyFilters |= NotifyFilters.LastWrite;
        }

        if (f.HasFlag(ChangeNotifyFilter.LastAccess))
        {
            notifyFilters |= NotifyFilters.LastAccess;
        }

        if (f.HasFlag(ChangeNotifyFilter.Creation))
        {
            notifyFilters |= NotifyFilters.CreationTime;
        }

        if (f.HasFlag(ChangeNotifyFilter.Security))
        {
            notifyFilters |= NotifyFilters.Security;
        }

        if (notifyFilters != 0)
        {
            return notifyFilters;
        }

        return (NotifyFilters)0;
    }

    private static string Relative(string root, string fullPath)
    {
        return Path.GetRelativePath(root, fullPath).Replace('/', '\\');
    }
}
