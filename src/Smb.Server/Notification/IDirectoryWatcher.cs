using System;
using System.Collections.Generic;

namespace Smb.Server.Notification;

public interface IDirectoryWatcher
{
	IDisposable? Watch(string directoryFullPath, bool watchSubtree, ChangeNotifyFilter filter, Action<IReadOnlyList<FileNotifyEvent>> onChanges);

	// Existing adapters remain source compatible. Adapters that can lose events must report a rescan/error.
	IDisposable? Watch(string path, bool subtree, ChangeNotifyFilter filter, Action<IReadOnlyList<FileNotifyEvent>> changes, Action<Protocol.Enums.NtStatus> error)
		=> Watch(path, subtree, filter, changes);
}
