using System;
using System.Collections.Generic;

namespace Smb.Server.Notification;

public interface IDirectoryWatcher
{
	IDisposable? Watch(string directoryFullPath, bool watchSubtree, ChangeNotifyFilter filter, Action<IReadOnlyList<FileNotifyEvent>> onChanges);
}
