using System;
using System.Collections.Generic;

namespace Smb.Server.Notification;

public sealed class NullDirectoryWatcher : IDirectoryWatcher
{
	public IDisposable? Watch(string directoryFullPath, bool watchSubtree, ChangeNotifyFilter filter, Action<IReadOnlyList<FileNotifyEvent>> onChanges)
	{
		return null;
	}
}
