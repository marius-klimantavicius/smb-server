using System;
using System.Collections.Generic;

namespace Smb.FileSystem.Versioning;

public interface ISnapshotStore
{
	IReadOnlyList<DateTime> GetSnapshots(string path);

	IReadOnlyList<DateTime> GetAllSnapshots();
}
