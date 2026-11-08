using System;
using System.Collections.Generic;
using System.Threading;
using Smb.FileSystem;

namespace Smb.Server.Sharing;

public sealed class InMemoryShareModeManager : IShareModeManager
{
	private readonly record struct Entry(object Owner, FileAccessIntent Access, FileShareMode Share);

	private readonly Lock _gate = new Lock();

	private readonly Dictionary<string, List<Entry>> _files = new Dictionary<string, List<Entry>>(StringComparer.Ordinal);

	public int ReservationCount
	{
		get
		{
			lock (_gate)
			{
				var count = 0;
				foreach (var entries in _files.Values) count += entries.Count;
				return count;
			}
		}
	}

	public bool TryOpen(string fileKey, object owner, FileAccessIntent access, FileShareMode share)
	{
		lock (_gate)
		{
			if (!_files.TryGetValue(fileKey, out var value))
			{
				value = (_files[fileKey] = new List<Entry>());
			}
			else
			{
				foreach (var item in value)
				{
					if (!Compatible(access, item.Share) || !Compatible(item.Access, share))
					{
						return false;
					}
				}
			}

			value.Add(new Entry(owner, access, share));
			return true;
		}
	}

	public void Close(string fileKey, object owner)
	{
		lock (_gate)
		{
			if (_files.TryGetValue(fileKey, out var value))
			{
				value.RemoveAll(e => e.Owner == owner);
				if (value.Count == 0)
				{
					_files.Remove(fileKey);
				}
			}
		}
	}

	private static bool Compatible(FileAccessIntent access, FileShareMode share)
	{
		if ((!access.HasFlag(FileAccessIntent.Read) || share.HasFlag(FileShareMode.Read)) && (!access.HasFlag(FileAccessIntent.Write) || share.HasFlag(FileShareMode.Write)))
		{
			if (access.HasFlag(FileAccessIntent.Delete))
			{
				return share.HasFlag(FileShareMode.Delete);
			}

			return true;
		}

		return false;
	}
}
