using System;
using System.Collections.Generic;
using System.Threading;
using Smb.FileSystem;
using Smb.Server.State;

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
			if (owner is SmbOpen candidate && (candidate.LocalOpen?.Identity ?? candidate.AdmissionIdentity) is { } identity && access != FileAccessIntent.None)
				foreach (var entries in _files.Values)
					foreach (var entry in entries)
						if (!ReferenceEquals(entry.Owner, owner) && entry.Access != FileAccessIntent.None && entry.Owner is SmbOpen existing &&
							(existing.LocalOpen?.Identity ?? existing.AdmissionIdentity) is { } other && other.ObjectId == identity.ObjectId && other.StreamId != identity.StreamId &&
							((candidate.LocalOpen?.IsDefaultStream ?? identity.StreamId.Length == 0) && access.HasFlag(FileAccessIntent.Delete) && !entry.Share.HasFlag(FileShareMode.Delete) ||
							 (existing.LocalOpen?.IsDefaultStream ?? other.StreamId.Length == 0) && entry.Access.HasFlag(FileAccessIntent.Delete) && !share.HasFlag(FileShareMode.Delete)))
							return false;

			if (!_files.TryGetValue(fileKey, out var value))
			{
				value = (_files[fileKey] = new List<Entry>());
			}
			else
			{
				foreach (var item in value)
				{
					if (access != FileAccessIntent.None && item.Access != FileAccessIntent.None &&
						(!Compatible(access, item.Share) || !Compatible(item.Access, share)))
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
