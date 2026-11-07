using System;
using System.Collections.Generic;
using System.Threading;
using Smb.Protocol.Enums;
using Smb.Server.State;

namespace Smb.Server.Oplocks;

public sealed class InMemoryOplockManager : IOplockManager
{
	private sealed class Holder(SmbOpen open, OplockLevel level)
	{
		public SmbOpen Open { get; } = open;

		public OplockLevel Level { get; set; } = level;
	}

	private sealed class FileOplockState
	{
		public List<Holder> Holders { get; } = new List<Holder>();
	}

	private readonly Lock _gate = new Lock();

	private readonly Dictionary<string, FileOplockState> _files = new Dictionary<string, FileOplockState>(StringComparer.OrdinalIgnoreCase);

	public OplockGrant RequestOplock(SmbOpen open, OplockLevel requested)
	{
		if (requested != OplockLevel.LevelII && requested - 8 > OplockLevel.LevelII)
		{
			return OplockGrant.None;
		}

		var key = FileKey(open);
		lock (_gate)
		{
			var orAdd = GetOrAdd(key);
			if (orAdd.Holders.Count == 0)
			{
				orAdd.Holders.Add(new Holder(open, requested));
				return new OplockGrant(requested, Array.Empty<OplockBreak>());
			}

			var list = new List<OplockBreak>();
			foreach (var holder in orAdd.Holders)
			{
				var level = holder.Level;
				if (level - 8 <= OplockLevel.LevelII)
				{
					holder.Level = OplockLevel.LevelII;
					list.Add(new OplockBreak(holder.Open, OplockLevel.LevelII));
				}
			}

			orAdd.Holders.Add(new Holder(open, OplockLevel.LevelII));
			return new OplockGrant(OplockLevel.LevelII, list);
		}
	}

	public OplockLevel Acknowledge(SmbOpen open, OplockLevel newLevel)
	{
		lock (_gate)
		{
			if (!_files.TryGetValue(FileKey(open), out var value))
			{
				return OplockLevel.None;
			}

			foreach (var holder in value.Holders)
			{
				if (holder.Open == open)
				{
					holder.Level = newLevel;
					return holder.Level;
				}
			}

			return OplockLevel.None;
		}
	}

	public void ReleaseOwner(SmbOpen open)
	{
		var key = FileKey(open);
		lock (_gate)
		{
			if (_files.TryGetValue(key, out var value))
			{
				value.Holders.RemoveAll(h => h.Open == open);
				if (value.Holders.Count == 0)
				{
					_files.Remove(key);
				}
			}
		}
	}

	private FileOplockState GetOrAdd(string key)
	{
		if (!_files.TryGetValue(key, out var value))
		{
			value = (_files[key] = new FileOplockState());
		}

		return value;
	}

	private static string FileKey(SmbOpen open)
	{
		return open.LocalOpen?.PhysicalPath ?? open.PathName;
	}
}
