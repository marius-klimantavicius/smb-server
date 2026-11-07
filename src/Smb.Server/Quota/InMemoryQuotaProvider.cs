using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Security;

namespace Smb.Server.Quota;

public sealed class InMemoryQuotaProvider : IQuotaProvider
{
	private sealed class Record
	{
		public long Used;

		public long Threshold = -1L;

		public long Limit = -1L;

		public long ChangeTime;
	}

	private readonly ConcurrentDictionary<string, Record> _records = new ConcurrentDictionary<string, Record>(StringComparer.Ordinal);

	public bool IsSupported => true;

	public void SetLimit(string shareName, Sid owner, long limit, long threshold = -1L)
	{
		var orAdd = _records.GetOrAdd(Key(shareName, owner), _ => new Record());
		lock (orAdd)
		{
			orAdd.Limit = limit;
			orAdd.Threshold = threshold;
		}
	}

	public IReadOnlyList<FileQuotaInformation> Query(IShare share, IReadOnlyList<Sid> sidFilter)
	{
		var list = new List<FileQuotaInformation>();
		if (sidFilter.Count > 0)
		{
			foreach (var item in sidFilter)
			{
				if (_records.TryGetValue(Key(share.Name, item), out var value))
				{
					list.Add(Snapshot(item, value));
				}
			}

			return list;
		}

		var text = share.Name + "\0";
		foreach (var record in _records)
		{
			if (record.Key.StartsWith(text, StringComparison.Ordinal))
			{
				var sid = Sid.Parse(Convert.FromHexString(record.Key.Substring(text.Length)));
				list.Add(Snapshot(sid, record.Value));
			}
		}

		return list;
	}

	public NtStatus Set(IShare share, IReadOnlyList<FileQuotaInformation> entries)
	{
		foreach (var entry in entries)
		{
			var orAdd = _records.GetOrAdd(Key(share.Name, entry.Sid), _ => new Record());
			lock (orAdd)
			{
				orAdd.Threshold = entry.QuotaThreshold;
				orAdd.Limit = entry.QuotaLimit;
				orAdd.ChangeTime = entry.ChangeTime;
				if (entry.QuotaUsed >= 0)
				{
					orAdd.Used = entry.QuotaUsed;
				}
			}
		}

		return NtStatus.Success;
	}

	public bool TryReserve(IShare share, Sid owner, long additionalBytes)
	{
		if (additionalBytes <= 0)
		{
			return true;
		}

		var orAdd = _records.GetOrAdd(Key(share.Name, owner), _ => new Record());
		lock (orAdd)
		{
			if (orAdd.Limit != -1 && orAdd.Used + additionalBytes > orAdd.Limit)
			{
				return false;
			}

			orAdd.Used += additionalBytes;
			return true;
		}
	}

	public void Release(IShare share, Sid owner, long bytes)
	{
		if (bytes <= 0 || !_records.TryGetValue(Key(share.Name, owner), out var value))
		{
			return;
		}

		lock (value)
		{
			value.Used = Math.Max(0L, value.Used - bytes);
		}
	}

	private static FileQuotaInformation Snapshot(Sid sid, Record rec)
	{
		lock (rec)
		{
			return new FileQuotaInformation(sid, rec.ChangeTime, rec.Used, rec.Threshold, rec.Limit);
		}
	}

	private static string Key(string shareName, Sid owner)
	{
		return shareName + "\0" + Convert.ToHexString(owner.ToBytes());
	}
}
