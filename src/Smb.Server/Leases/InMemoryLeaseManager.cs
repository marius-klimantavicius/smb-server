using System;
using System.Collections.Generic;
using System.Threading;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server.State;

namespace Smb.Server.Leases;

public sealed class InMemoryLeaseManager : ILeaseManager
{
	private sealed class LeaseHolder(LeaseKey key, string fileKey)
	{
		public LeaseKey Key { get; } = key;

		public string FileKey { get; } = fileKey;

		public LeaseState State { get; set; }

		public ushort Epoch { get; set; }

		public bool IsDirectory { get; init; }

		public HashSet<SmbOpen> Opens { get; } = new HashSet<SmbOpen>();
	}

	private readonly Lock _gate = new Lock();

	private readonly Dictionary<string, HashSet<LeaseKey>> _fileKeys = new Dictionary<string, HashSet<LeaseKey>>(StringComparer.OrdinalIgnoreCase);

	private readonly Dictionary<LeaseKey, LeaseHolder> _byKey = new Dictionary<LeaseKey, LeaseHolder>();

	private readonly Dictionary<SmbOpen, LeaseKey> _openIndex = new Dictionary<SmbOpen, LeaseKey>();

	public LeaseGrant RequestLease(SmbOpen open, LeaseRequest request)
	{
		var leaseState = request.RequestedState & LeaseState.ReadWriteHandle;
		var key = request.Key;
		if (key.IsZero)
		{
			return LeaseGrant.None;
		}

		var fileKey = FileKey(open);
		lock (_gate)
		{
			var orAddFile = GetOrAddFile(fileKey);
			var flag = HasOtherKey(orAddFile, key);
			var list = new List<LeaseBreak>();
			if (flag)
			{
				foreach (var item in orAddFile)
				{
					if (!(item == key))
					{
						var leaseHolder = _byKey[item];
						var leaseState2 = leaseHolder.State & LeaseState.Read;
						if (leaseState2 != leaseHolder.State)
						{
							var state = leaseHolder.State;
							leaseHolder.State = leaseState2;
							leaseHolder.Epoch++;
							list.Add(new LeaseBreak(leaseHolder.Key, state, leaseState2, leaseHolder.Epoch, First(leaseHolder.Opens)));
						}
					}
				}
			}

			var leaseState3 = (flag ? (leaseState & LeaseState.Read) : leaseState);
			if (_byKey.TryGetValue(key, out var value))
			{
				value.Opens.Add(open);
				if (leaseState3 != value.State)
				{
					value.Epoch++;
				}

				value.State = leaseState3;
			}
			else
			{
				value = new LeaseHolder(key, fileKey)
				{
					State = leaseState3,
					Epoch = (ushort)(request.IsV2 ? request.Epoch : 0),
					IsDirectory = (open.LocalOpen?.IsDirectory ?? false),
				};
				value.Opens.Add(open);
				_byKey[key] = value;
				orAddFile.Add(key);
			}

			_openIndex[open] = key;
			return new LeaseGrant(value.State, value.Epoch, list);
		}
	}

	public LeaseState Acknowledge(LeaseKey key, LeaseState newState)
	{
		lock (_gate)
		{
			if (!_byKey.TryGetValue(key, out var value))
			{
				return LeaseState.None;
			}

			value.State = newState & LeaseState.ReadWriteHandle;
			return value.State;
		}
	}

	public void ReleaseOwner(SmbOpen open)
	{
		lock (_gate)
		{
			if (!_openIndex.Remove(open, out var value) || !_byKey.TryGetValue(value, out var value2))
			{
				return;
			}

			value2.Opens.Remove(open);
			if (value2.Opens.Count != 0)
			{
				return;
			}

			_byKey.Remove(value);
			if (_fileKeys.TryGetValue(value2.FileKey, out var value3))
			{
				value3.Remove(value);
				if (value3.Count == 0)
				{
					_fileKeys.Remove(value2.FileKey);
				}
			}
		}
	}

	public IReadOnlyList<LeaseBreak> BreakDirectoryLease(string directoryFileKey)
	{
		lock (_gate)
		{
			if (!_fileKeys.TryGetValue(directoryFileKey, out var value) || value.Count == 0)
			{
				return Array.Empty<LeaseBreak>();
			}

			List<LeaseBreak> list = null;
			foreach (var item in value)
			{
				var leaseHolder = _byKey[item];
				if (leaseHolder.IsDirectory)
				{
					var leaseState = leaseHolder.State & LeaseState.Read;
					if (leaseState != leaseHolder.State)
					{
						var state = leaseHolder.State;
						leaseHolder.State = leaseState;
						leaseHolder.Epoch++;
						(list ??= new List<LeaseBreak>()).Add(new LeaseBreak(leaseHolder.Key, state, leaseState, leaseHolder.Epoch, First(leaseHolder.Opens)));
					}
				}
			}

			IReadOnlyList<LeaseBreak> readOnlyList = list;
			return readOnlyList ?? Array.Empty<LeaseBreak>();
		}
	}

	private HashSet<LeaseKey> GetOrAddFile(string fileKey)
	{
		if (!_fileKeys.TryGetValue(fileKey, out var value))
		{
			value = (_fileKeys[fileKey] = new HashSet<LeaseKey>());
		}

		return value;
	}

	private static bool HasOtherKey(HashSet<LeaseKey> keys, LeaseKey self)
	{
		foreach (var key in keys)
		{
			if (key != self)
			{
				return true;
			}
		}

		return false;
	}

	private static SmbOpen First(HashSet<SmbOpen> opens)
	{
		using (var enumerator = opens.GetEnumerator())
		{
			if (enumerator.MoveNext())
			{
				return enumerator.Current!;
			}
		}

		throw new InvalidOperationException("Lease holder has no opens.");
	}

	private static string FileKey(SmbOpen open)
	{
		return open.LocalOpen?.PhysicalPath ?? open.PathName;
	}
}
