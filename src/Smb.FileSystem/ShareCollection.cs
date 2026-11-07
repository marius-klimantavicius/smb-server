using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace Smb.FileSystem;

public sealed class ShareCollection
{
	private readonly ConcurrentDictionary<string, IShare> _shares = new ConcurrentDictionary<string, IShare>(StringComparer.OrdinalIgnoreCase);

	public IReadOnlyCollection<IShare> All => _shares.Values.ToArray();

	public ShareCollection Add(IShare share)
	{
		_shares[share.Name] = share;
		return this;
	}

	public bool Remove(string name)
	{
		return _shares.TryRemove(name, out _);
	}

	public bool TryGet(string name, out IShare share)
	{
		return _shares.TryGetValue(name, out share);
	}

	public bool Contains(string name)
	{
		return _shares.ContainsKey(name);
	}
}
