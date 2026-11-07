using System;
using System.Collections.Generic;
using System.Threading;

namespace Smb.Server;

public sealed class ConnectionLimiter
{
	private readonly int _globalMax;

	private readonly int _perClientMax;

	private readonly Lock _gate = new Lock();

	private readonly Dictionary<string, int> _perClient = new Dictionary<string, int>(StringComparer.Ordinal);

	private int _total;

	public int Total
	{
		get
		{
			lock (_gate)
			{
				return _total;
			}
		}
	}

	public ConnectionLimiter(int globalMax, int perClientMax)
	{
		_globalMax = globalMax;
		_perClientMax = perClientMax;
	}

	public int CountFor(string clientAddress)
	{
		lock (_gate)
		{
			return _perClient.GetValueOrDefault(clientAddress, 0);
		}
	}

	public bool TryAdmit(string clientAddress)
	{
		lock (_gate)
		{
			if (_globalMax > 0 && _total >= _globalMax)
			{
				return false;
			}

			_perClient.TryGetValue(clientAddress, out var value);
			if (_perClientMax > 0 && value >= _perClientMax)
			{
				return false;
			}

			_total++;
			_perClient[clientAddress] = value + 1;
			return true;
		}
	}

	public void Release(string clientAddress)
	{
		lock (_gate)
		{
			if (_total > 0)
			{
				_total--;
			}

			if (_perClient.TryGetValue(clientAddress, out var value))
			{
				if (value <= 1)
				{
					_perClient.Remove(clientAddress);
				}
				else
				{
					_perClient[clientAddress] = value - 1;
				}
			}
		}
	}
}
