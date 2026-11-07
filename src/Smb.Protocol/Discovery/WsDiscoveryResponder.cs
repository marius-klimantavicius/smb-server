using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace Smb.Protocol.Discovery;

public sealed class WsDiscoveryResponder
{
	private readonly Guid _endpointId;

	private readonly IReadOnlyList<WsDiscoveryQName> _types;

	private readonly IReadOnlyList<string> _xAddrs;

	private readonly HashSet<string> _typeSet;

	private readonly ulong _instanceId;

	private long _messageNumber;

	public Guid EndpointId => _endpointId;

	public ulong InstanceId => _instanceId;

	public WsDiscoveryResponder(Guid endpointId, IReadOnlyList<WsDiscoveryQName>? types = null, IReadOnlyList<string>? xAddrs = null, ulong? instanceId = null)
	{
		_endpointId = endpointId;
		IReadOnlyList<WsDiscoveryQName>? types2;
		if (types == null || types.Count <= 0)
		{
			IReadOnlyList<WsDiscoveryQName> readOnlyList = [WsDiscoveryQName.Computer];
			types2 = readOnlyList;
		}
		else
		{
			types2 = types;
		}

		_types = types2;
		_xAddrs = xAddrs ?? Array.Empty<string>();
		_typeSet = new HashSet<string>(_types.Select(t => t.Clark), StringComparer.Ordinal);
		_instanceId = (ulong)(((long?)instanceId) ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds());
	}

	public byte[]? TryCreateProbeMatch(ReadOnlySpan<byte> datagram)
	{
		if (!WsDiscoveryMessage.TryParseProbe(datagram, out var probe))
		{
			return null;
		}

		if (!Matches(probe))
		{
			return null;
		}

		return WsDiscoveryMessage.BuildProbeMatches(probe.MessageId, _endpointId, _types, _xAddrs, _instanceId, NextMessageNumber());
	}

	public byte[] CreateHello()
	{
		return WsDiscoveryMessage.BuildHello(_endpointId, _types, _xAddrs, _instanceId, NextMessageNumber());
	}

	public byte[] CreateBye()
	{
		return WsDiscoveryMessage.BuildBye(_endpointId, _types, _xAddrs, _instanceId, NextMessageNumber());
	}

	private bool Matches(WsDiscoveryProbe probe)
	{
		if (probe.Types.Count != 0)
		{
			return probe.Types.Any(_typeSet.Contains);
		}

		return true;
	}

	private ulong NextMessageNumber()
	{
		return (ulong)Interlocked.Increment(ref _messageNumber);
	}
}
