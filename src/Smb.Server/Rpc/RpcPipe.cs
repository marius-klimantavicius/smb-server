using System;
using System.Threading;

namespace Smb.Server.Rpc;

public sealed class RpcPipe
{
	private readonly IRpcEndpoint _endpoint;

	private readonly Lock _gate = new Lock();

	private byte[] _output = Array.Empty<byte>();

	public IRpcEndpoint Endpoint => _endpoint;

	public RpcPipe(IRpcEndpoint endpoint)
	{
		_endpoint = endpoint;
	}

	public byte[] Transceive(ReadOnlySpan<byte> requestPdu)
	{
		var array = _endpoint.HandlePdu(requestPdu);
		lock (_gate)
		{
			_output = array;
			return array;
		}
	}

	public byte[] TakeOutput()
	{
		lock (_gate)
		{
			var output = _output;
			_output = Array.Empty<byte>();
			return output;
		}
	}
}
