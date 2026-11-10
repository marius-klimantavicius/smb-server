using System;
using System.Collections.Generic;
using System.Threading;

namespace Smb.Server.Rpc;

public sealed class RpcPipe
{
    private readonly IRpcEndpoint _endpoint;

    private readonly Lock _gate = new Lock();

    private readonly Queue<byte[]> _output = new Queue<byte[]>();
    private int _cursor;

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
            _output.Enqueue(array);
            return array;
        }
    }

    public void QueueOutput(byte[] data)
    {
        lock (_gate) _output.Enqueue(data);
    }

    public byte[] TakeOutput() => TakeOutput(int.MaxValue, out _);

    public byte[] TakeOutput(int count, out bool more) => TakeOutput(count, out more, out _);

    public byte[] TakeOutput(int count, out bool more, out bool partialMessage)
    {
        lock (_gate)
        {
            if (_output.Count == 0)
            {
                more = false;
                partialMessage = false;
                return Array.Empty<byte>();
            }

            var message = _output.Peek();
            var take = Math.Min(Math.Max(0, count), message.Length - _cursor);
            var result = message.AsSpan(_cursor, take).ToArray();
            _cursor += take;
            partialMessage = _cursor < message.Length;
            if (_cursor == message.Length)
            {
                _output.Dequeue();
                _cursor = 0;
            }

            more = _output.Count != 0;
            return result;
        }
    }
}
