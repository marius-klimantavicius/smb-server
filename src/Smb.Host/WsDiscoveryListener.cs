using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Smb.Protocol.Discovery;

namespace Smb.Host;

/// <summary>
/// [M11.3] WS-Discovery UDP responder. Binds a datagram socket on the WS-Discovery port (default 3702),
/// optionally joins the IPv4 multicast group 239.255.255.250, and answers Probe messages with a ProbeMatches
/// reply so the server appears in Windows Explorer's Network view. Also emits a Hello on start and a Bye on
/// stop. The wire format is built by the pure <see cref="T:Smb.Protocol.Discovery.WsDiscoveryResponder" />; this class only owns the
/// socket. Kept in the host layer so the core stays transport-agnostic.
/// </summary>
internal sealed class WsDiscoveryListener
{
    private readonly WsDiscoveryOptions _options;

    private readonly WsDiscoveryResponder _responder;

    private readonly Action<string>? _log;

    private Socket? _socket;

    private IPEndPoint? _multicastEndpoint;

    private Task? _receiveLoop;

    private CancellationTokenSource? _cts;

    /// <summary>The bound local endpoint (with the actual port after <see cref="M:Smb.Host.WsDiscoveryListener.Start(System.Threading.CancellationToken)" />), for diagnostics/tests.</summary>
    public IPEndPoint? LocalEndPoint => _socket?.LocalEndPoint as IPEndPoint;

    public WsDiscoveryListener(WsDiscoveryOptions options, Action<string>? log)
    {
        _options = options;
        _responder = options.CreateResponder();
        _log = log;
    }

    /// <summary>Binds the socket, optionally joins the multicast group, announces Hello, and starts receiving.</summary>
    public void Start(CancellationToken hardCt)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(hardCt);
        _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        _socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, optionValue: true);
        _socket.Bind(new IPEndPoint(_options.BindAddress, _options.Port));
        var iPAddress = IPAddress.Parse("239.255.255.250");
        _multicastEndpoint = new IPEndPoint(iPAddress, _options.Port);
        if (_options.JoinMulticast)
        {
            try
            {
                _socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership, new MulticastOption(iPAddress, _options.BindAddress));
            }
            catch (SocketException ex)
            {
                _log?.Invoke($"[wsd] multicast join failed ({ex.SocketErrorCode}); serving unicast probes only.");
            }
        }

        _log?.Invoke($"WS-Discovery listening on {LocalEndPoint} (endpoint {_responder.EndpointId:D}).");
        _receiveLoop = ReceiveLoopAsync(_cts.Token);
        if (_options.AnnouncePresence && _options.JoinMulticast)
        {
            _ = SendToMulticastAsync(_responder.CreateHello(), _cts.Token);
        }
    }

    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        var buffer = new byte[65536];
        try
        {
            while (!ct.IsCancellationRequested)
            {
                SocketReceiveFromResult socketReceiveFromResult;
                try
                {
                    socketReceiveFromResult = await _socket!.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), ct).ConfigureAwait(continueOnCapturedContext: false);
                }
                catch (SocketException)
                {
                    continue;
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                byte[] array;
                try
                {
                    array = _responder.TryCreateProbeMatch(buffer.AsSpan(0, socketReceiveFromResult.ReceivedBytes));
                }
                catch (Exception ex3)
                {
                    _log?.Invoke("[wsd] probe handling error: " + ex3.GetType().Name + ": " + ex3.Message);
                    continue;
                }

                if (array != null)
                {
                    try
                    {
                        await _socket.SendToAsync(array, SocketFlags.None, socketReceiveFromResult.RemoteEndPoint, ct).ConfigureAwait(continueOnCapturedContext: false);
                    }
                    catch (SocketException ex4)
                    {
                        _log?.Invoke($"[wsd] reply send failed: {ex4.SocketErrorCode}.");
                    }
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }

    private async Task SendToMulticastAsync(byte[] message, CancellationToken ct)
    {
        try
        {
            if (_socket != null && _multicastEndpoint != null)
            {
                await _socket.SendToAsync(message, SocketFlags.None, _multicastEndpoint, ct).ConfigureAwait(continueOnCapturedContext: false);
            }
        }
        catch (SocketException ex)
        {
            _log?.Invoke($"[wsd] multicast send failed: {ex.SocketErrorCode}.");
        }
        catch (ObjectDisposedException)
        {
        }
        catch (OperationCanceledException)
        {
        }
    }

    /// <summary>Announces Bye (best-effort), stops the receive loop and closes the socket.</summary>
    public async Task StopAsync()
    {
        if (_options.AnnouncePresence && _options.JoinMulticast && _socket != null)
        {
            try
            {
                await SendToMulticastAsync(_responder.CreateBye(), CancellationToken.None).ConfigureAwait(continueOnCapturedContext: false);
            }
            catch
            {
                // ignored
            }
        }

        try
        {
            if (_cts != null)
            {
                await _cts.CancelAsync().ConfigureAwait(continueOnCapturedContext: false);
            }
        }
        catch
        {
            // ignored
        }

        if (_socket != null)
        {
            try
            {
                _socket.Dispose();
            }
            catch
            {
                // ignored
            }
        }

        if (_receiveLoop != null)
        {
            try
            {
                await _receiveLoop.ConfigureAwait(continueOnCapturedContext: false);
            }
            catch
            {
                // ignored
            }
        }

        _cts?.Dispose();
        _socket = null;
    }
}
