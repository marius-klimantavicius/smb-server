using static Managed.Transport.MsQuic;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;

namespace Managed.Transport.Hosting;

public sealed unsafe partial class MsQuicHost
{
    private const uint DatagramAllocationTag = 0x55647048;
    private const ushort DatagramMtu = CXPLAT_MAX_MTU;
    private const int DatagramCapacity = DatagramMtu;

    private static readonly ushort DatagramMaxPayload = MaxUdpPayloadSizeFromMTU(DatagramMtu);

    private readonly ConcurrentDictionary<nint, DatagramReceive> _datagramReceives = new ConcurrentDictionary<IntPtr, DatagramReceive>();
    private long _datagramTruncations, _datagramSendErrors, _datagramReceiveErrors;

    public long DatagramTruncations => Interlocked.Read(ref _datagramTruncations);
    public long DatagramSendErrors => Interlocked.Read(ref _datagramSendErrors);
    public long DatagramReceiveErrors => Interlocked.Read(ref _datagramReceiveErrors);
    public int OutstandingDatagramReceives => _datagramReceives.Count;

    private static void RegisterDatapath(ref MSQUIC_HOST_TABLE table)
    {
        table.CxPlatConvertFromMappedV6 = &DatapathFromMapped;
        table.CxPlatConvertToMappedV6 = &DatapathToMapped;
        table.CxPlatDataPathInitialize = &DatapathInitialize;
        table.CxPlatDataPathUninitialize = &DatapathUninitialize;
        table.CxPlatDataPathGetSupportedFeatures = &DatapathFeatures;
        table.CxPlatDataPathIsPaddingPreferred = &DatapathPadding;
        table.CxPlatDataPathResolveAddress = &DatapathResolveAddress;
        table.CxPlatDataPathGetLocalAddressForRemote = &DatapathLocalForRemote;
        table.CxPlatDataPathGetLocalAddresses = &DatapathAddresses;
        table.CxPlatDataPathRssConfigGet = &DatapathRssGet;
        table.CxPlatDataPathRssConfigFree = &DatapathRssFree;
        table.CxPlatDataPathUpdatePollingIdleTimeout = &DatapathPolling;
        table.CxPlatSocketCreateUdp = &DatapathSocketCreate;
        table.CxPlatSocketDelete = &DatapathSocketDelete;
        table.CxPlatSocketGetLocalAddress = &DatapathSocketLocal;
        table.CxPlatSocketGetRemoteAddress = &DatapathSocketRemote;
        table.CxPlatSocketGetLocalMtu = &DatapathSocketMtu;
        table.CxPlatSocketGetQtipEnabled = &DatapathSocketQtip;
        table.CxPlatSocketUpdateQeo = &DatapathSocketQeo;
        table.CxPlatSocketSend = &DatapathSocketSend;
        table.CxPlatSendDataAlloc = &DatapathSendAlloc;
        table.CxPlatSendDataAllocBuffer = &DatapathSendBuffer;
        table.CxPlatSendDataFreeBuffer = &DatapathSendFreeBuffer;
        table.CxPlatSendDataFree = &DatapathSendFree;
        table.CxPlatSendDataIsFull = &DatapathSendFull;
        table.CxPlatRecvDataReturn = &DatapathReceiveReturn;
        table.CxPlatResolveRoute = &DatapathResolveRoute;
        table.CxPlatResolveRouteComplete = &DatapathResolveComplete;
        table.CxPlatUpdateRoute = &DatapathUpdateRoute;
    }

    internal static IPEndPoint DatagramEndpoint(QUIC_ADDR* address)
    {
        if (address == null)
            throw new ArgumentNullException(nameof(address));

        var ip = QuicAddrGetFamily(address) switch
        {
            QUIC_ADDRESS_FAMILY_INET => new IPAddress(new ReadOnlySpan<byte>(&address->Ipv4.sin_addr, sizeof(in_addr))),
            QUIC_ADDRESS_FAMILY_INET6 => new IPAddress(new ReadOnlySpan<byte>(&address->Ipv6.sin6_addr, sizeof(in6_addr)), address->Ipv6.sin6_scope_id),
            _ => throw new ArgumentException("Unsupported address family."),
        };

        if (ip.IsIPv4MappedToIPv6)
            ip = ip.MapToIPv4();

        if (ip.AddressFamily == AddressFamily.InterNetworkV6 && !ip.IsIPv6LinkLocal && ip.ScopeId != 0)
            ip = new IPAddress(ip.GetAddressBytes());

        return new IPEndPoint(ip, QuicAddrGetPort(address));
    }

    internal static void DatagramAddress(IPEndPoint endpoint, QUIC_ADDR* address, bool mapped = false)
    {
        *address = default;

        var ip = endpoint.Address;
        if (!mapped && ip.IsIPv4MappedToIPv6)
            ip = ip.MapToIPv4();
        if (mapped && ip.AddressFamily == AddressFamily.InterNetwork)
            ip = ip.MapToIPv6();

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            QuicAddrSetFamily(address, QUIC_ADDRESS_FAMILY_INET);
            if (ip.Equals(IPAddress.Loopback))
                QuicAddrSetToLoopback(address);
            else
                ip.TryWriteBytes(new Span<byte>(&address->Ipv4.sin_addr, sizeof(in_addr)), out _);
        }
        else
        {
            QuicAddrSetFamily(address, QUIC_ADDRESS_FAMILY_INET6);
            address->Ipv6.sin6_scope_id = checked((uint)ip.ScopeId);
            if (ip.Equals(IPAddress.IPv6Loopback))
                QuicAddrSetToLoopback(address);
            else
                ip.TryWriteBytes(new Span<byte>(&address->Ipv6.sin6_addr, sizeof(in6_addr)), out _);
        }

        QuicAddrSetPort(address, checked((ushort)endpoint.Port));
    }

    private static uint DatagramStatus(Exception error) => error switch
    {
        OutOfMemoryException => Status.OutOfMemory,
        ObjectDisposedException => Status.Aborted,
        ArgumentException or OverflowException => Status.InvalidParameter,
        SocketException s => s.SocketErrorCode switch
        {
            SocketError.AddressAlreadyInUse => Status.AddressInUse,
            SocketError.AddressNotAvailable => Status.AddressNotAvailable,
            SocketError.AddressFamilyNotSupported => Status.InvalidAddress,
            SocketError.ConnectionRefused => Status.ConnectionRefused,
            SocketError.HostUnreachable or SocketError.NetworkUnreachable => Status.Unreachable,
            SocketError.OperationAborted or SocketError.Interrupted => Status.Aborted,
            SocketError.NoBufferSpaceAvailable => Status.OutOfMemory,
            SocketError.OperationNotSupported or SocketError.ProtocolOption => Status.NotSupported,
            SocketError.TimedOut => Status.ConnectionTimeout,
            SocketError.HostNotFound or SocketError.NoData => Status.NotFound,
            SocketError.MessageSize => 90,
            _ => Status.InternalError,
        },
        NotSupportedException => Status.NotSupported,
        _ => Status.InternalError,
    };

    private static void DatapathFromMapped(void* context, QUIC_ADDR* input, QUIC_ADDR* output)
    {
        try
        {
            var ep = DatagramEndpoint(input);
            DatagramAddress(ep, output);
        }
        catch (Exception e)
        {
            FatalInvariant(e.ToString());
        }
    }

    private static void DatapathToMapped(void* context, QUIC_ADDR* input, QUIC_ADDR* output)
    {
        try
        {
            var ep = DatagramEndpoint(input);
            DatagramAddress(ep, output, true);
        }
        catch (Exception e)
        {
            FatalInvariant(e.ToString());
        }
    }

    private static uint DatapathInitialize(void* context, uint clientLength, CXPLAT_UDP_DATAPATH_CALLBACKS* udp, CXPLAT_TCP_DATAPATH_CALLBACKS* tcp, CXPLAT_WORKER_POOL* workers, CXPLAT_DATAPATH_INIT_CONFIG* config, CXPLAT_DATAPATH** output)
    {
        if (output == null)
            return Status.InvalidParameter;

        *output = null;

        if (udp == null || udp->Receive == null || udp->Unreachable == null || workers == null)
            return Status.InvalidParameter;
        if (tcp != null || (config != null && (config->EnableDscpOnRecv != 0 || config->XdpMapConfigCount != 0)))
            return Status.NotSupported;

        DatagramPath? path = null;
        try
        {
            var host = FromContext(context);
            if (clientLength > int.MaxValue - 4096)
                return Status.OutOfMemory;

            path = new DatagramPath(host, *udp, workers, checked((int)clientLength));
            *output = (CXPLAT_DATAPATH*)host.AddResource(path);
            return Status.Success;
        }
        catch (Exception error)
        {
            path?.Dispose();
            return DatagramStatus(error);
        }
    }

    private static void DatapathUninitialize(void* context, CXPLAT_DATAPATH* path)
    {
        try
        {
            FromContext(context).ReleaseResource<DatagramPath>(path);
        }
        catch (Exception e)
        {
            FatalInvariant(e.ToString());
        }
    }

    private static CXPLAT_DATAPATH_FEATURES DatapathFeatures(void* c, CXPLAT_DATAPATH* p, CXPLAT_SOCKET_FLAGS flags) => 0;
    private static byte DatapathPadding(void* c, CXPLAT_DATAPATH* p, CXPLAT_SEND_DATA* send) => 0;

    private static uint DatapathRssGet(void* c, uint index, CXPLAT_RSS_CONFIG** output)
    {
        if (output == null)
            return Status.InvalidParameter;

        *output = null;
        return Status.NotSupported;
    }

    private static void DatapathRssFree(void* c, CXPLAT_RSS_CONFIG* value)
    {
        if (value != null)
            FatalInvariant("RSS configuration was not allocated by this host.");
    }

    private static void DatapathPolling(void* c, CXPLAT_DATAPATH* p, uint timeout)
    {
        if (timeout != 0)
            FatalInvariant("Busy-polling is outside the BCL datapath profile.");
    }

    private static uint DatapathResolveAddress(void* c, CXPLAT_DATAPATH* p, byte* name, QUIC_ADDR* output)
    {
        if (name == null || output == null) return Status.InvalidParameter;

        try
        {
            var text = Marshal.PtrToStringUTF8((nint)name)!;
            var family = QuicAddrGetFamily(output);
            int port = QuicAddrGetPort(output);

            foreach (var ip in Dns.GetHostAddresses(text))
            {
                if (family == QUIC_ADDRESS_FAMILY_UNSPEC || (family == QUIC_ADDRESS_FAMILY_INET && ip.AddressFamily == AddressFamily.InterNetwork) || (family == QUIC_ADDRESS_FAMILY_INET6 && ip.AddressFamily == AddressFamily.InterNetworkV6))
                {
                    DatagramAddress(new IPEndPoint(ip, port), output);
                    return Status.Success;
                }
            }

            return Status.NotFound;
        }
        catch (Exception e)
        {
            return DatagramStatus(e);
        }
    }

    private static uint DatapathLocalForRemote(void* c, QUIC_ADDR* remote, QUIC_ADDR* local)
    {
        if (remote == null || local == null)
            return Status.InvalidParameter;

        try
        {
            var endpoint = DatagramEndpoint(remote);

            using var socket = new Socket(endpoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            socket.Connect(endpoint.Port == 0 ? new IPEndPoint(endpoint.Address, 9) : endpoint);

            var selected = (IPEndPoint)socket.LocalEndPoint!;
            DatagramAddress(new IPEndPoint(selected.Address, 0), local);

            return Status.Success;
        }
        catch (Exception e)
        {
            return DatagramStatus(e);
        }
    }

    private static uint DatapathAddresses(void* c, CXPLAT_DATAPATH* p, CXPLAT_ADAPTER_ADDRESS** output, uint* count)
    {
        if (output == null || count == null)
            return Status.InvalidParameter;

        *output = null;
        *count = 0;
        try
        {
            var list = new List<CXPLAT_ADAPTER_ADDRESS>();
            foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
            foreach (var unicast in adapter.GetIPProperties().UnicastAddresses)
            {
                var ip = unicast.Address;
                if (ip.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
                    continue;

                CXPLAT_ADAPTER_ADDRESS item = default;
                DatagramAddress(new IPEndPoint(ip, 0), &item.Address);
                item.InterfaceIndex = checked((uint)(ip.AddressFamily == AddressFamily.InterNetwork ? adapter.GetIPProperties().GetIPv4Properties().Index : adapter.GetIPProperties().GetIPv6Properties().Index));
                item.InterfaceType = checked((ushort)adapter.NetworkInterfaceType);
                item.OperationStatus = adapter.OperationalStatus switch
                {
                    OperationalStatus.Up => CXPLAT_OPERATION_STATUS.CXPLAT_OPERATION_STATUS_UP,
                    OperationalStatus.Down => CXPLAT_OPERATION_STATUS.CXPLAT_OPERATION_STATUS_DOWN,
                    OperationalStatus.Testing => CXPLAT_OPERATION_STATUS.CXPLAT_OPERATION_STATUS_TESTING,
                    OperationalStatus.Dormant => CXPLAT_OPERATION_STATUS.CXPLAT_OPERATION_STATUS_DORMANT,
                    OperationalStatus.NotPresent => CXPLAT_OPERATION_STATUS.CXPLAT_OPERATION_STATUS_NOT_PRESENT,
                    OperationalStatus.LowerLayerDown => CXPLAT_OPERATION_STATUS.CXPLAT_OPERATION_STATUS_LOWER_LAYER_DOWN,
                    _ => CXPLAT_OPERATION_STATUS.CXPLAT_OPERATION_STATUS_UNKNOWN,
                };
                list.Add(item);
            }

            var memory = (CXPLAT_ADAPTER_ADDRESS*)FromContext(c).AllocatePlatformMemory(checked((ulong)list.Count * (ulong)sizeof(CXPLAT_ADAPTER_ADDRESS)), QUIC_POOL_DATAPATH_ADDRESSES);
            if (memory == null && list.Count != 0)
                return Status.OutOfMemory;

            CollectionsMarshal.AsSpan(list).CopyTo(new Span<CXPLAT_ADAPTER_ADDRESS>(memory, list.Count));

            *output = memory;
            *count = checked((uint)list.Count);
            return Status.Success;
        }
        catch (Exception e)
        {
            return DatagramStatus(e);
        }
    }

    private static uint DatapathSocketCreate(void* context, CXPLAT_DATAPATH* path, CXPLAT_UDP_CONFIG* config, CXPLAT_SOCKET** output)
    {
        if (output == null || config == null)
            return Status.InvalidParameter;

        *output = null;
        // Upstream ListenerStart always requests SHARE | SERVER_OWNED. The core
        // shares its binding object; the BCL sockets retain same-port reuse.
        const CXPLAT_SOCKET_FLAGS supported = CXPLAT_SOCKET_FLAGS.CXPLAT_SOCKET_FLAG_SHARE | CXPLAT_SOCKET_FLAGS.CXPLAT_SOCKET_SERVER_OWNED;
        if ((config->Flags & ~supported) != 0 || config->CibirIdLength != 0)
            return Status.NotSupported;

        DatagramSocket? socket = null;
        try
        {
            var host = FromContext(context);
            socket = new DatagramSocket(host.Resource<DatagramPath>(path), *config);
            socket.Token = host.AddResource(socket);
            socket.Start();
            *output = (CXPLAT_SOCKET*)socket.Token;
            return Status.Success;
        }
        catch (Exception e)
        {
            if (socket != null && socket.Token != null)
                FromContext(context).ReleaseResource<DatagramSocket>(socket.Token);
            else
                socket?.Dispose();

            return DatagramStatus(e);
        }
    }

    private static void DatapathSocketDelete(void* c, CXPLAT_SOCKET* p)
    {
        try
        {
            var h = FromContext(c);
            h.Resource<DatagramSocket>(p).Close(true);
        }
        catch (Exception e)
        {
            FatalInvariant(e.ToString());
        }
    }

    private static void DatapathSocketLocal(void* c, CXPLAT_SOCKET* p, QUIC_ADDR* output)
    {
        try
        {
            DatagramAddress(FromContext(c).Resource<DatagramSocket>(p).Local, output);
        }
        catch (Exception e)
        {
            FatalInvariant(e.ToString());
        }
    }

    private static void DatapathSocketRemote(void* c, CXPLAT_SOCKET* p, QUIC_ADDR* output)
    {
        try
        {
            var remote = FromContext(c).Resource<DatagramSocket>(p).Remote;
            if (remote == null)
                *output = default;
            else
                DatagramAddress(remote, output);
        }
        catch (Exception e)
        {
            FatalInvariant(e.ToString());
        }
    }

    private static ushort DatapathSocketMtu(void* c, CXPLAT_SOCKET* p, CXPLAT_ROUTE* route) => DatagramMtu;
    private static byte DatapathSocketQtip(void* c, CXPLAT_SOCKET* p) => 0;
    private static uint DatapathSocketQeo(void* c, CXPLAT_SOCKET* p, CXPLAT_QEO_CONNECTION* q, uint count) => Status.NotSupported;

    private static uint DatapathResolveRoute(void* c, CXPLAT_SOCKET* p, CXPLAT_ROUTE* route, byte path, void* context, delegate*<void*, byte*, byte, byte, void> callback)
    {
        if (route == null)
            return Status.InvalidParameter;
        if (route->DatapathType == 2 || route->UseQTIP != 0)
            return Status.NotSupported;

        try
        {
            var socket = FromContext(c).Resource<DatagramSocket>(p);
            // Normalize mapped IPv4 and scope IDs before applying the C address
            // predicate, just as the socket endpoint conversion does.
            var local = route->LocalAddress;
            if (QuicAddrGetFamily(&local) != QUIC_ADDRESS_FAMILY_UNSPEC)
                DatagramAddress(DatagramEndpoint(&local), &local);

            if (QuicAddrGetFamily(&local) == QUIC_ADDRESS_FAMILY_UNSPEC || QuicAddrIsWildCard(&local) != 0)
            {
                QUIC_ADDR selected;
                var status = DatapathLocalForRemote(c, &route->RemoteAddress, &selected);
                if (status != 0)
                    return status;

                QuicAddrSetPort(&selected, checked((ushort)socket.Local.Port));
                route->LocalAddress = selected;
            }

            socket.SelectSocket(DatagramEndpoint(&route->LocalAddress));
            route->DatapathType = 1;
            route->State = CXPLAT_ROUTE_STATE.RouteResolved;
            return Status.Success;
        }
        catch (Exception e)
        {
            return DatagramStatus(e);
        }
    }

    private static void DatapathResolveComplete(void* c, void* context, CXPLAT_ROUTE* route, byte* physical, byte path)
    {
        if (route == null || route->DatapathType == 2 || route->UseQTIP != 0)
            FatalInvariant("Raw route completion is unsupported.");

        route->State = CXPLAT_ROUTE_STATE.RouteResolved;
    }

    private static void DatapathUpdateRoute(void* c, CXPLAT_ROUTE* target, CXPLAT_ROUTE* source)
    {
        if (target == null || source == null || source->DatapathType == 2 || source->UseQTIP != 0)
            FatalInvariant("Raw route update is unsupported.");

        *target = *source;
    }

    private static bool IsWildcard(IPAddress address) => address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any);
}