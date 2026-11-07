using System;
using System.Buffers;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using static Managed.Transport.MsQuic;

namespace Managed.Transport.Hosting;

public sealed unsafe partial class MsQuicHost
{
    // Erased from production builds. Source-linked fault tests throw after rent
    // and before submission, so the real receive catch must return the lease.
    static partial void ObserveBeforeDatagramReceive();

    private sealed class DatagramPath : IDisposable
    {
        private readonly object _gate = new object();
        private readonly Stack<DatagramReceive> _pool = new Stack<DatagramReceive>();
        private int _sockets, _closingSockets, _rented;
        private bool _closing, _disposed;

        internal readonly MsQuicHost Host;
        internal readonly CXPLAT_UDP_DATAPATH_CALLBACKS Callbacks;
        internal readonly CXPLAT_WORKER_POOL* Workers;
        internal readonly int ClientLength;

        internal DatagramPath(MsQuicHost host, CXPLAT_UDP_DATAPATH_CALLBACKS callbacks, CXPLAT_WORKER_POOL* workers, int clientLength)
        {
            Host = host;
            Callbacks = callbacks;
            Workers = workers;
            ClientLength = clientLength;
            if (CxPlatWorkerPoolAddRef(workers, CXPLAT_WORKER_POOL_REF.CXPLAT_WORKER_POOL_REF_EXTERNAL) == 0)
                throw new ObjectDisposedException("worker pool");
        }

        internal void AddSocket()
        {
            lock (_gate)
            {
                if (_closing)
                    throw new ObjectDisposedException("datapath");

                _sockets++;
            }
        }

        internal void BeginSocketClose()
        {
            lock (_gate)
                _closingSockets++;
        }

        internal void RemoveSocket()
        {
            lock (_gate)
            {
                _closingSockets--;

                if (--_sockets < 0)
                    FatalInvariant("Negative socket ownership count.");

                Monitor.PulseAll(_gate);
            }
        }

        internal DatagramReceive Rent()
        {
            lock (_gate)
            {
                if (_closing)
                    throw new ObjectDisposedException("datapath");

                var item = _pool.Count != 0 ? _pool.Pop() : new DatagramReceive(this);

                _rented++;
                new Span<byte>(item.Data, sizeof(CXPLAT_RECV_DATA) + ClientLength).Clear();
                *item.Route = default;
                item.Data->Route = item.Route;
                item.Data->Buffer = item.Payload;
                item.Data->Allocated = 1;
                item.Data->DatapathType = 1;
                return item;
            }
        }

        internal void Return(DatagramReceive packet)
        {
            lock (_gate)
            {
                packet.Data->Allocated = 0;
                if (_closing || _pool.Count >= 64)
                    packet.Free();
                else
                    _pool.Push(packet);

                if (--_rented < 0)
                    FatalInvariant("Receive buffer returned twice.");

                Monitor.PulseAll(_gate);
            }
        }

        public void Dispose()
        {
            lock (_gate)
            {
                if (_disposed)
                    return;

                if (_sockets != _closingSockets)
                    FatalInvariant("Datapath destroyed with live sockets.");

                _closing = true;
                while (_sockets != 0 || _rented != 0)
                    Monitor.Wait(_gate);

                while (_pool.Count != 0)
                    _pool.Pop().Free();

                _disposed = true;
            }

            CxPlatWorkerPoolRelease(Workers, CXPLAT_WORKER_POOL_REF.CXPLAT_WORKER_POOL_REF_EXTERNAL);
        }
    }

    private sealed class DatagramReceive
    {
        internal readonly DatagramPath Path;
        internal readonly CXPLAT_RECV_DATA* Data;
        internal readonly CXPLAT_ROUTE* Route;
        internal readonly byte* Payload;
        internal readonly DatagramMemory Memory;

        internal DatagramReceive(DatagramPath path)
        {
            Path = path;
            var routeOffset = checked((sizeof(CXPLAT_RECV_DATA) + path.ClientLength + 15) & ~15);
            var bytes = checked(routeOffset + sizeof(CXPLAT_ROUTE) + DatagramCapacity);
            Data = (CXPLAT_RECV_DATA*)path.Host.AllocatePlatformMemory((ulong)bytes, DatagramAllocationTag);
            if (Data == null)
                throw new OutOfMemoryException();

            Route = (CXPLAT_ROUTE*)((byte*)Data + routeOffset);
            Payload = (byte*)Route + sizeof(CXPLAT_ROUTE);
            try
            {
                Memory = new DatagramMemory((nint)Payload, DatagramCapacity);
            }
            catch
            {
                path.Host.FreePlatformMemory(Data, DatagramAllocationTag);
                throw;
            }
        }

        internal void Free() => Path.Host.FreePlatformMemory(Data, DatagramAllocationTag);
    }

    private struct DatagramNotification
    {
        internal CXPLAT_SQE Sqe;
        internal void* Context;
        internal void* Socket;
    }

    private sealed class DatagramPhysical
    {
        internal readonly Socket Socket;
        internal readonly Thread Thread;
        internal bool Started;

        internal DatagramPhysical(DatagramSocket owner, Socket socket)
        {
            Socket = socket;
            Thread = new Thread(() => owner.Receive(this)) { IsBackground = true, Name = "MsQuic UDP receive" };
        }
    }

    private sealed class DatagramSocket : IDisposable
    {
        private readonly Queue<DatagramReceive> _received = new Queue<DatagramReceive>(256);
        private readonly Queue<IPEndPoint> _unreachable = new Queue<IPEndPoint>(64);
        private readonly CXPLAT_EVENTQ* _queue;
        private DatagramNotification* _notification;
        private readonly bool _counted;
        private int _activeSends, _callbackThread;
        private bool _closing, _disposed;
        private bool _registered;

        internal readonly DatagramPath Path;
        internal readonly IPEndPoint Local;
        internal readonly IPEndPoint? Remote;
        internal readonly ushort Partition;
        internal readonly uint InterfaceIndex;
        internal readonly void* CallbackContext;
        internal void* Token;
        internal readonly object Gate = new object();
        internal readonly List<DatagramPhysical> Physical = new List<DatagramPhysical>();
        internal CXPLAT_SQE* NotificationSqe => &_notification->Sqe;

        internal DatagramSocket(DatagramPath path, CXPLAT_UDP_CONFIG config)
        {
            Path = path;
            Partition = config.PartitionIndex;
            InterfaceIndex = config.InterfaceIndex;
            CallbackContext = config.CallbackContext;
            if (Partition >= CxPlatWorkerPoolGetCount(path.Workers))
                throw new ArgumentException("Invalid worker partition.");

            Remote = config.RemoteAddress == null ? null : DatagramEndpoint(config.RemoteAddress);
            if (Remote != null && IsWildcard(Remote.Address))
                throw new ArgumentException("Remote endpoint must not be wildcard.");

            var local = config.LocalAddress == null || QuicAddrGetFamily(config.LocalAddress) == QUIC_ADDRESS_FAMILY_UNSPEC ? new IPEndPoint(Remote?.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0) : DatagramEndpoint(config.LocalAddress);
            _queue = CxPlatWorkerPoolGetEventQ(path.Workers, Partition);

            Socket? socket = null;
            try
            {
                socket = CreateSocket(local);
                if (Remote != null)
                    socket.Connect(MapEndpoint(Remote, socket));

                Local = Normalize((IPEndPoint)socket.LocalEndPoint!);
                Physical.Add(new DatagramPhysical(this, socket));
                path.AddSocket();
                _counted = true;
            }
            catch
            {
                socket?.Dispose();
                throw;
            }
        }

        internal void Start()
        {
            _notification = (DatagramNotification*)Path.Host.AllocatePlatformMemory((ulong)sizeof(DatagramNotification), DatagramAllocationTag);
            if (_notification == null)
                throw new OutOfMemoryException();

            _notification->Context = Path.Host.ContextPointer;
            _notification->Socket = Token;
            if (PlatformSqeInitialize(Path.Host.ContextPointer, _queue, &DatagramDispatch, &_notification->Sqe) == 0)
                throw new OutOfMemoryException();

            _registered = true;
            foreach (var entry in Physical.ToArray())
            {
                entry.Thread.Start();
                entry.Started = true;
            }
        }

        private Socket CreateSocket(IPEndPoint local)
        {
            var socket = new Socket(local.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                if (socket.AddressFamily == AddressFamily.InterNetworkV6)
                    socket.DualMode = local.Address.Equals(IPAddress.IPv6Any);

                socket.SetSocketOption(socket.AddressFamily == AddressFamily.InterNetwork ? SocketOptionLevel.IP : SocketOptionLevel.IPv6, SocketOptionName.PacketInformation, true);
                if (socket.AddressFamily == AddressFamily.InterNetworkV6 && socket.DualMode)
                    socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.PacketInformation, true);
                if (socket.AddressFamily == AddressFamily.InterNetwork)
                    socket.DontFragment = true;

                ApplyDatagramInterface(socket, InterfaceIndex);
                socket.Bind(local);
                return socket;
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }

        internal Socket SelectSocket(IPEndPoint local)
        {
            lock (Gate)
            {
                if (_closing)
                    throw new ObjectDisposedException("UDP socket");
                if (local.Port != 0 && local.Port != Local.Port)
                    throw new ArgumentException("Route changed binding port.");

                if (!IsWildcard(Local.Address))
                {
                    if (!IsWildcard(local.Address) && !local.Address.Equals(Local.Address))
                        throw new ArgumentException("Route changed explicitly bound source.");

                    return Physical[0].Socket;
                }

                if (IsWildcard(local.Address))
                    throw new ArgumentException("An outbound route needs a concrete source address.");

                foreach (var item in Physical)
                {
                    if (Normalize((IPEndPoint)item.Socket.LocalEndPoint!).Address.Equals(local.Address))
                        return item.Socket;
                }

                var socket = CreateSocket(new IPEndPoint(local.Address, Local.Port));
                try
                {
                    var entry = new DatagramPhysical(this, socket);
                    Physical.Add(entry);
                    entry.Thread.Start();
                    entry.Started = true;
                    return socket;
                }
                catch
                {
                    Physical.RemoveAll(item => ReferenceEquals(item.Socket, socket));
                    socket.Dispose();
                    throw;
                }
            }
        }

        private static IPEndPoint Normalize(IPEndPoint endpoint) => endpoint.Address.IsIPv4MappedToIPv6 ? new IPEndPoint(endpoint.Address.MapToIPv4(), endpoint.Port) : endpoint;
        internal static IPEndPoint MapEndpoint(IPEndPoint endpoint, Socket socket) => socket.AddressFamily == AddressFamily.InterNetworkV6 && endpoint.AddressFamily == AddressFamily.InterNetwork ? new IPEndPoint(endpoint.Address.MapToIPv6(), endpoint.Port) : endpoint;

        internal void Receive(DatagramPhysical entry)
        {
            try
            {
                while (true)
                {
                    lock (Gate)
                    {
                        if (_closing)
                            return;
                    }

                    DatagramReceive? packet = null;
                    try
                    {
                        packet = Path.Rent();
                        ObserveBeforeDatagramReceive();
                        EndPoint peer = new IPEndPoint(entry.Socket.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0);
                        var result = entry.Socket.ReceiveMessageFromAsync(packet.Memory.Memory, SocketFlags.None, peer).AsTask().GetAwaiter().GetResult();
                        var length = result.ReceivedBytes;
                        var flags = result.SocketFlags;
                        var info = result.PacketInformation;
                        peer = result.RemoteEndPoint;

                        if ((flags & SocketFlags.Truncated) != 0)
                        {
                            Interlocked.Increment(ref Path.Host._datagramTruncations);
                            Path.Return(packet);
                            packet = null;
                            continue;
                        }

                        var remote = Normalize((IPEndPoint)peer);
                        var address = info.Address.IsIPv4MappedToIPv6 ? info.Address.MapToIPv4() : info.Address;
                        if (info.Interface <= 0 || IsWildcard(address))
                        {
                            Interlocked.Increment(ref Path.Host._datagramReceiveErrors);
                            Path.Return(packet);
                            packet = null;
                            continue;
                        }

                        if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.IsIPv6LinkLocal && address.ScopeId == 0)
                            address = new IPAddress(address.GetAddressBytes(), info.Interface);

                        DatagramAddress(remote, &packet.Route->RemoteAddress);
                        DatagramAddress(new IPEndPoint(address, Local.Port), &packet.Route->LocalAddress);
                        packet.Route->LocalAddress.Ipv6.sin6_scope_id = checked((uint)info.Interface);
                        packet.Route->State = CXPLAT_ROUTE_STATE.RouteResolved;
                        packet.Route->DatapathType = 1;
                        packet.Data->BufferLength = checked((ushort)length);
                        packet.Data->PartitionIndex = Partition;

                        lock (Gate)
                        {
                            if (_closing)
                            {
                                Path.Return(packet);
                                packet = null;
                                return;
                            }

                            if (_received.Count == 256)
                            {
                                Interlocked.Increment(ref Path.Host._datagramReceiveErrors);
                                Path.Return(packet);
                                packet = null;
                                continue;
                            }

                            if (!Path.Host._datagramReceives.TryAdd((nint)packet.Data, packet))
                                FatalInvariant("Receive pointer already leased.");

                            _received.Enqueue(packet);
                            packet = null;
                            if (PlatformQueueEnqueue(Path.Host.ContextPointer, _queue, &_notification->Sqe) == 0)
                                FatalInvariant("Live datapath notification rejected.");
                        }
                    }
                    catch (SocketException error)
                    {
                        if (packet != null)
                            Path.Return(packet);

                        lock (Gate)
                        {
                            if (_closing) return;
                        }

                        if (error.SocketErrorCode == SocketError.MessageSize)
                        {
                            Interlocked.Increment(ref Path.Host._datagramTruncations);
                        }
                        else if (error.SocketErrorCode is SocketError.ConnectionRefused or SocketError.HostUnreachable or SocketError.NetworkUnreachable)
                        {
                            if (Remote != null) NotifyUnreachable(Remote);
                        }
                        else
                        {
                            Interlocked.Increment(ref Path.Host._datagramReceiveErrors);
                            Thread.Sleep(1);
                        }
                    }
                    catch (ObjectDisposedException)
                    {
                        if (packet != null)
                            Path.Return(packet);

                        lock (Gate)
                        {
                            if (_closing)
                                return;
                        }

                        throw;
                    }
                    catch (OutOfMemoryException)
                    {
                        if (packet != null)
                            FatalInvariant("Unable to retain an asynchronous receive operation after submission.");

                        Interlocked.Increment(ref Path.Host._datagramReceiveErrors);
                        Thread.Sleep(1);
                    }
                }
            }
            catch (Exception error)
            {
                FatalInvariant("UDP receive pump failed: " + error);
            }
        }

        internal void NotifyUnreachable(IPEndPoint remote)
        {
            lock (Gate)
            {
                if (_closing) return;
                if (_unreachable.Count == 64)
                    return; // Repeated network-error hints may coalesce; packets never do.

                _unreachable.Enqueue(remote);
                if (PlatformQueueEnqueue(Path.Host.ContextPointer, _queue, &_notification->Sqe) == 0)
                    FatalInvariant("Unreachable notification rejected.");
            }
        }

        internal void Dispatch()
        {
            while (true)
            {
                DatagramReceive? packet = null;
                IPEndPoint? remote = null;
                lock (Gate)
                {
                    if (_closing)
                        return;

                    if (_received.Count != 0)
                        packet = _received.Dequeue();
                    else if (_unreachable.Count != 0)
                        remote = _unreachable.Dequeue();
                    else
                        return;

                    _callbackThread = Environment.CurrentManagedThreadId;
                }

                try
                {
                    if (packet != null)
                    {
                        Path.Callbacks.Receive((CXPLAT_SOCKET*)Token, CallbackContext, packet.Data);
                    }
                    else
                    {
                        QUIC_ADDR address;
                        DatagramAddress(remote!, &address);
                        Path.Callbacks.Unreachable((CXPLAT_SOCKET*)Token, CallbackContext, &address);
                    }
                }
                finally
                {
                    lock (Gate)
                    {
                        _callbackThread = 0;
                        Monitor.PulseAll(Gate);
                    }
                }
            }
        }

        internal void BeginSend()
        {
            lock (Gate)
            {
                if (_closing)
                    throw new ObjectDisposedException("socket");

                _activeSends++;
            }
        }

        internal void EndSend()
        {
            lock (Gate)
            {
                if (--_activeSends < 0)
                    FatalInvariant("Negative pending send count.");

                Monitor.PulseAll(Gate);
            }
        }

        public void Dispose() => Close(false);

        internal void Close(bool releaseToken)
        {
            DatagramPhysical[] entries;
            lock (Gate)
            {
                if (_disposed) return;

                if (_callbackThread == Environment.CurrentManagedThreadId)
                    FatalInvariant("Socket deletion must be deferred outside its callback.");

                if (_closing)
                {
                    while (!_disposed) Monitor.Wait(Gate);
                    return;
                }

                _closing = true;
                entries = Physical.ToArray();
            }

            if (_counted)
                Path.BeginSocketClose();

            foreach (var entry in entries)
                entry.Socket.Dispose();

            foreach (var entry in entries)
            {
                if (entry.Started)
                    entry.Thread.Join();
            }

            lock (Gate)
            {
                while (_activeSends != 0 || _callbackThread != 0)
                    Monitor.Wait(Gate);
            }

            lock (Gate)
            {
                while (_received.Count != 0)
                    ReturnDatagram(Path.Host, _received.Dequeue().Data);

                _unreachable.Clear();
            }

            if (_registered)
                PlatformSqeCleanupDeferred(Path.Host.ContextPointer, _queue, &_notification->Sqe, () => FinishClose(releaseToken));

            else FinishClose(releaseToken);
        }

        private void FinishClose(bool releaseToken)
        {
            if (_notification != null)
                Path.Host.FreePlatformMemory(_notification, DatagramAllocationTag);

            if (_counted)
                Path.RemoveSocket();

            lock (Gate)
            {
                _disposed = true;
                Monitor.PulseAll(Gate);
            }

            if (releaseToken)
                Path.Host.ReleaseResource<DatagramSocket>(Token);
        }
    }

    private static void DatagramDispatch(CXPLAT_CQE* completion)
    {
        try
        {
            var notification = (DatagramNotification*)completion->Sqe;
            var host = FromContext(notification->Context);
            host.Resource<DatagramSocket>(notification->Socket).Dispatch();
        }
        catch (Exception error)
        {
            FatalInvariant("UDP worker completion failed: " + error);
        }
    }

    private static void ReturnDatagram(MsQuicHost host, CXPLAT_RECV_DATA* packet)
    {
        if (!host._datagramReceives.TryRemove((nint)packet, out var owner))
            FatalInvariant("Unknown or already returned receive buffer.");

        owner.Path.Return(owner);
    }

    private static void DatapathReceiveReturn(void* context, CXPLAT_RECV_DATA* chain)
    {
        try
        {
            var host = FromContext(context);
            while (chain != null)
            {
                var next = chain->Next;
                ReturnDatagram(host, chain);
                chain = next;
            }
        }
        catch (Exception error)
        {
            FatalInvariant(error.ToString());
        }
    }
}

// Memory is backed by the platform's pinned allocation registry. The receive
// owner stays rented until the Socket operation completes, including cancellation.
internal sealed unsafe class DatagramMemory(nint address, int length) : MemoryManager<byte>
{
    public override Span<byte> GetSpan() => new Span<byte>((void*)address, length);

    public override MemoryHandle Pin(int elementIndex = 0)
    {
        if ((uint)elementIndex > (uint)length)
            throw new ArgumentOutOfRangeException(nameof(elementIndex));

        return new MemoryHandle((byte*)address + elementIndex);
    }

    public override void Unpin() { }
    protected override void Dispose(bool disposing) { }
}