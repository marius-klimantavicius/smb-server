using static Managed.Transport.MsQuic;
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Managed.Transport.Hosting;

public sealed unsafe partial class MsQuicHost
{
    private sealed class DatagramSend : IDisposable
    {
        private int _submitted, _disposed;

        internal readonly DatagramSocket Socket;
        internal readonly ushort Maximum;
        internal QUIC_BUFFER* Buffer;
        internal byte[]? Payload;
        internal void* Token;
        internal IPEndPoint? Remote;
        internal bool Submitted => Volatile.Read(ref _submitted) != 0;

        internal DatagramSend(DatagramSocket socket, ushort maximum)
        {
            Socket = socket;
            Maximum = maximum;
        }

        internal QUIC_BUFFER* Allocate(ushort length)
        {
            if (Buffer != null || length == 0 || length > Maximum || Volatile.Read(ref _submitted) != 0)
                return null;

            var payload = GC.AllocateUninitializedArray<byte>(length, pinned: true);
            var header = (QUIC_BUFFER*)Socket.Path.Host.AllocatePlatformMemory((ulong)sizeof(QUIC_BUFFER), DatagramAllocationTag);
            if (header == null)
                return null;

            fixed (byte* data = payload) header->Buffer = data;
            header->Length = length;
            Payload = payload;
            Buffer = header;
            return header;
        }

        internal void FreeBuffer(QUIC_BUFFER* buffer)
        {
            if (buffer == null || buffer != Buffer || Volatile.Read(ref _submitted) != 0)
                FatalInvariant("Invalid send buffer release.");

            Socket.Path.Host.FreePlatformMemory(Buffer, DatagramAllocationTag);
            Buffer = null;
            Payload = null;
        }

        internal void Submit(CXPLAT_ROUTE* route)
        {
            if (Interlocked.Exchange(ref _submitted, 1) != 0 || Buffer == null || Payload == null || Buffer->Length > Payload.Length)
                FatalInvariant("Invalid UDP send submission.");

            var admitted = false;
            try
            {
                Remote = DatagramEndpoint(&route->RemoteAddress);
                var local = DatagramEndpoint(&route->LocalAddress);
                var physical = Socket.SelectSocket(local);
                Socket.BeginSend();
                admitted = true;
                DatagramAsync.Send(physical, Payload.AsMemory(0, checked((int)Buffer->Length)), DatagramSocket.MapEndpoint(Remote, physical), Complete);
            }
            catch (Exception error)
            {
                if (admitted)
                {
                    Complete(error);
                }
                else
                {
                    Interlocked.Increment(ref Socket.Path.Host._datagramSendErrors);
                    Socket.Path.Host.ReleaseResource<DatagramSend>(Token);
                }
            }
        }

        private void Complete(Exception? error)
        {
            try
            {
                if (error != null)
                {
                    Interlocked.Increment(ref Socket.Path.Host._datagramSendErrors);
                    if (error is SocketException { SocketErrorCode: SocketError.ConnectionRefused or SocketError.HostUnreachable or SocketError.NetworkUnreachable })
                        Socket.NotifyUnreachable(Remote!);
                }

                Socket.Path.Host.ReleaseResource<DatagramSend>(Token);
            }
            catch (Exception failure)
            {
                FatalInvariant("UDP send completion failed: " + failure);
            }
            finally
            {
                Socket.EndSend();
            }
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
                return;

            if (Buffer != null)
                Socket.Path.Host.FreePlatformMemory(Buffer, DatagramAllocationTag);

            Buffer = null;
            Payload = null;
        }
    }

    private static CXPLAT_SEND_DATA* DatapathSendAlloc(void* context, CXPLAT_SOCKET* socket, CXPLAT_SEND_CONFIG* config)
    {
        if (config == null || config->ECN != 0 || config->DSCP != 0 || (config->Flags & ~(byte)CXPLAT_SEND_FLAGS.CXPLAT_SEND_FLAGS_MAX_THROUGHPUT) != 0 || config->MaxPacketSize > DatagramMaxPayload)
            return null;

        try
        {
            var host = FromContext(context);
            // MaxPacketSize is a segmentation hint. Upstream deliberately uses
            // zero for PMTU probes and stateless responses; the native datapath
            // ignores this hint when segmentation is unavailable. Bound actual
            // allocations by our supported UDP payload size instead.
            var send = new DatagramSend(host.Resource<DatagramSocket>(socket), DatagramMaxPayload);
            send.Token = host.AddResource(send);
            return (CXPLAT_SEND_DATA*)send.Token;
        }
        catch (OutOfMemoryException)
        {
            return null;
        }
        catch (Exception error)
        {
            FatalInvariant(error.ToString());
            return null;
        }
    }

    private static QUIC_BUFFER* DatapathSendBuffer(void* context, CXPLAT_SEND_DATA* send, ushort length)
    {
        try
        {
            return FromContext(context).Resource<DatagramSend>(send).Allocate(length);
        }
        catch (OutOfMemoryException)
        {
            return null;
        }
        catch (Exception error)
        {
            FatalInvariant(error.ToString());
            return null;
        }
    }

    private static void DatapathSendFreeBuffer(void* context, CXPLAT_SEND_DATA* send, QUIC_BUFFER* buffer)
    {
        try
        {
            FromContext(context).Resource<DatagramSend>(send).FreeBuffer(buffer);
        }
        catch (Exception error)
        {
            FatalInvariant(error.ToString());
        }
    }

    private static void DatapathSendFree(void* context, CXPLAT_SEND_DATA* send)
    {
        try
        {
            var host = FromContext(context);
            if (host.Resource<DatagramSend>(send).Submitted)
                FatalInvariant("Caller freed an in-flight send.");

            host.ReleaseResource<DatagramSend>(send);
        }
        catch (Exception error)
        {
            FatalInvariant(error.ToString());
        }
    }

    private static byte DatapathSendFull(void* context, CXPLAT_SEND_DATA* send)
    {
        try
        {
            return FromContext(context).Resource<DatagramSend>(send).Buffer == null ? (byte)0 : (byte)1;
        }
        catch (Exception error)
        {
            FatalInvariant(error.ToString());
            return 1;
        }
    }

    private static void DatapathSocketSend(void* context, CXPLAT_SOCKET* socket, CXPLAT_ROUTE* route, CXPLAT_SEND_DATA* send)
    {
        try
        {
            var host = FromContext(context);
            var item = host.Resource<DatagramSend>(send);
            if (route == null || !ReferenceEquals(item.Socket, host.Resource<DatagramSocket>(socket)))
                FatalInvariant("Send submitted to a foreign socket or invalid route.");

            item.Submit(route);
        }
        catch (Exception error)
        {
            FatalInvariant(error.ToString());
        }
    }
}

// Keep await outside unsafe contexts. The Memory and completion delegate retain the
// send owner through both synchronous ValueTask completion and deferred completion.
internal static partial class DatagramAsync
{
    internal static void Send(Socket socket, ReadOnlyMemory<byte> payload, IPEndPoint remote, Action<Exception?> complete)
    {
        ValueTask<int> operation;
        try
        {
            operation = socket.SendToAsync(payload, SocketFlags.None, remote);
        }
        catch (Exception error)
        {
            complete(error);
            return;
        }

        ObserveSend(ref operation);
        if (operation.IsCompletedSuccessfully)
        {
            var bytes = operation.Result;
            complete(bytes == payload.Length ? null : new SocketException((int)SocketError.MessageSize));
        }
        else
        {
            _ = Await(operation, payload.Length, complete);
        }
    }

    // Omitted from production builds; isolated tests use it to force the deferred
    // completion path after submitting the real Socket operation.
    static partial void ObserveSend(ref ValueTask<int> operation);

    private static async Task Await(ValueTask<int> operation, int expected, Action<Exception?> complete)
    {
        Exception? failure = null;
        try
        {
            if (await operation.ConfigureAwait(false) != expected)
                failure = new SocketException((int)SocketError.MessageSize);
        }
        catch (Exception error)
        {
            failure = error;
        }

        complete(failure);
    }
}