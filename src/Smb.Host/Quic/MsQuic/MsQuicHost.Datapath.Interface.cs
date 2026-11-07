using System;
using System.Buffers.Binary;
using System.Net.Sockets;

namespace Managed.Transport.Hosting;

public sealed unsafe partial class MsQuicHost
{
    private static void ApplyDatagramInterface(Socket socket, uint index)
    {
        if (index == 0)
            return;

        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("UDP interface selection is qualified only for Linux.");

        // BCL SetRawSocketOption is intended for options missing from its enum.
        // Linux UAPI: IP_UNICAST_IF=50, IPV6_UNICAST_IF=76. BOTH consume network
        // byte order; do not apply the different Windows IPv6 convention here.
        // net/ipv4/ip_sockglue.c and net/ipv6/ipv6_sockglue.c, *_UNICAST_IF cases:
        // https://github.com/torvalds/linux/blob/v6.12/net/ipv6/ipv6_sockglue.c
        Span<byte> value = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(value, index);

        if (socket.AddressFamily == AddressFamily.InterNetworkV6)
            socket.SetRawSocketOption(41, 76, value); // IPPROTO_IPV6
        if (socket.AddressFamily == AddressFamily.InterNetwork || socket.DualMode)
            socket.SetRawSocketOption(0, 50, value); // IPPROTO_IP
    }
}