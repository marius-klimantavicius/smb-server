// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using static Managed.Transport.MsQuic;

namespace Managed.Net.Quic;

internal static class MsQuicHelpers
{
    internal static bool TryParse(this EndPoint endPoint, out string? host, out IPAddress? address, out int port)
    {
        if (endPoint is DnsEndPoint dnsEndPoint)
        {
            host = IPAddress.TryParse(dnsEndPoint.Host, out address) ? null : dnsEndPoint.Host;
            port = dnsEndPoint.Port;
            return true;
        }

        if (endPoint is IPEndPoint ipEndPoint)
        {
            host = null;
            address = ipEndPoint.Address;
            port = ipEndPoint.Port;
            return true;
        }

        host = default;
        address = default;
        port = default;
        return false;
    }

    internal static unsafe IPEndPoint QuicAddrToIPEndPoint(QUIC_ADDR* quicAddress, AddressFamily? addressFamilyOverride = null)
    {
        var familiy = QuicAddrGetFamily(quicAddress);
        if (familiy == QUIC_ADDRESS_FAMILY_INET) // IPv4
        {
            var port = QuicAddrGetPort(quicAddress);
            return new IPEndPoint(new IPAddress(quicAddress->Ipv4.sin_addr.s_addr), port);
        }

        if (familiy == QUIC_ADDRESS_FAMILY_INET6) // IPv6
        {
            var port = QuicAddrGetPort(quicAddress);
            return new IPEndPoint(new IPAddress(new ReadOnlySpan<byte>(quicAddress->Ipv6.sin6_addr.__in6_u.__u6_addr8, 16), quicAddress->Ipv6.sin6_scope_id), port);
        }

        throw new NotSupportedException($"Unsupported address family: {familiy}");
    }

    internal static unsafe QUIC_ADDR ToQuicAddr(this IPEndPoint ipEndPoint)
    {
        if (ipEndPoint.AddressFamily == AddressFamily.InterNetwork)
        {
            var quicAddr = new QUIC_ADDR();
            quicAddr.Ipv4.sin_family = QUIC_ADDRESS_FAMILY_INET;
            quicAddr.Ipv4.sin_port = (ushort)IPAddress.HostToNetworkOrder((short)ipEndPoint.Port);

            var a = &quicAddr.Ipv4.sin_addr.s_addr;
            var success = ipEndPoint.Address.TryWriteBytes(new Span<byte>(a, 4), out _);
            Debug.Assert(success, "Failed to write IPv4 address bytes to QUIC_ADDR");

            return quicAddr;
        }

        if (ipEndPoint.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var quicAddr = new QUIC_ADDR();
            quicAddr.Ipv6.sin6_family = QUIC_ADDRESS_FAMILY_INET6;
            quicAddr.Ipv6.sin6_port = (ushort)IPAddress.HostToNetworkOrder((short)ipEndPoint.Port);
            quicAddr.Ipv6.sin6_scope_id = (uint)ipEndPoint.Address.ScopeId;

            var success = ipEndPoint.Address.TryWriteBytes(new Span<byte>(quicAddr.Ipv6.sin6_addr.__in6_u.__u6_addr8, 16), out _);
            Debug.Assert(success, "Failed to write IPv6 address bytes to QUIC_ADDR");

            return quicAddr;
        }

        throw new NotSupportedException($"Unsupported address family: {ipEndPoint.AddressFamily}");
    }

    internal static unsafe T GetMsQuicParameter<T>(MsQuicSafeHandle handle, uint parameter) where T : unmanaged
    {
        T value;
        GetMsQuicParameter(handle, parameter, (uint)sizeof(T), (byte*)&value);
        return value;
    }

    internal static unsafe void GetMsQuicParameter(MsQuicSafeHandle handle, uint parameter, uint length, byte* value)
    {
        var status = MsQuicApi.Api.GetParam(handle, parameter, &length, value);

        if (MsQuicApi.StatusFailed(status))
        {
            ThrowHelper.ThrowMsQuicException(status, $"GetParam({handle}, {parameter}) failed");
        }
    }

    internal static unsafe void SetMsQuicParameter<T>(MsQuicSafeHandle handle, uint parameter, T value) where T : unmanaged
    {
        SetMsQuicParameter(handle, parameter, (uint)sizeof(T), (byte*)&value);
    }

    internal static unsafe void SetMsQuicParameter(MsQuicSafeHandle handle, uint parameter, uint length, byte* value)
    {
        var status = MsQuicApi.Api.SetParam(handle, parameter, length, value);

        if (MsQuicApi.StatusFailed(status))
        {
            ThrowHelper.ThrowMsQuicException(status, $"SetParam({handle}, {parameter}) failed");
        }
    }
}