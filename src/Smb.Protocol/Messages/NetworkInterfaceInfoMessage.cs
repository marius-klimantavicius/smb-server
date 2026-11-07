using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public static class NetworkInterfaceInfoMessage
{
	public const uint FsctlQueryNetworkInterfaceInfo = 1311228u;

	public const int EntrySize = 152;

	private const int SockAddrStorageSize = 128;

	private const ushort AddressFamilyInet = 2;

	private const ushort AddressFamilyInet6 = 23;

	public static byte[] Build(IReadOnlyList<NetworkInterfaceInfo> interfaces)
	{
		var array = new byte[interfaces.Count * EntrySize];
		var w = new SpanWriter(array);
		for (var i = 0; i < interfaces.Count; i++)
		{
			var networkInterfaceInfo = interfaces[i];
			var flag = i == interfaces.Count - 1;
			w.WriteUInt32((!flag) ? (uint)EntrySize : 0u);
			w.WriteUInt32(networkInterfaceInfo.IfIndex);
			w.WriteUInt32((uint)networkInterfaceInfo.Capability);
			w.WriteUInt32(0u);
			w.WriteUInt64(networkInterfaceInfo.LinkSpeedBitsPerSecond);
			WriteSockAddrStorage(ref w, networkInterfaceInfo.Address);
		}

		return array;
	}

	private static void WriteSockAddrStorage(ref SpanWriter w, IPAddress address)
	{
		var position = w.Position;
		if (address.AddressFamily == AddressFamily.InterNetworkV6)
		{
			w.WriteUInt16(AddressFamilyInet6);
			w.WriteUInt16(0);
			w.WriteUInt32(0u);
			w.WriteBytes(address.GetAddressBytes());
			w.WriteUInt32((uint)address.ScopeId);
		}
		else
		{
			w.WriteUInt16(AddressFamilyInet);
			w.WriteUInt16(0);
			w.WriteBytes(address.GetAddressBytes());
		}

		var num = w.Position - position;
		if (num < SockAddrStorageSize)
		{
			w.WriteZeros(SockAddrStorageSize - num);
		}
	}
}
