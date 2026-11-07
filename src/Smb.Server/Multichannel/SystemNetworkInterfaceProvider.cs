using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Smb.Protocol.Messages;

namespace Smb.Server.Multichannel;

public sealed class SystemNetworkInterfaceProvider : INetworkInterfaceProvider
{
	private const ulong DefaultLinkSpeed = 1000000000uL;

	public IReadOnlyList<NetworkInterfaceInfo> GetInterfaces()
	{
		var list = new List<NetworkInterfaceInfo>();
		var allNetworkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
		foreach (var networkInterface in allNetworkInterfaces)
		{
			if (networkInterface.OperationalStatus != OperationalStatus.Up || networkInterface.NetworkInterfaceType == NetworkInterfaceType.Loopback)
			{
				continue;
			}

			var iPProperties = networkInterface.GetIPProperties();
			var linkSpeedBitsPerSecond = (ulong)((networkInterface.Speed > 0) ? networkInterface.Speed : (long)DefaultLinkSpeed);
			foreach (var unicastAddress in iPProperties.UnicastAddresses)
			{
				var address = unicastAddress.Address;
				if (!IPAddress.IsLoopback(address))
				{
					var ifIndex = InterfaceIndex(iPProperties, address.AddressFamily);
					list.Add(new NetworkInterfaceInfo(ifIndex, NetworkInterfaceCapability.None, linkSpeedBitsPerSecond, address));
				}
			}
		}

		return list;
	}

	private static uint InterfaceIndex(IPInterfaceProperties props, AddressFamily family)
	{
		try
		{
			return (uint)((family == AddressFamily.InterNetworkV6) ? props.GetIPv6Properties().Index : props.GetIPv4Properties().Index);
		}
		catch (NetworkInformationException)
		{
			return 0u;
		}
	}
}
