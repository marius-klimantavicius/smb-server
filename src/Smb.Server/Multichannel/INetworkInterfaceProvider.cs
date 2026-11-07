using System.Collections.Generic;
using Smb.Protocol.Messages;

namespace Smb.Server.Multichannel;

public interface INetworkInterfaceProvider
{
	IReadOnlyList<NetworkInterfaceInfo> GetInterfaces();
}
