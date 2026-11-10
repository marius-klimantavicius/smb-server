namespace Smb.Protocol.Discovery;

public readonly record struct WsDiscoveryQName(string Namespace, string LocalName, string Prefix)
{
    public string Clark => "{" + Namespace + "}" + LocalName;

    public static readonly WsDiscoveryQName Computer = new WsDiscoveryQName("http://schemas.microsoft.com/windows/pub/2005/07", "Computer", "pub");

    public static readonly WsDiscoveryQName Device = new WsDiscoveryQName("http://schemas.xmlsoap.org/ws/2006/02/devprof", "Device", "wsdp");
}
