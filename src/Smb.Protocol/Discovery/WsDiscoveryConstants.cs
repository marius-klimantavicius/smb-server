namespace Smb.Protocol.Discovery;

public static class WsDiscoveryConstants
{
	public const string SoapNs = "http://www.w3.org/2003/05/soap-envelope";

	public const string WsaNs = "http://schemas.xmlsoap.org/ws/2004/08/addressing";

	public const string WsdNs = "http://schemas.xmlsoap.org/ws/2005/04/discovery";

	public const string MulticastAddressV4 = "239.255.255.250";

	public const string MulticastAddressV6 = "FF02::C";

	public const int Port = 3702;

	public const string DiscoveryTo = "urn:schemas-xmlsoap-org:ws:2005:04:discovery";

	public const string AnonymousTo = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous";

	public const string ProbeAction = "http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe";

	public const string ProbeMatchesAction = "http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches";

	public const string ResolveAction = "http://schemas.xmlsoap.org/ws/2005/04/discovery/Resolve";

	public const string ResolveMatchesAction = "http://schemas.xmlsoap.org/ws/2005/04/discovery/ResolveMatches";

	public const string HelloAction = "http://schemas.xmlsoap.org/ws/2005/04/discovery/Hello";

	public const string ByeAction = "http://schemas.xmlsoap.org/ws/2005/04/discovery/Bye";
}
