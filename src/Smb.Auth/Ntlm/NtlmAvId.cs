namespace Smb.Auth.Ntlm;

public enum NtlmAvId : ushort
{
	EOL,
	NbComputerName,
	NbDomainName,
	DnsComputerName,
	DnsDomainName,
	DnsTreeName,
	Flags,
	Timestamp,
	SingleHost,
	TargetName,
	ChannelBindings,
}
