using System;

namespace Smb.Auth.Ntlm;

public sealed class NtlmServerOptions
{
    public string NetbiosDomainName { get; set; } = "WORKGROUP";

    public string NetbiosComputerName { get; set; } = Environment.MachineName.ToUpperInvariant();

    public string DnsDomainName { get; set; } = "workgroup";

    public string DnsComputerName { get; set; } = Environment.MachineName.ToLowerInvariant();

    public bool RequireMessageIntegrity { get; set; }
}
