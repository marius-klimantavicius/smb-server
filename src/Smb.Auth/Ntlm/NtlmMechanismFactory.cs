using System;

namespace Smb.Auth.Ntlm;

public sealed class NtlmMechanismFactory : IGssMechanismFactory
{
	private readonly IIdentityBackend _backend;

	private readonly NtlmServerOptions _options;

	public string MechOid => "1.3.6.1.4.1.311.2.2.10";

	public NtlmMechanismFactory(IIdentityBackend backend, NtlmServerOptions? options = null)
	{
		_backend = backend ?? throw new ArgumentNullException(nameof(backend));
		_options = options ?? new NtlmServerOptions();
	}

	public IGssMechanism Create()
	{
		return new NtlmServerMechanism(_backend, _options);
	}
}
