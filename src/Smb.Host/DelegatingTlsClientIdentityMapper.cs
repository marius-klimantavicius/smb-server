using System;
using System.Security.Cryptography.X509Certificates;
using Smb.Auth;

namespace Smb.Host;

/// <summary>Adapts a delegate to <see cref="T:Smb.Host.ITlsClientIdentityMapper" /> for inline wiring.</summary>
public sealed class DelegatingTlsClientIdentityMapper(Func<X509Certificate2, SecurityIdentity?> map) : ITlsClientIdentityMapper
{
	private readonly Func<X509Certificate2, SecurityIdentity?> _map = map ?? throw new ArgumentNullException("map");

	public SecurityIdentity? Map(X509Certificate2 clientCertificate)
	{
		return _map(clientCertificate);
	}
}
