namespace Smb.Auth.Ntlm;

public sealed class NtlmSpnegoNegotiator : ISpnegoNegotiator
{
	private readonly SpnegoNegotiator _inner;

	public NtlmSpnegoNegotiator(IIdentityBackend backend, NtlmServerOptions? options = null)
	{
		_inner = new SpnegoNegotiator(new NtlmMechanismFactory(backend, options));
	}

	public byte[] CreateInitialServerToken()
	{
		return _inner.CreateInitialServerToken();
	}

	public ISpnegoServerContext CreateServerContext()
	{
		return _inner.CreateServerContext();
	}
}
