namespace Smb.Auth;

public interface ISpnegoNegotiator
{
	byte[] CreateInitialServerToken();

	ISpnegoServerContext CreateServerContext();
}
