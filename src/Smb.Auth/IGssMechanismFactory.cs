namespace Smb.Auth;

public interface IGssMechanismFactory
{
	string MechOid { get; }

	IGssMechanism Create();
}
