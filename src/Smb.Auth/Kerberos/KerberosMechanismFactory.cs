using System;

namespace Smb.Auth.Kerberos;

public sealed class KerberosMechanismFactory : IGssMechanismFactory
{
    private readonly IKerberosTicketValidator _validator;

    private readonly string _mechOid;

    public string MechOid => _mechOid;

    public KerberosMechanismFactory(IKerberosTicketValidator validator, string mechOid = "1.2.840.113554.1.2.2")
    {
        _validator = validator ?? throw new ArgumentNullException(nameof(validator));
        _mechOid = mechOid;
    }

    public IGssMechanism Create()
    {
        return new KerberosServerMechanism(_validator, _mechOid);
    }
}
