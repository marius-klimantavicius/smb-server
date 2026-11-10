using System;
using Smb.Protocol.Enums;

namespace Smb.Auth.Kerberos;

public sealed class KerberosServerMechanism : IGssMechanism
{
    private readonly IKerberosTicketValidator _validator;

    private bool _complete;

    public string MechOid { get; }

    public bool IsComplete => _complete;

    public KerberosServerMechanism(IKerberosTicketValidator validator, string mechOid = "1.2.840.113554.1.2.2")
    {
        _validator = validator ?? throw new ArgumentNullException(nameof(validator));
        MechOid = mechOid;
    }

    public GssResult Accept(ReadOnlySpan<byte> inToken)
    {
        _complete = true;
        if (inToken.IsEmpty)
        {
            return GssResult.Failed(NtStatus.InvalidParameter);
        }

        var array = (KerberosGssToken.TryReadApReq(inToken, out var apReq) ? apReq : inToken.ToArray());
        var kerberosValidationResult = _validator.Validate(array);
        if (!kerberosValidationResult.IsSuccess)
        {
            return GssResult.Failed(kerberosValidationResult.Status);
        }

        var sessionKey = kerberosValidationResult.SessionKey;
        if (sessionKey == null || sessionKey.Length <= 0 || kerberosValidationResult.Identity == null)
        {
            return GssResult.Failed();
        }

        var apRep = kerberosValidationResult.ApRep;
        var outToken = (apRep != null && apRep.Length > 0) ? KerberosGssToken.WrapApRep(apRep) : null;
        return GssResult.Succeeded(kerberosValidationResult.SessionKey!, kerberosValidationResult.Identity, outToken);
    }
}
