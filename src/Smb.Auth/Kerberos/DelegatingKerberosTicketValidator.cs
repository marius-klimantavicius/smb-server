using System;

namespace Smb.Auth.Kerberos;

public sealed class DelegatingKerberosTicketValidator : IKerberosTicketValidator
{
    public delegate KerberosValidationResult ValidateCallback(ReadOnlySpan<byte> apReq);

    private readonly ValidateCallback _validate;

    public DelegatingKerberosTicketValidator(ValidateCallback validate)
    {
        _validate = validate ?? throw new ArgumentNullException(nameof(validate));
    }

    public KerberosValidationResult Validate(ReadOnlySpan<byte> apReq)
    {
        return _validate(apReq);
    }
}
