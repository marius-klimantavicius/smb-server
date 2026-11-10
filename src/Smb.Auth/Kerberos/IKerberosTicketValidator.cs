using System;

namespace Smb.Auth.Kerberos;

public interface IKerberosTicketValidator
{
    KerberosValidationResult Validate(ReadOnlySpan<byte> apReq);
}
