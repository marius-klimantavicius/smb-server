using System;

namespace Smb.Server.Rpc;

public interface IRpcEndpoint
{
    byte[] HandlePdu(ReadOnlySpan<byte> pdu);
}
