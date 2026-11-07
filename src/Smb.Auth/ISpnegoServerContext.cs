using System;

namespace Smb.Auth;

public interface ISpnegoServerContext
{
	GssResult Accept(ReadOnlySpan<byte> spnegoToken);
}
