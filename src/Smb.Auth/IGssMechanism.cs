using System;

namespace Smb.Auth;

public interface IGssMechanism
{
	string MechOid { get; }

	bool IsComplete { get; }

	GssResult Accept(ReadOnlySpan<byte> inToken);
}
