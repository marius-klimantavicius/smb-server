namespace Smb.Protocol.Enums;

public static class SmbDialectExtensions
{
	public static bool IsSmb3OrLater(this SmbDialect dialect)
	{
		if (dialect == SmbDialect.Smb300 || dialect == SmbDialect.Smb302 || dialect == SmbDialect.Smb311)
		{
			return true;
		}
		return false;
	}

	public static bool SupportsLargeMtu(this SmbDialect dialect)
	{
		if (dialect != SmbDialect.None)
		{
			return dialect != SmbDialect.Smb202;
		}
		return false;
	}

	public static bool UsesNegotiateContexts(this SmbDialect dialect)
	{
		return dialect == SmbDialect.Smb311;
	}
}
