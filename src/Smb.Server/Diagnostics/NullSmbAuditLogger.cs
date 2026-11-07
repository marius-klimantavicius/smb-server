namespace Smb.Server.Diagnostics;

public sealed class NullSmbAuditLogger : ISmbAuditLogger
{
	public static readonly NullSmbAuditLogger Instance = new NullSmbAuditLogger();

	private NullSmbAuditLogger()
	{
	}

	public bool IsEnabled(SmbLogLevel level)
	{
		return false;
	}

	public void Log(in SmbAuditEvent auditEvent)
	{
	}

	void ISmbAuditLogger.Log(in SmbAuditEvent auditEvent)
	{
		Log(in auditEvent);
	}
}
