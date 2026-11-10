namespace Smb.Server.Diagnostics;

public interface ISmbAuditLogger
{
    bool IsEnabled(SmbLogLevel level);

    void Log(in SmbAuditEvent auditEvent);
}
