using System;

namespace Smb.Server.Diagnostics;

public sealed class DelegatingSmbAuditLogger : ISmbAuditLogger
{
	private readonly Action<SmbAuditEvent> _sink;

	public SmbLogLevel MinLevel { get; }

	public DelegatingSmbAuditLogger(Action<SmbAuditEvent> sink, SmbLogLevel minLevel = SmbLogLevel.Information)
	{
		_sink = sink ?? throw new ArgumentNullException(nameof(sink));
		MinLevel = minLevel;
	}

	public bool IsEnabled(SmbLogLevel level)
	{
		return level >= MinLevel;
	}

	public void Log(in SmbAuditEvent auditEvent)
	{
		if (IsEnabled(auditEvent.Level))
		{
			_sink(auditEvent);
		}
	}

	void ISmbAuditLogger.Log(in SmbAuditEvent auditEvent)
	{
		Log(in auditEvent);
	}
}
