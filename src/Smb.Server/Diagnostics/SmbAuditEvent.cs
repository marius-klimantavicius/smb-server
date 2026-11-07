using System;
using System.Text;
using Smb.Protocol.Enums;

namespace Smb.Server.Diagnostics;

public readonly record struct SmbAuditEvent
{
	public required SmbAuditEventType EventType { get; init; }

	public SmbLogLevel Level { get; init; }

	public DateTimeOffset Timestamp { get; init; }

	public string? User { get; init; }

	public string? ClientAddress { get; init; }

	public string? Share { get; init; }

	public string? Path { get; init; }

	public NtStatus Status { get; init; }

	public string? Message { get; init; }

	public int EventId => (int)EventType;

	public override string ToString()
	{
		var stringBuilder = new StringBuilder(128);
		stringBuilder.Append(Timestamp.ToString("yyyy-MM-ddTHH:mm:ss.fffzzz")).Append(" [").Append(Level)
			.Append("] ")
			.Append(EventId)
			.Append(' ')
			.Append(EventType);
		if (User != null)
		{
			stringBuilder.Append(" user=").Append(User);
		}

		if (ClientAddress != null)
		{
			stringBuilder.Append(" client=").Append(ClientAddress);
		}

		if (Share != null)
		{
			stringBuilder.Append(" share=").Append(Share);
		}

		if (Path != null)
		{
			stringBuilder.Append(" path=").Append(Path);
		}

		if (Status != NtStatus.Success)
		{
			stringBuilder.Append(" status=").Append(Status);
		}

		if (Message != null)
		{
			stringBuilder.Append(" msg=").Append(Message);
		}

		return stringBuilder.ToString();
	}
}
