using System;

namespace Smb.Server.Witness;

public sealed class WitnessRegistration
{
	public required Guid Id { get; init; }

	public required Guid ConnectionId { get; init; }

	public required uint Version { get; init; }

	public string? NetName { get; init; }

	public string? ShareName { get; init; }

	public string? IpAddress { get; init; }

	public string? ClientComputerName { get; init; }

	public WitnessNotificationChannel Notifications { get; } = new WitnessNotificationChannel();

	public byte[] ContextHandle()
	{
		var array = new byte[20];
		Id.TryWriteBytes(array.AsSpan(4));
		return array;
	}
}
