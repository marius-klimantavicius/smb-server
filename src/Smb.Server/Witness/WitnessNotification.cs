namespace Smb.Server.Witness;

public sealed class WitnessNotification
{
    public required WitnessNotifyType Type { get; init; }

    public required int MessageCount { get; init; }

    public required byte[] MessageBuffer { get; init; }
}
