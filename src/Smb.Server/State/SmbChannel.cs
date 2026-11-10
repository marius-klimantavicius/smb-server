namespace Smb.Server.State;

public sealed class SmbChannel
{
    public required SmbConnection Connection { get; init; }

    public required byte[] SigningKey { get; set; }
}
