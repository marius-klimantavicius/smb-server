namespace Smb.Protocol.Enums;

public enum CreateDisposition : uint
{
    Supersede,
    Open,
    Create,
    OpenIf,
    Overwrite,
    OverwriteIf,
}
