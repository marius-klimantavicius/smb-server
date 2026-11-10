namespace Smb.Server.Rpc;

public enum DcerpcPduType : byte
{
    Request = 0,
    Response = 2,
    Fault = 3,
    Bind = 11,
    BindAck = 12,
    BindNak = 13,
    AlterContext = 14,
    AlterContextResp = 15,
}
