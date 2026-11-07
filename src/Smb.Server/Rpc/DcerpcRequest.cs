namespace Smb.Server.Rpc;

public readonly record struct DcerpcRequest(DcerpcPduType Type, uint CallId, ushort Opnum, byte[] Stub);
