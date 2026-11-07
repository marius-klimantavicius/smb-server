namespace Smb.Server.Rpc;

public readonly record struct ShareEntry(string Name, uint Type, string Remark);
