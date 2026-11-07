namespace Smb.Auth.Ntlm;

public readonly record struct NtlmAvPair(NtlmAvId Id, byte[] Value);
