using System.Text;
using Smb.Protocol.Wire;

namespace Smb.Auth.Ntlm;

public sealed class NtlmChallengeMessage
{
	public required byte[] ServerChallenge { get; init; }

	public required string TargetName { get; init; }

	public required NtlmNegotiateFlags Flags { get; init; }

	public required byte[] TargetInfo { get; init; }

	public byte[] ToArray()
	{
		var bytes = Encoding.Unicode.GetBytes(TargetName);
		var num = 56;
		var value = num + bytes.Length;
		var growableWriter = new GrowableWriter(56 + bytes.Length + TargetInfo.Length);
		growableWriter.WriteBytes(NtlmConstants.Signature);
		growableWriter.WriteUInt32(2u);
		growableWriter.WriteUInt16((ushort)bytes.Length);
		growableWriter.WriteUInt16((ushort)bytes.Length);
		growableWriter.WriteUInt32((uint)num);
		growableWriter.WriteUInt32((uint)Flags);
		growableWriter.WriteBytes(ServerChallenge);
		growableWriter.WriteUInt64(0uL);
		growableWriter.WriteUInt16((ushort)TargetInfo.Length);
		growableWriter.WriteUInt16((ushort)TargetInfo.Length);
		growableWriter.WriteUInt32((uint)value);
		growableWriter.WriteUInt64(0uL);
		growableWriter.WriteBytes(bytes);
		growableWriter.WriteBytes(TargetInfo);
		return growableWriter.ToArray();
	}
}
