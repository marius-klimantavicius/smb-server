using System;
using System.Collections.Generic;
using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public sealed class PreauthIntegrityContext : NegotiateContext
{
	public override NegotiateContextType Type => NegotiateContextType.PreauthIntegrityCapabilities;

	public IReadOnlyList<PreauthHashAlgorithm> HashAlgorithms { get; init; } = [PreauthHashAlgorithm.Sha512];

	public byte[] Salt { get; init; } = Array.Empty<byte>();

	protected override void WriteData(GrowableWriter w)
	{
		w.WriteUInt16((ushort)HashAlgorithms.Count);
		w.WriteUInt16((ushort)Salt.Length);
		foreach (var hashAlgorithm in HashAlgorithms)
		{
			w.WriteUInt16((ushort)hashAlgorithm);
		}

		w.WriteBytes(Salt);
	}

	public static PreauthIntegrityContext ParseData(ReadOnlySpan<byte> data)
	{
		var spanReader = new SpanReader(data);
		int num = spanReader.ReadUInt16();
		int count = spanReader.ReadUInt16();
		var array = new PreauthHashAlgorithm[num];
		for (var i = 0; i < num; i++)
		{
			array[i] = (PreauthHashAlgorithm)spanReader.ReadUInt16();
		}

		var salt = spanReader.ReadByteArray(count);
		return new PreauthIntegrityContext
		{
			HashAlgorithms = array,
			Salt = salt,
		};
	}
}
