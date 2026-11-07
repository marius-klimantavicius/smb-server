using System;
using System.Collections.Generic;
using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public sealed class SigningContext : NegotiateContext
{
	public override NegotiateContextType Type => NegotiateContextType.SigningCapabilities;

	public IReadOnlyList<SmbSigningAlgorithmId> Algorithms { get; init; } = Array.Empty<SmbSigningAlgorithmId>();

	protected override void WriteData(GrowableWriter w)
	{
		w.WriteUInt16((ushort)Algorithms.Count);
		foreach (var algorithm in Algorithms)
		{
			w.WriteUInt16((ushort)algorithm);
		}
	}

	public static SigningContext ParseData(ReadOnlySpan<byte> data)
	{
		var spanReader = new SpanReader(data);
		int num = spanReader.ReadUInt16();
		var array = new SmbSigningAlgorithmId[num];
		for (var i = 0; i < num; i++)
		{
			array[i] = (SmbSigningAlgorithmId)spanReader.ReadUInt16();
		}

		return new SigningContext
		{
			Algorithms = array,
		};
	}
}
