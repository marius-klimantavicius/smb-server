using System;
using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public abstract class NegotiateContext
{
	public const int HeaderSize = 8;

	public abstract NegotiateContextType Type { get; }

	protected abstract void WriteData(GrowableWriter w);

	public void Write(GrowableWriter w)
	{
		var position = w.Position;
		w.WriteUInt16((ushort)Type);
		w.WriteUInt16(0);
		w.WriteUInt32(0u);
		var position2 = w.Position;
		WriteData(w);
		var num = w.Position - position2;
		w.PatchUInt16(position + 2, (ushort)num);
	}

	public static NegotiateContext Read(ReadOnlySpan<byte> buffer, out int consumed)
	{
		var spanReader = new SpanReader(buffer);
		var negotiateContextType = (NegotiateContextType)spanReader.ReadUInt16();
		int num = spanReader.ReadUInt16();
		spanReader.Skip(4);
		var data = spanReader.ReadBytes(num);
		consumed = HeaderSize + num;
		return negotiateContextType switch
		{
			NegotiateContextType.PreauthIntegrityCapabilities => (NegotiateContext)PreauthIntegrityContext.ParseData(data),
			NegotiateContextType.EncryptionCapabilities => EncryptionContext.ParseData(data),
			NegotiateContextType.SigningCapabilities => SigningContext.ParseData(data),
			NegotiateContextType.CompressionCapabilities => CompressionContext.ParseData(data),
			NegotiateContextType.NetnameNegotiateContextId => NetnameContext.ParseData(data),
			_ => new UnknownNegotiateContext(negotiateContextType, data.ToArray()),
		};
	}
}
