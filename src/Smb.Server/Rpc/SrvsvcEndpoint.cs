using System;
using System.Collections.Generic;
using Smb.FileSystem;

namespace Smb.Server.Rpc;

public sealed class SrvsvcEndpoint : IRpcEndpoint
{
	private const ushort OpnumNetrShareEnum = 15;

	public const uint StypeDisktree = 0u;

	public const uint StypePrintq = 1u;

	public const uint StypeIpc = 3u;

	public const uint StypeSpecial = 2147483648u;

	private readonly IReadOnlyList<ShareEntry> _shares;

	public SrvsvcEndpoint(IReadOnlyList<ShareEntry> shares)
	{
		_shares = shares;
	}

	public static uint MapStype(ShareType type)
	{
		return type switch
		{
			ShareType.Pipe => StypeIpc | StypeSpecial,
			ShareType.Print => StypePrintq,
			_ => StypeDisktree,
		};
	}

	public byte[] HandlePdu(ReadOnlySpan<byte> pdu)
	{
		DcerpcRequest dcerpcRequest;
		try
		{
			dcerpcRequest = Dcerpc.Parse(pdu);
		}
		catch
		{
			return Array.Empty<byte>();
		}

		switch (dcerpcRequest.Type)
		{
			case DcerpcPduType.Bind:
			case DcerpcPduType.AlterContext:
				return Dcerpc.BuildBindAck(dcerpcRequest.CallId, @"\PIPE\srvsvc");
			case DcerpcPduType.Request:
				if (dcerpcRequest.Opnum == OpnumNetrShareEnum)
				{
					return Dcerpc.BuildResponse(dcerpcRequest.CallId, BuildShareEnumLevel1());
				}

				return Dcerpc.BuildFault(dcerpcRequest.CallId, 469827586u);
			default:
				return Array.Empty<byte>();
		}
	}

	private byte[] BuildShareEnumLevel1()
	{
		var count = _shares.Count;
		var ndrWriter = new NdrWriter();
		ndrWriter.UInt32(1u);
		ndrWriter.UInt32(1u);
		ndrWriter.ReferentId();
		ndrWriter.UInt32((uint)count);
		ndrWriter.ReferentId();
		ndrWriter.UInt32((uint)count);
		foreach (var share in _shares)
		{
			ndrWriter.ReferentId();
			ndrWriter.UInt32(share.Type);
			ndrWriter.ReferentId();
		}

		foreach (var share2 in _shares)
		{
			ndrWriter.WideStringNullTerminated(share2.Name);
			ndrWriter.WideStringNullTerminated(share2.Remark);
		}

		ndrWriter.UInt32((uint)count);
		ndrWriter.ReferentId();
		ndrWriter.UInt32(0u);
		ndrWriter.UInt32(0u);
		return ndrWriter.ToArray();
	}
}
