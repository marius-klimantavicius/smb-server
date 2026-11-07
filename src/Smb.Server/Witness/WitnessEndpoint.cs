using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Net.Sockets;
using Smb.Protocol.Messages;
using Smb.Protocol.Wire;
using Smb.Server.Rpc;

namespace Smb.Server.Witness;

public sealed class WitnessEndpoint : IRpcEndpoint
{
	private const uint ErrorSuccess = 0u;

	private const uint ErrorInvalidParameter = 87u;

	private const uint ErrorRevisionMismatch = 1255u;

	private const uint RpcFaultOpRange = 469827586u;

	private static readonly byte[] NullHandle = new byte[20];

	private readonly WitnessRegistrationStore _store;

	private readonly Guid _connectionId;

	private readonly Func<IReadOnlyList<WitnessInterfaceInfo>> _interfaces;

	public WitnessEndpoint(WitnessRegistrationStore store, Guid connectionId, Func<IReadOnlyList<WitnessInterfaceInfo>> interfaces)
	{
		_store = store;
		_connectionId = connectionId;
		_interfaces = interfaces;
	}

	public static IReadOnlyList<WitnessInterfaceInfo> SelfInterfaces(string serverName)
	{
		return [new WitnessInterfaceInfo(serverName, 65537u, WitnessNodeState.Available, 0u, WitnessInterfaceFlags.InterfaceWitness)];
	}

	public static IReadOnlyList<WitnessInterfaceInfo> FromNetworkInterfaces(string serverName, IReadOnlyList<NetworkInterfaceInfo> nics)
	{
		var list = new List<WitnessInterfaceInfo>();
		foreach (var nic in nics)
		{
			if (nic.Address.AddressFamily == AddressFamily.InterNetwork)
			{
				var iPv = BinaryPrimitives.ReadUInt32LittleEndian(nic.Address.GetAddressBytes());
				list.Add(new WitnessInterfaceInfo(serverName, 65537u, WitnessNodeState.Available, iPv, WitnessInterfaceFlags.IPv4Valid | WitnessInterfaceFlags.InterfaceWitness));
			}
		}

		if (list.Count <= 0)
		{
			return SelfInterfaces(serverName);
		}

		return list;
	}

	public bool TryBeginAsyncNotify(ReadOnlySpan<byte> pdu, [NotNullWhen(true)] out WitnessRegistration? registration, out uint callId)
	{
		registration = null;
		callId = 0u;
		DcerpcRequest dcerpcRequest;
		try
		{
			dcerpcRequest = Dcerpc.Parse(pdu);
		}
		catch
		{
			return false;
		}

		if (dcerpcRequest.Type != DcerpcPduType.Request || dcerpcRequest.Opnum != 3)
		{
			return false;
		}

		if (!WitnessRegistrationStore.TryReadContextHandle(dcerpcRequest.Stub, out var id))
		{
			return false;
		}

		if (!_store.TryGet(id, out var registration2) || registration2.ConnectionId != _connectionId)
		{
			return false;
		}

		registration = registration2;
		callId = dcerpcRequest.CallId;
		return true;
	}

	public static byte[] BuildAsyncNotifyPdu(uint callId, WitnessNotification notification)
	{
		return Dcerpc.BuildResponse(callId, WitnessWire.EncodeAsyncNotifyResponse(notification.Type, notification.MessageCount, notification.MessageBuffer));
	}

	public byte[] HandlePdu(ReadOnlySpan<byte> pdu)
	{
		DcerpcRequest req;
		try
		{
			req = Dcerpc.Parse(pdu);
		}
		catch
		{
			return Array.Empty<byte>();
		}

		switch (req.Type)
		{
			case DcerpcPduType.Bind:
			case DcerpcPduType.AlterContext:
				return Dcerpc.BuildBindAck(req.CallId, "\\PIPE\\witness");
			case DcerpcPduType.Request:
				return HandleRequest(req);
			default:
				return Array.Empty<byte>();
		}
	}

	private byte[] HandleRequest(DcerpcRequest req)
	{
		return (WitnessOpnum)req.Opnum switch
		{
			WitnessOpnum.GetInterfaceList => Dcerpc.BuildResponse(req.CallId, WitnessWire.EncodeInterfaceList(_interfaces())),
			WitnessOpnum.Register => HandleRegister(req, WitnessWire.ParseRegister(req.Stub)),
			WitnessOpnum.RegisterEx => HandleRegister(req, WitnessWire.ParseRegisterEx(req.Stub)),
			WitnessOpnum.UnRegister => HandleUnRegister(req),
			_ => Dcerpc.BuildFault(req.CallId, RpcFaultOpRange),
		};
	}

	private byte[] HandleRegister(DcerpcRequest req, WitnessRegisterArgs args)
	{
		if (args.Version != 65537 && args.Version != 131072)
		{
			return Dcerpc.BuildResponse(req.CallId, EncodeRegisterResponse(NullHandle, ErrorRevisionMismatch));
		}

		if (string.IsNullOrEmpty(args.NetName))
		{
			return Dcerpc.BuildResponse(req.CallId, EncodeRegisterResponse(NullHandle, ErrorInvalidParameter));
		}

		var witnessRegistration = _store.Add(_connectionId, args.Version, args.NetName, args.ShareName, args.IpAddress, args.ClientComputerName);
		return Dcerpc.BuildResponse(req.CallId, EncodeRegisterResponse(witnessRegistration.ContextHandle(), ErrorSuccess));
	}

	private byte[] HandleUnRegister(DcerpcRequest req)
	{
		var flag = WitnessRegistrationStore.TryReadContextHandle(req.Stub, out var id) && _store.Remove(id);
		return Dcerpc.BuildResponse(req.CallId, EncodeReturn((!flag) ? ErrorInvalidParameter : ErrorSuccess));
	}

	private static byte[] EncodeRegisterResponse(ReadOnlySpan<byte> contextHandle, uint returnCode)
	{
		var growableWriter = new GrowableWriter(24);
		growableWriter.WriteBytes(contextHandle);
		growableWriter.WriteUInt32(returnCode);
		return growableWriter.ToArray();
	}

	private static byte[] EncodeReturn(uint returnCode)
	{
		var growableWriter = new GrowableWriter(4);
		growableWriter.WriteUInt32(returnCode);
		return growableWriter.ToArray();
	}
}
