using System;
using System.Collections.Generic;
using System.Text;
using Smb.Protocol.Wire;
using Smb.Server.Rpc;

namespace Smb.Server.Witness;

public static class WitnessWire
{
	public const int InterfaceGroupNameChars = 260;

	private const int IpAddrInfoSize = 24;

	public static ReadOnlySpan<byte> InterfaceUuid =>
	[
		116, 192, 216, 204, 229, 208, 64, 74, 146, 180,
		208, 116, 250, 166, 186, 40,
	];

	public static byte[] EncodeInterfaceList(IReadOnlyList<WitnessInterfaceInfo> interfaces, uint returnCode = 0u)
	{
		var ndrWriter = new NdrWriter();
		ndrWriter.ReferentId();
		ndrWriter.UInt32((uint)interfaces.Count);
		ndrWriter.ReferentId();
		ndrWriter.UInt32((uint)interfaces.Count);
		foreach (var @interface in interfaces)
		{
			ndrWriter.FixedWideString(@interface.InterfaceGroupName, InterfaceGroupNameChars);
			ndrWriter.UInt32(@interface.Version);
			ndrWriter.UInt16((ushort)@interface.NodeState);
			ndrWriter.UInt32(@interface.IPv4);
			for (var i = 0; i < 8; i++)
			{
				ndrWriter.UInt16(0);
			}

			ndrWriter.UInt32((uint)@interface.Flags);
		}

		ndrWriter.UInt32(returnCode);
		return ndrWriter.ToArray();
	}

	public static byte[] EncodeAsyncNotifyResponse(WitnessNotifyType type, int messageCount, ReadOnlySpan<byte> messageBuffer, uint returnCode = 0u)
	{
		var ndrWriter = new NdrWriter();
		ndrWriter.ReferentId();
		ndrWriter.UInt32((uint)type);
		ndrWriter.UInt32((uint)messageBuffer.Length);
		ndrWriter.UInt32((uint)messageCount);
		ndrWriter.ReferentId();
		ndrWriter.UInt32((uint)messageBuffer.Length);
		ndrWriter.Bytes(messageBuffer);
		ndrWriter.Align(4);
		ndrWriter.UInt32(returnCode);
		return ndrWriter.ToArray();
	}

	public static byte[] EncodeResourceChange(WitnessResourceChange change, string resourceName)
	{
		var bytes = Encoding.Unicode.GetBytes(resourceName + "\0");
		var growableWriter = new GrowableWriter(8 + bytes.Length);
		growableWriter.WriteUInt32((uint)(8 + bytes.Length));
		growableWriter.WriteUInt32((uint)change);
		growableWriter.WriteBytes(bytes);
		return growableWriter.ToArray();
	}

	public static byte[] EncodeIpAddrInfoList(IReadOnlyList<WitnessIpAddr> addresses)
	{
		var num = 12 + addresses.Count * IpAddrInfoSize;
		var growableWriter = new GrowableWriter(num);
		growableWriter.WriteUInt32(0u);
		growableWriter.WriteUInt32((uint)num);
		growableWriter.WriteUInt32((uint)addresses.Count);
		foreach (var address in addresses)
		{
			growableWriter.WriteUInt32((uint)address.Flags);
			growableWriter.WriteUInt32(address.IPv4);
			var iPv = address.IPv6;
			if (iPv != null && iPv.Length == 16)
			{
				growableWriter.WriteBytes(address.IPv6);
				continue;
			}

			for (var i = 0; i < 16; i++)
			{
				growableWriter.WriteByte(0);
			}
		}

		return growableWriter.ToArray();
	}

	public static WitnessRegisterArgs ParseRegister(ReadOnlyMemory<byte> stub)
	{
		var ndrReader = new NdrReader(stub);
		var version = ndrReader.UInt32();
		var netName = ReadUniqueString(ndrReader);
		var ipAddress = ReadUniqueString(ndrReader);
		var clientComputerName = ReadUniqueString(ndrReader);
		return new WitnessRegisterArgs(version, netName, null, ipAddress, clientComputerName, 0u, 0u);
	}

	public static WitnessRegisterArgs ParseRegisterEx(ReadOnlyMemory<byte> stub)
	{
		var ndrReader = new NdrReader(stub);
		var version = ndrReader.UInt32();
		var netName = ReadUniqueString(ndrReader);
		var shareName = ReadUniqueString(ndrReader);
		var ipAddress = ReadUniqueString(ndrReader);
		var clientComputerName = ReadUniqueString(ndrReader);
		var flags = ndrReader.UInt32();
		var keepAliveTimeoutSeconds = ndrReader.UInt32();
		return new WitnessRegisterArgs(version, netName, shareName, ipAddress, clientComputerName, flags, keepAliveTimeoutSeconds);
	}

	private static string? ReadUniqueString(NdrReader r)
	{
		if (r.ReferentId() != 0)
		{
			return r.WideStringNullTerminated();
		}

		return null;
	}
}
