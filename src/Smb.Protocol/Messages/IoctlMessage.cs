using System;
using System.Collections.Generic;
using System.Text;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public static class IoctlMessage
{
	public readonly record struct Request(uint CtlCode, ulong PersistentId, ulong VolatileId, uint Flags, byte[] Input, uint MaxOutputResponse);

	public readonly record struct ValidateNegotiateRequest(uint Capabilities, byte[] Guid, ushort SecurityMode, ushort[] Dialects);

	public const ushort RequestStructureSize = 57;

	public const ushort ResponseStructureSize = 49;

	public const uint FsctlPipeTransceive = 1163287u;

	public const uint FsctlValidateNegotiateInfo = 1311236u;

	public const uint FsctlSrvEnumerateSnapshots = 1327204u;

	public const uint FlagIsFsctl = 1u;

	public static Request ParseRequest(ReadOnlySpan<byte> message, int bodyOffset)
	{
		var spanReader = new SpanReader(message.Slice(bodyOffset));
		var num = spanReader.ReadUInt16();
		if (num != RequestStructureSize)
		{
			throw new SmbWireFormatException($"IOCTL Request StructureSize {num} ≠ {RequestStructureSize}.");
		}

		spanReader.Skip(2);
		var ctlCode = spanReader.ReadUInt32();
		var persistentId = spanReader.ReadUInt64();
		var volatileId = spanReader.ReadUInt64();
		var num2 = spanReader.ReadUInt32();
		var num3 = spanReader.ReadUInt32();
		spanReader.ReadUInt32();
		var outputOffset = spanReader.ReadUInt32();
		var outputCount = spanReader.ReadUInt32();
		RequestBounds.Buffer(message, outputOffset, outputCount, bodyOffset + 56, "IOCTL output");
		var maxOutputResponse = spanReader.ReadUInt32();
		var flags = spanReader.ReadUInt32();
		spanReader.ReadUInt32();
		RequestBounds.Buffer(message, num2, num3, bodyOffset + 56, "IOCTL input");
		var input = Array.Empty<byte>();
		if (num3 != 0)
		{
			if (num2 + num3 > message.Length)
			{
				throw new SmbWireFormatException("IOCTL input extends past the message.");
			}

			input = message.Slice((int)num2, (int)num3).ToArray();
		}

		return new Request(ctlCode, persistentId, volatileId, flags, input, maxOutputResponse);
	}

	public static byte[] BuildResponseBody(uint ctlCode, ulong persistentId, ulong volatileId, ReadOnlySpan<byte> output)
	{
		var array = new byte[48 + output.Length];
		var spanWriter = new SpanWriter(array);
		spanWriter.WriteUInt16(ResponseStructureSize);
		spanWriter.WriteUInt16(0);
		spanWriter.WriteUInt32(ctlCode);
		spanWriter.WriteUInt64(persistentId);
		spanWriter.WriteUInt64(volatileId);
		spanWriter.WriteUInt32((output.Length > 0) ? 112u : 0u);
		spanWriter.WriteUInt32(0u);
		spanWriter.WriteUInt32((output.Length > 0) ? 112u : 0u);
		spanWriter.WriteUInt32((uint)output.Length);
		spanWriter.WriteUInt32(0u);
		spanWriter.WriteUInt32(0u);
		spanWriter.WriteBytes(output);
		return array;
	}

	public static ValidateNegotiateRequest ParseValidateNegotiate(ReadOnlySpan<byte> input)
	{
		var spanReader = new SpanReader(input);
		var capabilities = spanReader.ReadUInt32();
		var guid = spanReader.ReadByteArray(16);
		var securityMode = spanReader.ReadUInt16();
		var num = spanReader.ReadUInt16();
		var array = new ushort[num];
		for (var i = 0; i < num; i++)
		{
			array[i] = spanReader.ReadUInt16();
		}

		return new ValidateNegotiateRequest(capabilities, guid, securityMode, array);
	}

	public static byte[] BuildValidateNegotiateResponse(uint capabilities, ReadOnlySpan<byte> serverGuid, ushort securityMode, ushort dialect)
	{
		var array = new byte[24];
		var spanWriter = new SpanWriter(array);
		spanWriter.WriteUInt32(capabilities);
		spanWriter.WriteBytes((serverGuid.Length == 16) ? serverGuid : ((ReadOnlySpan<byte>)new byte[16]));
		spanWriter.WriteUInt16(securityMode);
		spanWriter.WriteUInt16(dialect);
		return array;
	}

	public static byte[] BuildEnumerateSnapshotsResponse(IReadOnlyList<string> gmtTokens, uint maxOutputResponse)
	{
		var list = new List<byte>();
		foreach (var gmtToken in gmtTokens)
		{
			list.AddRange(Encoding.Unicode.GetBytes(gmtToken));
			list.Add(0);
			list.Add(0);
		}

		list.Add(0);
		list.Add(0);
		var count = (uint)gmtTokens.Count;
		var count2 = (uint)list.Count;
		var flag = 12 + count2 <= maxOutputResponse;
		var array = (flag ? list.ToArray() : Array.Empty<byte>());
		var value = (flag ? count : 0u);
		var array2 = new byte[12 + array.Length];
		var spanWriter = new SpanWriter(array2);
		spanWriter.WriteUInt32(count);
		spanWriter.WriteUInt32(value);
		spanWriter.WriteUInt32(count2);
		spanWriter.WriteBytes(array);
		return array2;
	}
}
