using System;
using System.Buffers.Binary;
using System.Threading.Tasks;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;

namespace Smb.Server.State;

/// <summary>One execution chain, owned by one ProcessMessageAsync invocation.</summary>
public sealed class CompoundExecutionContext
{
	public int ChainStart { get; private set; }
	public int SegmentStart { get; internal set; }
	public int SegmentLength { get; internal set; }
	public ulong SessionId { get; private set; }
	public uint TreeId { get; private set; }
	public (ulong Persistent, ulong Volatile)? FileId { get; private set; }

	public NtStatus? PrerequisiteFailure { get; private set; }

	// Invocation-owned continuation retains original command slices and resumes after final transmission.
	public Func<ValueTask>? PendingContinuation { get; internal set; }
	private NtStatus? terminalFailure;

	public static int FileIdOffset(SmbCommand command) => command switch
	{
		SmbCommand.Read or SmbCommand.Write or SmbCommand.SetInfo => 80,
		SmbCommand.QueryInfo => 88,
		SmbCommand.Close or SmbCommand.Flush or SmbCommand.Lock or SmbCommand.QueryDirectory or SmbCommand.ChangeNotify or SmbCommand.Ioctl => 72,
		_ => -1
	};

	internal static int RequestFileIdOffset(SmbCommand command, ReadOnlySpan<byte> packet)
	{
		if (command == SmbCommand.Ioctl && packet.Length >= 72)
		{
			var code = BinaryPrimitives.ReadUInt32LittleEndian(packet.Slice(68));
			// 3.3.5.15: these control codes address the server/tree, and require the all-ones sentinel.
			if (code is 0x00060194 or 0x000601b0 or 0x001401fc or 0x00140204 or 0x00110018) return -1;
		}

		return FileIdOffset(command);
	}

	internal NtStatus? Resolve(Smb2Header header, ReadOnlyMemory<byte> wire, out ReadOnlyMemory<byte> resolved)
	{
		resolved = wire;
		var related = header.Flags.HasFlag(Smb2HeaderFlags.RelatedOperations);
		if (!related)
		{
			ChainStart = SegmentStart;
			SessionId = header.SessionId;
			TreeId = header.TreeId;
			FileId = null;
			PrerequisiteFailure = terminalFailure = null;
			return null;
		}

		if (SegmentStart == 0) return terminalFailure = NtStatus.InvalidParameter;

		header.SessionId = SessionId;
		header.TreeId = TreeId;
		if (terminalFailure.HasValue) return terminalFailure;
		if (header.Command > SmbCommand.SessionSetup && SessionId == 0) return terminalFailure = NtStatus.InvalidParameter;
		if (header.Command >= SmbCommand.TreeDisconnect && header.Command != SmbCommand.Echo && header.Command != SmbCommand.Cancel && TreeId == 0)
			return terminalFailure = NtStatus.InvalidParameter;
		if (PrerequisiteFailure.HasValue) return PrerequisiteFailure;

		var fileOffset = RequestFileIdOffset(header.Command, wire.Span);
		if (fileOffset >= 0)
		{
			if (!FileId.HasValue) return terminalFailure = (NtStatus)0xc0000008;

			if (wire.Length >= fileOffset + 16)
			{
				var copy = wire.ToArray();
				BinaryPrimitives.WriteUInt64LittleEndian(copy.AsSpan(fileOffset), FileId.Value.Persistent);
				BinaryPrimitives.WriteUInt64LittleEndian(copy.AsSpan(fileOffset + 8), FileId.Value.Volatile);
				resolved = copy;
			}
		}

		return null;
	}

	internal void Complete(Smb2Header request, ReadOnlyMemory<byte> resolved, Smb2Header response, byte[] body)
	{
		SessionId = response.SessionId;
		TreeId = response.TreeId;
		if (request.Command == SmbCommand.SessionSetup && response.Status != NtStatus.Success) SessionId = 0;
		if (request.Command == SmbCommand.TreeConnect && response.Status != NtStatus.Success) TreeId = 0;
		if ((uint)response.Status >= 0x80000000) PrerequisiteFailure = response.Status;
		else PrerequisiteFailure = null;
		var fileOffset = RequestFileIdOffset(request.Command, resolved.Span);
		FileId = fileOffset >= 0 && resolved.Length >= fileOffset + 16
			? (BinaryPrimitives.ReadUInt64LittleEndian(resolved.Span.Slice(fileOffset)), BinaryPrimitives.ReadUInt64LittleEndian(resolved.Span.Slice(fileOffset + 8)))
			: null;
		if (request.Command == SmbCommand.Create && response.Status == NtStatus.Success && body.Length >= 80)
			FileId = (BinaryPrimitives.ReadUInt64LittleEndian(body.AsSpan(64)), BinaryPrimitives.ReadUInt64LittleEndian(body.AsSpan(72)));
	}
}
