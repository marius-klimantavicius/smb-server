using System;
using System.Threading;
using Smb.Protocol.Enums;

namespace Smb.Server.State;

/// <summary>Per-open SMB3 admission. Tickets belong to physical work, never to an interim/cancel response.</summary>
public sealed class ChannelSequenceState(ushort initialSequence = 0)
{
	private readonly Lock _gate = new Lock();
	private object _current = new object();
	private long _outstanding;
	private ushort _sequence = initialSequence;
	private long _prior;

	public (ushort Sequence, long Current, long Prior) Snapshot
	{
		get
		{
			lock (_gate) return (_sequence, _outstanding, _prior);
		}
	}

	// MS-SMB2 88.0 3.3.5.2.10. New replay follows the SHOULD transition, including
	// advancing the sequence when prior work prevents a mutating replay admission.
	public NtStatus TryAdmit(ushort sequence, bool replay, SmbCommand command, out IDisposable? ticket)
	{
		ticket = null;
		var mutation = command is SmbCommand.Write or SmbCommand.SetInfo or SmbCommand.Ioctl;
		lock (_gate)
		{
			var newer = sequence != _sequence;
			if (newer && unchecked((ushort)(sequence - _sequence)) > 0x7fff)
				return mutation ? (NtStatus)0xc0000467 : NtStatus.Success;

			var total = _prior + _outstanding;
			var replayBlocked = replay && (newer ? total : _prior) != 0;
			// Bound the total live ticket population. Failed admission leaves the whole
			// transition unchanged; a blocked replay still performs the normative transition.
			if (!replayBlocked && total >= int.MaxValue) return NtStatus.InsufficientResources;

			if (newer)
			{
				_prior += _outstanding;
				_current = new object();
				_outstanding = 0;
				_sequence = sequence;
			}

			if (replay && _prior != 0)
				return mutation ? (NtStatus)0xc0000467 : NtStatus.Success;

			_outstanding++;
			ticket = new Ticket(this, _current);
			return NtStatus.Success;
		}
	}

	private sealed class Ticket(ChannelSequenceState owner, object generation) : IDisposable
	{
		private ChannelSequenceState? _owner = owner;

		public void Dispose()
		{
			var state = Interlocked.Exchange(ref _owner, null);
			if (state == null) return;

			lock (state._gate)
			{
				if (ReferenceEquals(generation, state._current)) state._outstanding--;
				else state._prior--;
			}
		}
	}
}
