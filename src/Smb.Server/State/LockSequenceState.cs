using System;
using System.Threading;
using System.Threading.Tasks;
using Smb.Server.Locking;

namespace Smb.Server.State;

/// <summary>MS-SMB2 3.3.5.14: 64 per-open slots, independent of ReplayOperation and channel sequence.</summary>
public sealed class LockSequenceState
{
    private sealed class Slot
    {
        internal readonly SemaphoreSlim Gate = new SemaphoreSlim(1, 1);
        internal bool Valid;
        internal uint Number;
    }

    private readonly Slot[] _slots = new Slot[64];

    public LockSequenceState()
    {
        for (var i = 0; i < _slots.Length; i++) _slots[i] = new Slot();
    }

    public byte[] Capture()
    {
        var result = new byte[64];
        for (var i = 0; i < result.Length; i++)
        {
            var slot = _slots[i];
            // Snapshot is taken after the operation's sequence slot has been committed.
            if (Volatile.Read(ref slot.Valid)) result[i] = checked((byte)(Volatile.Read(ref slot.Number) + 1));
        }
        return result;
    }
    public void Restore(byte[] state)
    {
        if (state.Length != 64) throw new ArgumentException("Expected 64 replay slots.", nameof(state));
        for (var i = 0; i < state.Length; i++)
        {
            if (state[i] > 16) throw new ArgumentException("Invalid replay slot.", nameof(state));
            _slots[i].Number = state[i] == 0 ? 0 : (uint)(state[i] - 1);
            _slots[i].Valid = state[i] != 0;
        }
    }

    public async Task<LockOutcome> ApplyAsync(uint sequence, Func<Task<LockOutcome>> apply, CancellationToken token)
    {
        var index = sequence >> 4;
        // Reserved and out-of-extent indexes continue ordinary processing (3.3.5.14).
        if (index == 0 || index > 64) return await apply().ConfigureAwait(false);

        var slot = _slots[index - 1];
        await slot.Gate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            // A cancelled queued waiter must not become a replay-success winner when
            // cancellation and semaphore handoff continuations race.
            token.ThrowIfCancellationRequested();
            var number = sequence & 15;
            if (slot.Valid && slot.Number == number) return LockOutcome.Granted;

            slot.Valid = false;
            var outcome = await apply().ConfigureAwait(false);
            if (outcome == LockOutcome.Granted)
            {
                slot.Number = number;
                slot.Valid = true;
            }

            return outcome;
        }
        finally { slot.Gate.Release(); }
    }
}
