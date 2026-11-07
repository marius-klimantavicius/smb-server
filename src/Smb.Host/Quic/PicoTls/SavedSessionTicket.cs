using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using static Managed.Security.PicoTls;

namespace Managed.Security;

/// <summary>A client resumption credential containing PSK material. Keep it
/// confidential. Dispose clears the owned bytes; Export returns a caller-owned copy.</summary>
public sealed unsafe class SavedSessionTicket : IDisposable
{
    private readonly Lock _gate = new Lock();
    private byte[]? _bytes;

    public DateTimeOffset ExpiresAt { get; }

    public bool IsExpired => DateTimeOffset.UtcNow >= ExpiresAt;

    // This profile never offers early data, regardless of the ticket extension.
    public bool EarlyDataEnabled => false;

    internal SavedSessionTicket(byte[] bytes, uint lifetime)
    {
        _bytes = bytes;
        ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(lifetime);
    }

    public byte[] Export()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_bytes == null, this);
            return (byte[])_bytes!.Clone();
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_bytes != null)
            {
                CryptographicOperations.ZeroMemory(_bytes);
                _bytes = null;
            }
        }
    }

    private sealed class SavedTicketState : IDisposable
    {
        public readonly List<SavedSessionTicket> Pending = [];

        public void Dispose()
        {
            foreach (var ticket in Pending) ticket.Dispose();
            Pending.Clear();
        }
    }

    internal static readonly delegate*<st_ptls_save_ticket_t*, st_ptls_t*, st_ptls_iovec_t, st_ptls_save_ticket_properties_t*, int> SaveTicketPointer = &SaveTicket;

    private static int SaveTicket(st_ptls_save_ticket_t* self, st_ptls_t* tls, st_ptls_iovec_t input, st_ptls_save_ticket_properties_t* properties)
    {
        SavedSessionTicket? saved = null;
        try
        {
            CallbackScope.RequireActive();
            if (CallbackScope.HasFailure)
                return PTLS_ERROR_LIBRARY;

            if (properties == null || tls == null || input.len > 65536 || input.@base == null)
                return PTLS_ALERT_ILLEGAL_PARAMETER;

            if (properties->lifetime is 0 or > 604800)
                return 0; // Discard out-of-profile lifetimes.

            var opaque = (nint)(*ptls_get_data_ptr(tls));
            if (opaque == 0)
                throw new InvalidOperationException("A client ticket callback requires connection-owned state.");

            var state = (SavedTicketState)GCHandle.FromIntPtr(opaque).Target!;
            saved = new SavedSessionTicket(new ReadOnlySpan<byte>(input.@base, (int)input.len).ToArray(), properties->lifetime);
            state.Pending.Add(saved);
            saved = null;

            if (state.Pending.Count > 4)
            {
                state.Pending[0].Dispose();
                state.Pending.RemoveAt(0);
            }

            return 0;
        }
        catch (Exception error)
        {
            CallbackScope.Capture(error);
            return error is OutOfMemoryException ? PTLS_ERROR_NO_MEMORY : PTLS_ERROR_LIBRARY;
        }
        finally
        {
            saved?.Dispose();
        }
    }
}