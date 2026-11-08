// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Net;
using System.Runtime.InteropServices;
using static Managed.Transport.MsQuic;

namespace Managed.Net.Quic;

internal sealed class MsQuicTlsSecret : IDisposable
{
    private unsafe QUIC_TLS_SECRETS* _tlsSecrets;

    public static unsafe MsQuicTlsSecret? Create(MsQuicContextSafeHandle handle)
    {
        if (!SslKeyLogger.IsEnabled)
        {
            return null;
        }

        QUIC_TLS_SECRETS* tlsSecrets = null;
        try
        {
            tlsSecrets = (QUIC_TLS_SECRETS*)NativeMemory.AllocZeroed((nuint)sizeof(QUIC_TLS_SECRETS));
            MsQuicHelpers.SetMsQuicParameter(handle, QUIC_PARAM_CONN_TLS_SECRETS, (uint)sizeof(QUIC_TLS_SECRETS), (byte*)tlsSecrets);
            var instance = new MsQuicTlsSecret(tlsSecrets);
            handle.Disposable = instance;
            return instance;
        }
        catch (Exception ex)
        {
            if (NetEventSource.Log.IsEnabled())
            {
                NetEventSource.Error(handle, $"Failed to set native memory for TLS secret: {ex}");
            }
            if (tlsSecrets is not null)
            {
                NativeMemory.Free(tlsSecrets);
            }
            return null;
        }
    }

    private unsafe MsQuicTlsSecret(QUIC_TLS_SECRETS* tlsSecrets)
    {
        _tlsSecrets = tlsSecrets;
    }

    public unsafe void WriteSecret()
    {
        var clientRandom = _tlsSecrets->IsSet.ClientRandom != 0
            ? new ReadOnlySpan<byte>(_tlsSecrets->ClientRandom, 32)
            : ReadOnlySpan<byte>.Empty;

        var clientHandshakeTrafficSecret = _tlsSecrets->IsSet.ClientHandshakeTrafficSecret != 0
            ? new Span<byte>(_tlsSecrets->ClientHandshakeTrafficSecret, _tlsSecrets->SecretLength)
            : Span<byte>.Empty;

        var serverHandshakeTrafficSecret = _tlsSecrets->IsSet.ServerHandshakeTrafficSecret != 0
            ? new Span<byte>(_tlsSecrets->ServerHandshakeTrafficSecret, _tlsSecrets->SecretLength)
            : Span<byte>.Empty;

        var clientTrafficSecret0 = _tlsSecrets->IsSet.ClientTrafficSecret0 != 0
            ? new Span<byte>(_tlsSecrets->ClientTrafficSecret0, _tlsSecrets->SecretLength)
            : Span<byte>.Empty;

        var serverTrafficSecret0 = _tlsSecrets->IsSet.ServerTrafficSecret0 != 0
            ? new Span<byte>(_tlsSecrets->ServerTrafficSecret0, _tlsSecrets->SecretLength)
            : Span<byte>.Empty;

        var clientEarlyTrafficSecret = _tlsSecrets->IsSet.ClientEarlyTrafficSecret != 0
            ? new Span<byte>(_tlsSecrets->ClientEarlyTrafficSecret, _tlsSecrets->SecretLength)
            : Span<byte>.Empty;

        SslKeyLogger.WriteSecrets(
            clientRandom,
            clientHandshakeTrafficSecret,
            serverHandshakeTrafficSecret,
            clientTrafficSecret0,
            serverTrafficSecret0,
            clientEarlyTrafficSecret);

        // clear secrets already logged, so they are not logged again on next call,
        // keep ClientRandom as it is used for all secrets (and is not a secret itself)
        if (!clientHandshakeTrafficSecret.IsEmpty)
        {
            clientHandshakeTrafficSecret.Clear();
            _tlsSecrets->IsSet.ClientHandshakeTrafficSecret = 0;
        }

        if (!serverHandshakeTrafficSecret.IsEmpty)
        {
            serverHandshakeTrafficSecret.Clear();
            _tlsSecrets->IsSet.ServerHandshakeTrafficSecret = 0;
        }

        if (!clientTrafficSecret0.IsEmpty)
        {
            clientTrafficSecret0.Clear();
            _tlsSecrets->IsSet.ClientTrafficSecret0 = 0;
        }

        if (!serverTrafficSecret0.IsEmpty)
        {
            serverTrafficSecret0.Clear();
            _tlsSecrets->IsSet.ServerTrafficSecret0 = 0;
        }

        if (!clientEarlyTrafficSecret.IsEmpty)
        {
            clientEarlyTrafficSecret.Clear();
            _tlsSecrets->IsSet.ClientEarlyTrafficSecret = 0;
        }
    }

    public unsafe void Dispose()
    {
        if (_tlsSecrets is null)
        {
            return;
        }
        lock (this)
        {
            if (_tlsSecrets is null)
            {
                return;
            }

            var tlsSecrets = _tlsSecrets;
            _tlsSecrets = null;
            NativeMemory.Free(tlsSecrets);
        }
    }
}