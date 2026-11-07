// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using static Managed.Transport.MsQuic;

namespace Managed.Net.Quic;

internal static partial class MsQuicConfiguration
{
    private static bool HasPrivateKey(this X509Certificate certificate)
        => certificate is X509Certificate2 certificate2 && certificate2.Handle != IntPtr.Zero && certificate2.HasPrivateKey;

    public static MsQuicConfigurationSafeHandle Create(QuicClientConnectionOptions options)
    {
        SslClientAuthenticationOptions authenticationOptions = options.ClientAuthenticationOptions;

        QUIC_CREDENTIAL_FLAGS flags = QUIC_CREDENTIAL_FLAGS.QUIC_CREDENTIAL_FLAG_NONE;
        flags |= QUIC_CREDENTIAL_FLAGS.QUIC_CREDENTIAL_FLAG_CLIENT;
        flags |= QUIC_CREDENTIAL_FLAGS.QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;
        flags |= QUIC_CREDENTIAL_FLAGS.QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
        // Find the first certificate with private key, either from selection callback or from a provided collection.
        X509Certificate? certificate = null;
        ReadOnlyCollection<X509Certificate2>? intermediates = null;
        if (authenticationOptions.ClientCertificateContext is not null)
        {
            certificate = authenticationOptions.ClientCertificateContext.TargetCertificate;
            intermediates = authenticationOptions.ClientCertificateContext.IntermediateCertificates;
        }
        else if (authenticationOptions.LocalCertificateSelectionCallback != null)
        {
            X509Certificate? selectedCertificate = authenticationOptions.LocalCertificateSelectionCallback(
                options,
                authenticationOptions.TargetHost ?? string.Empty,
                authenticationOptions.ClientCertificates ?? new X509CertificateCollection(),
                null,
                Array.Empty<string>());

            if (selectedCertificate is not null)
            {
                if (selectedCertificate.HasPrivateKey())
                {
                    certificate = selectedCertificate;
                }
                else
                {
                    if (NetEventSource.Log.IsEnabled())
                    {
                        NetEventSource.Info(options, $"'{certificate}' not selected because it doesn't have a private key.");
                    }
                }
            }
        }
        else if (authenticationOptions.ClientCertificates != null)
        {
            foreach (X509Certificate clientCertificate in authenticationOptions.ClientCertificates)
            {
                if (clientCertificate.HasPrivateKey())
                {
                    certificate = clientCertificate;
                    break;
                }
                else
                {
                    if (NetEventSource.Log.IsEnabled())
                    {
                        NetEventSource.Info(options, $"'{certificate}' not selected because it doesn't have a private key.");
                    }
                }
            }
        }

        return Create(options, flags, certificate, intermediates, authenticationOptions.ApplicationProtocols, authenticationOptions.CipherSuitesPolicy, authenticationOptions.EncryptionPolicy);
    }

    public static MsQuicConfigurationSafeHandle Create(QuicServerConnectionOptions options, string? targetHost)
    {
        SslServerAuthenticationOptions authenticationOptions = options.ServerAuthenticationOptions;

        QUIC_CREDENTIAL_FLAGS flags = QUIC_CREDENTIAL_FLAGS.QUIC_CREDENTIAL_FLAG_NONE;
        if (authenticationOptions.ClientCertificateRequired)
        {
            flags |= QUIC_CREDENTIAL_FLAGS.QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION;
            flags |= QUIC_CREDENTIAL_FLAGS.QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;
            flags |= QUIC_CREDENTIAL_FLAGS.QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
        }

        X509Certificate? certificate = null;
        ReadOnlyCollection<X509Certificate2>? intermediates = default;

        // the order of checking here matches the order of checking in SslStream
        if (authenticationOptions.ServerCertificateSelectionCallback is not null)
        {
            certificate = authenticationOptions.ServerCertificateSelectionCallback.Invoke(authenticationOptions, targetHost);
        }
        else if (authenticationOptions.ServerCertificateContext is not null)
        {
            certificate = authenticationOptions.ServerCertificateContext.TargetCertificate;
            intermediates = authenticationOptions.ServerCertificateContext.IntermediateCertificates;
        }
        else if (authenticationOptions.ServerCertificate is not null)
        {
            certificate = authenticationOptions.ServerCertificate;
        }

        if (certificate is null)
        {
            throw new ArgumentException(SR.Format(SR.net_quic_not_null_ceritifcate, nameof(SslServerAuthenticationOptions.ServerCertificate), nameof(SslServerAuthenticationOptions.ServerCertificateContext), nameof(SslServerAuthenticationOptions.ServerCertificateSelectionCallback)), nameof(options));
        }

        return Create(options, flags, certificate, intermediates, authenticationOptions.ApplicationProtocols, authenticationOptions.CipherSuitesPolicy, authenticationOptions.EncryptionPolicy);
    }

    private static MsQuicConfigurationSafeHandle Create(QuicConnectionOptions options, QUIC_CREDENTIAL_FLAGS flags, X509Certificate? certificate, ReadOnlyCollection<X509Certificate2>? intermediates, List<SslApplicationProtocol>? alpnProtocols, CipherSuitesPolicy? cipherSuitesPolicy, EncryptionPolicy encryptionPolicy)
    {
        // Validate options and SSL parameters.
        if (alpnProtocols is null || alpnProtocols.Count <= 0)
        {
            throw new ArgumentException(SR.Format(SR.net_quic_not_null_not_empty_connection, nameof(SslApplicationProtocol)), nameof(options));
        }

#pragma warning disable SYSLIB0040 // NoEncryption and AllowNoEncryption are obsolete
        if (encryptionPolicy == EncryptionPolicy.NoEncryption)
        {
            throw new PlatformNotSupportedException(SR.Format(SR.net_quic_ssl_option, encryptionPolicy));
        }
#pragma warning restore SYSLIB0040

        QUIC_SETTINGS settings = default(QUIC_SETTINGS);

        settings.IsSet.PeerUnidiStreamCount = 1;
        settings.PeerUnidiStreamCount = (ushort)options.MaxInboundUnidirectionalStreams;

        settings.IsSet.PeerBidiStreamCount = 1;
        settings.PeerBidiStreamCount = (ushort)options.MaxInboundBidirectionalStreams;

        if (options.IdleTimeout != TimeSpan.Zero)
        {
            settings.IsSet.IdleTimeoutMs = 1;
            settings.IdleTimeoutMs = options.IdleTimeout != Timeout.InfiniteTimeSpan
                ? (ulong)options.IdleTimeout.TotalMilliseconds
                : 0; // 0 disables the timeout
        }

        if (options.KeepAliveInterval != TimeSpan.Zero)
        {
            settings.IsSet.KeepAliveIntervalMs = 1;
            settings.KeepAliveIntervalMs = options.KeepAliveInterval != Timeout.InfiniteTimeSpan
                ? (uint)options.KeepAliveInterval.TotalMilliseconds
                : 0; // 0 disables the keepalive
        }

        settings.IsSet.ConnFlowControlWindow = 1;
        settings.ConnFlowControlWindow = (uint)(options._initialReceiveWindowSizes?.Connection ?? QuicDefaults.DefaultConnectionMaxData);

        settings.IsSet.StreamRecvWindowBidiLocalDefault = 1;
        settings.StreamRecvWindowBidiLocalDefault = (uint)(options._initialReceiveWindowSizes?.LocallyInitiatedBidirectionalStream ?? QuicDefaults.DefaultStreamMaxData);

        settings.IsSet.StreamRecvWindowBidiRemoteDefault = 1;
        settings.StreamRecvWindowBidiRemoteDefault = (uint)(options._initialReceiveWindowSizes?.RemotelyInitiatedBidirectionalStream ?? QuicDefaults.DefaultStreamMaxData);

        settings.IsSet.StreamRecvWindowUnidiDefault = 1;
        settings.StreamRecvWindowUnidiDefault = (uint)(options._initialReceiveWindowSizes?.UnidirectionalStream ?? QuicDefaults.DefaultStreamMaxData);

        if (options.HandshakeTimeout != TimeSpan.Zero)
        {
            settings.IsSet.HandshakeIdleTimeoutMs = 1;
            settings.HandshakeIdleTimeoutMs = options.HandshakeTimeout != Timeout.InfiniteTimeSpan
                    ? (ulong)options.HandshakeTimeout.TotalMilliseconds
                    : 0; // 0 disables the timeout
        }

        QUIC_ALLOWED_CIPHER_SUITE_FLAGS allowedCipherSuites = QUIC_ALLOWED_CIPHER_SUITE_FLAGS.QUIC_ALLOWED_CIPHER_SUITE_NONE;

        if (cipherSuitesPolicy != null)
        {
            flags |= QUIC_CREDENTIAL_FLAGS.QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES;
            allowedCipherSuites = CipherSuitePolicyToFlags(cipherSuitesPolicy);
        }

        flags |= QUIC_CREDENTIAL_FLAGS.QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES;

        if (ConfigurationCacheEnabled)
        {
            return GetCachedCredentialOrCreate(settings, flags, certificate, intermediates, alpnProtocols, allowedCipherSuites);
        }

        return CreateInternal(settings, flags, certificate, intermediates, alpnProtocols, allowedCipherSuites);
    }

    private static unsafe MsQuicConfigurationSafeHandle CreateInternal(QUIC_SETTINGS settings, QUIC_CREDENTIAL_FLAGS flags, X509Certificate? certificate, ReadOnlyCollection<X509Certificate2>? intermediates, List<SslApplicationProtocol> alpnProtocols, QUIC_ALLOWED_CIPHER_SUITE_FLAGS allowedCipherSuites)
    {
        if (certificate is X509Certificate2 cert && intermediates is null)
        {
            // MsQuic will not lookup intermediates in local CA store if not explicitly provided,
            // so we build the cert context to get on feature parity with SslStream. Note that this code
            // path runs after the MsQuicConfigurationCache check.
            SslStreamCertificateContext context = SslStreamCertificateContext.Create(cert, additionalCertificates: null, offline: true, trust: null);
            intermediates = context.IntermediateCertificates;
        }

        QUIC_HANDLE* handle;

        using MsQuicBuffers msquicBuffers = new MsQuicBuffers();
        msquicBuffers.Initialize(alpnProtocols, alpnProtocol => alpnProtocol.Protocol);
        ThrowHelper.ThrowIfMsQuicError(MsQuicApi.Api.ConfigurationOpen(
            MsQuicApi.Api.Registration,
            msquicBuffers.Buffers,
            (uint)msquicBuffers.Count,
            &settings,
            (uint)sizeof(QUIC_SETTINGS),
            (void*)IntPtr.Zero,
            &handle),
            "ConfigurationOpen failed");
        MsQuicConfigurationSafeHandle configurationHandle = new MsQuicConfigurationSafeHandle(handle);

        try
        {
            bool server = (flags & QUIC_CREDENTIAL_FLAGS.QUIC_CREDENTIAL_FLAG_CLIENT) == 0;
            using var credential = MsQuicApi.Host.CreateApplicationCredential(server,
                certificate as X509Certificate2, intermediates);
            // Security configuration retains the identity; private keys need not be exportable.
            uint status = MsQuicApi.Host.LoadCredential(configurationHandle.QuicHandle, credential, flags, null,
                (flags & QUIC_CREDENTIAL_FLAGS.QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES) != 0
                    ? (uint)allowedCipherSuites : 3u);

            ThrowHelper.ThrowIfMsQuicError(status, "ConfigurationLoadCredential failed");
        }
        catch
        {
            configurationHandle.Dispose();
            throw;
        }

        return configurationHandle;
    }

    private static QUIC_ALLOWED_CIPHER_SUITE_FLAGS CipherSuitePolicyToFlags(CipherSuitesPolicy cipherSuitesPolicy)
    {
        QUIC_ALLOWED_CIPHER_SUITE_FLAGS flags = QUIC_ALLOWED_CIPHER_SUITE_FLAGS.QUIC_ALLOWED_CIPHER_SUITE_NONE;
#pragma warning disable CA1416  // not supported on all platforms
        foreach (TlsCipherSuite cipher in cipherSuitesPolicy.AllowedCipherSuites)
        {
            switch (cipher)
            {
                case TlsCipherSuite.TLS_AES_128_GCM_SHA256:
                    flags |= QUIC_ALLOWED_CIPHER_SUITE_FLAGS.QUIC_ALLOWED_CIPHER_SUITE_AES_128_GCM_SHA256;
                    break;
                case TlsCipherSuite.TLS_AES_256_GCM_SHA384:
                    flags |= QUIC_ALLOWED_CIPHER_SUITE_FLAGS.QUIC_ALLOWED_CIPHER_SUITE_AES_256_GCM_SHA384;
                    break;
                // The BCL PicoTLS provider currently implements AES-GCM only.
                case TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256:
                case TlsCipherSuite.TLS_AES_128_CCM_SHA256: // not supported by MsQuic (yet?), but QUIC RFC allows it so we ignore it.
                default:
                    // ignore
                    break;
            }
#pragma warning restore
        }

        if (flags == QUIC_ALLOWED_CIPHER_SUITE_FLAGS.QUIC_ALLOWED_CIPHER_SUITE_NONE)
        {
            throw new ArgumentException(SR.net_quic_empty_cipher_suite, nameof(SslClientAuthenticationOptions.CipherSuitesPolicy));
        }

        return flags;
    }
}
