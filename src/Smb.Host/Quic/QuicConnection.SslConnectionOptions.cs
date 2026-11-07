// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Quic;
using static Managed.Transport.MsQuic;

namespace Managed.Net.Quic;

public partial class QuicConnection
{
    private readonly struct SslConnectionOptions
    {
        private static readonly Oid s_serverAuthOid = new Oid("1.3.6.1.5.5.7.3.1", null);
        private static readonly Oid s_clientAuthOid = new Oid("1.3.6.1.5.5.7.3.2", null);

        /// <summary>
        /// The connection to which these options belong.
        /// </summary>
        private readonly QuicConnection _connection;
        /// <summary>
        /// Determines if the connection is outbound/client or inbound/server.
        /// </summary>
        private readonly bool _isClient;
        /// <summary>
        /// Host name send in SNI, set only for outbound/client connections. Configured via <see cref="SslClientAuthenticationOptions.TargetHost"/>.
        /// </summary>
        private readonly string _targetHost;
        /// <summary>
        /// Always <c>true</c> for outbound/client connections. Configured for inbound/server ones via <see cref="SslServerAuthenticationOptions.ClientCertificateRequired"/>.
        /// </summary>
        private readonly bool _certificateRequired;
        /// <summary>
        /// Configured via <see cref="SslServerAuthenticationOptions.CertificateRevocationCheckMode"/> or <see cref="SslClientAuthenticationOptions.CertificateRevocationCheckMode"/>.
        /// </summary>
        private readonly X509RevocationMode _revocationMode;
        /// <summary>
        /// Configured via <see cref="SslServerAuthenticationOptions.RemoteCertificateValidationCallback"/> or <see cref="SslClientAuthenticationOptions.RemoteCertificateValidationCallback"/>.
        /// </summary>
        private readonly RemoteCertificateValidationCallback? _validationCallback;

        /// <summary>
        /// Configured via <see cref="SslServerAuthenticationOptions.CertificateChainPolicy"/> or <see cref="SslClientAuthenticationOptions.CertificateChainPolicy"/>.
        /// </summary>
        private readonly X509ChainPolicy? _certificateChainPolicy;

        internal string TargetHost => _targetHost;

        public SslConnectionOptions(QuicConnection connection, bool isClient,
            string targetHost, bool certificateRequired, X509RevocationMode
            revocationMode, RemoteCertificateValidationCallback? validationCallback,
            X509ChainPolicy? certificateChainPolicy)
        {
            _connection = connection;
            _isClient = isClient;
            _targetHost = targetHost;
            _certificateRequired = certificateRequired;
            _revocationMode = revocationMode;
            _validationCallback = validationCallback;
            _certificateChainPolicy = certificateChainPolicy;
        }

        internal async Task<bool> StartAsyncCertificateValidation(IntPtr certificatePtr, IntPtr chainPtr)
        {
            X509Certificate2? certificate = null;
            QUIC_TLS_ALERT_CODES result;
            try
            {
                // Both pointers expire when the event returns. Snapshot before yielding.
                byte[] certData = CopyCertificateBuffer(certificatePtr);
                byte[] chainData = CopyCertificateBuffer(chainPtr);
                if (MsQuicApi.SupportsAsyncCertValidation)
                    await Task.CompletedTask.ConfigureAwait(ConfigureAwaitOptions.ForceYielding);

                if (certData.Length > 0)
                    certificate = X509CertificateLoader.LoadCertificate(certData);
                result = ValidateCertificate(certificate, chainData);
                lock (_connection._certificateGate)
                {
                    // Cancellation can dispose the connection while a user callback is running.
                    if (!_connection._disposed)
                    {
                        _connection._remoteCertificate = certificate;
                        certificate = null; // ownership transferred to the connection
                    }
                }
            }
            catch (Exception ex)
            {
                _connection._connectedTcs.TrySetException(ex);
                result = QUIC_TLS_ALERT_CODES.QUIC_TLS_ALERT_CODE_USER_CANCELED;
            }
            finally { certificate?.Dispose(); }

            if (MsQuicApi.SupportsAsyncCertValidation)
            {
                try
                {
                    uint status = MsQuicApi.Api.ConnectionCertificateValidationComplete(
                        _connection._handle,
                        result == QUIC_TLS_ALERT_CODES.QUIC_TLS_ALERT_CODE_SUCCESS ? (byte)1 : (byte)0, result);
                    if (MsQuicApi.StatusFailed(status) && NetEventSource.Log.IsEnabled())
                        NetEventSource.Error(_connection, $"ConnectionCertificateValidationComplete failed with {ThrowHelper.GetErrorMessageForStatus(status)}");
                }
                catch (ObjectDisposedException)
                {
                    // The handshake was canceled while certificate validation was in flight.
                }
            }
            return result == QUIC_TLS_ALERT_CODES.QUIC_TLS_ALERT_CODE_SUCCESS;
        }

        private static unsafe byte[] CopyCertificateBuffer(IntPtr pointer)
        {
            if (pointer == IntPtr.Zero) return [];
            QUIC_BUFFER* buffer = (QUIC_BUFFER*)pointer;
            // The host bounds DER input at 1 MiB; allow PKCS7 envelope overhead too.
            if (buffer->Length > 2 * 1024 * 1024 || (buffer->Length != 0 && buffer->Buffer == null))
                throw new CryptographicException("Invalid portable certificate buffer.");
            return buffer->Span.ToArray();
        }

        private QUIC_TLS_ALERT_CODES ValidateCertificate(X509Certificate2? certificate, Span<byte> chainData)
        {
            SslPolicyErrors sslPolicyErrors = SslPolicyErrors.None;
            bool wrapException = false;

            X509Chain? chain = null;
            X509Certificate2Collection additionalCertificates = new();
            try
            {
                if (certificate is not null)
                {
                    chain = new X509Chain();
                    if (_certificateChainPolicy != null)
                    {
                        chain.ChainPolicy = _certificateChainPolicy;
                    }
                    else
                    {
                        chain.ChainPolicy.RevocationMode = _revocationMode;
                        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;

                        // TODO: configure chain.ChainPolicy.CustomTrustStore to mirror behavior of SslStream.VerifyRemoteCertificate (https://github.com/dotnet/runtime/issues/73053)
                    }

                    // set ApplicationPolicy unless already provided.
                    if (chain.ChainPolicy.ApplicationPolicy.Count == 0)
                    {
                        // Authenticate the remote party: (e.g. when operating in server mode, authenticate the client).
                        chain.ChainPolicy.ApplicationPolicy.Add(_isClient ? s_serverAuthOid : s_clientAuthOid);
                    }

                    if (chainData.Length > 0)
                    {
                        Debug.Assert(X509Certificate2.GetCertContentType(chainData) is X509ContentType.Pkcs7);
#pragma warning disable SYSLIB0057
                        additionalCertificates.Import(chainData);
#pragma warning restore SYSLIB0057
                        chain.ChainPolicy.ExtraStore.AddRange(additionalCertificates);
                    }

                    bool checkCertName = !chain!.ChainPolicy!.VerificationFlags.HasFlag(X509VerificationFlags.IgnoreInvalidName);
                    sslPolicyErrors |= CertificateValidation.BuildChainAndVerifyProperties(chain, certificate, checkCertName && _isClient, TargetHostNameHelper.NormalizeHostName(_targetHost));
                }
                else if (_certificateRequired)
                {
                    sslPolicyErrors |= SslPolicyErrors.RemoteCertificateNotAvailable;
                }

                QUIC_TLS_ALERT_CODES result = QUIC_TLS_ALERT_CODES.QUIC_TLS_ALERT_CODE_SUCCESS;
                if (_validationCallback is not null)
                {
                    wrapException = true;
                    if (!_validationCallback(_connection, certificate, chain, sslPolicyErrors))
                    {
                        wrapException = false;
                        if (_isClient)
                        {
                            throw new AuthenticationException(SR.net_quic_cert_custom_validation);
                        }

                        result = QUIC_TLS_ALERT_CODES.QUIC_TLS_ALERT_CODE_BAD_CERTIFICATE;
                    }
                }
                else if (sslPolicyErrors != SslPolicyErrors.None)
                {
                    if (_isClient)
                    {
                        throw new AuthenticationException(SR.Format(SR.net_quic_cert_chain_validation, sslPolicyErrors));
                    }

                    result = QUIC_TLS_ALERT_CODES.QUIC_TLS_ALERT_CODE_BAD_CERTIFICATE;
                }

                return result;
            }
            catch (Exception ex)
            {
                if (wrapException)
                {
                    throw new QuicException(QuicError.CallbackError, null, SR.net_quic_callback_error, ex);
                }

                throw;
            }
            finally
            {
                foreach (X509Certificate2 intermediate in additionalCertificates) intermediate.Dispose();
                if (chain is not null)
                {
                    X509ChainElementCollection elements = chain.ChainElements;
                    for (int i = 0; i < elements.Count; i++)
                    {
                        elements[i].Certificate.Dispose();
                    }

                    chain.Dispose();
                }
            }
        }
    }
}
