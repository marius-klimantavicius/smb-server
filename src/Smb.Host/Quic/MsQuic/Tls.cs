using System;
using static Managed.Transport.MsQuic;
using System.Security.Cryptography;
using Managed.Security;

namespace Managed.Transport.Hosting;

public sealed unsafe partial class MsQuicHost
{
    private static void RegisterTls(ref MSQUIC_HOST_TABLE table)
    {
        table.CxPlatTlsGetProvider = &TlsProvider;
        table.CxPlatTlsSecConfigCreate = &TlsConfigCreate;
        table.CxPlatTlsSecConfigDelete = &TlsConfigDelete;
        table.CxPlatTlsSecConfigSetTicketKeys = &TlsSetTicketKeys;
        table.CxPlatTlsInitialize = &TlsInitialize;
        table.CxPlatTlsUninitialize = &TlsUninitialize;
        table.CxPlatTlsUpdateHkdfLabels = &TlsUpdateLabels;
        table.CxPlatTlsProcessData = &TlsProcess;
        table.CxPlatTlsParamSet = &TlsParamSet;
        table.CxPlatTlsParamGet = &TlsParamGet;
        table.CxPlatTlsExportKeyingMaterial = &TlsExport;
        table.QuicTlsPopulateOffloadKeys = &TlsOffload;
    }

    private static QUIC_TLS_PROVIDER TlsProvider(void* context)
    {
        _ = FromContext(context);
        return (QUIC_TLS_PROVIDER)PicotlsProviderIdentity;
    }

    private static uint TlsFailure(Exception error) => error switch
    {
        OutOfMemoryException => Status.OutOfMemory,
        ArgumentException => Status.InvalidParameter,
        ObjectDisposedException => Status.InvalidState,
        PlatformNotSupportedException => Status.NotSupported,
        _ => Status.TlsError,
    };

    private static uint TlsConfigCreate(void* context, QUIC_CREDENTIAL_CONFIG* config, CXPLAT_TLS_CREDENTIAL_FLAGS tlsFlags, CXPLAT_TLS_CALLBACKS* callbacks, void* completionContext, delegate*<QUIC_CREDENTIAL_CONFIG*, void*, uint, CXPLAT_SEC_CONFIG*, void> completion)
    {
        if (config == null || callbacks == null || completion == null)
            return Status.InvalidParameter;

        var flags = (uint)config->Flags;
        if ((int)config->Type != ManagedCredentialType || (flags & ~0x6077u) != 0 || ((uint)tlsFlags & ~1u) != 0)
            return Status.NotSupported;
        if (((flags & 2) != 0) != (config->AsyncHandler != null) || ((flags & 0x20) != 0 && (flags & 0x10) == 0))
            return Status.InvalidParameter;
        if ((flags & 0x10) != 0 && ((flags & 0x4000) == 0 || callbacks->CertificateReceived == null))
            return Status.NotSupported;
        if (config->CertificateContext == null || config->Reserved != null || config->Principal != null || config->CaCertificateFile != null || callbacks->ReceiveTP == null)
            return Status.InvalidParameter;

        var allowed = (flags & 0x2000) == 0 ? 3 : (uint)config->AllowedCipherSuites;
        if (allowed == 0 || (allowed & ~3u) != 0)
            return Status.NotSupported;

        var host = FromContext(context);
        TlsSecurityConfig? owner = null;
        CXPLAT_SEC_CONFIG* token;

        try
        {
            var credentials = host.Resource<TlsCredentials>(config->CertificateContext);
            if (credentials.Server == ((flags & 1) != 0))
                return Status.InvalidParameter;
            if ((flags & 0x10) != 0 && credentials.Verifier == null)
                return Status.NotSupported;

            var applicationApproval = (flags & 0x14) == 0x14;
            var needsPeerCertificate = !credentials.Server || (flags & 0x40) != 0;
            if ((flags & 4) != 0 && !applicationApproval)
                return Status.InvalidParameter;
            if (credentials.ApplicationValidation && needsPeerCertificate && !applicationApproval)
                return Status.InvalidParameter;
            if (!credentials.ApplicationValidation && (flags & (4u | 0x40u)) != 0)
                return Status.NotSupported;
            if ((flags & 0x40) != 0 && !credentials.Server)
                return Status.InvalidParameter;

            owner = new TlsSecurityConfig(credentials, *callbacks, ((uint)tlsFlags & 1) == 0, allowed, flags);
            token = (CXPLAT_SEC_CONFIG*)host.AddResource(owner);
            owner = null;
        }
        catch (Exception error)
        {
            return TlsFailure(error);
        }
        finally
        {
            owner?.Dispose();
        }

        // The caller takes ownership through this synchronous completion.
        completion(config, completionContext, Status.Success, token);
        return (flags & 2) != 0 ? Status.Pending : Status.Success;
    }

    private static void TlsConfigDelete(void* context, CXPLAT_SEC_CONFIG* configuration)
    {
        if (configuration != null)
            FromContext(context).ReleaseResource<TlsSecurityConfig>(configuration);
    }

    private static uint TlsSetTicketKeys(void* context, CXPLAT_SEC_CONFIG* configuration, QUIC_TICKET_KEY_CONFIG* keys, byte count)
    {
        if (configuration == null || keys == null || count is < 1 or > 16)
            return Status.InvalidParameter;

        var owner = FromContext(context).Resource<TlsSecurityConfig>(configuration);
        if (!owner.Credentials.Server || owner.Tickets == null) return Status.NotSupported;

        byte[][]? material = null;
        try
        {
            material = new byte[count][];
            var imported = new BclCryptoProvider.TicketKeyImport[count];
            for (var i = 0; i < count; i++)
            {
                if (keys[i].MaterialLength != 64)
                    return Status.InvalidParameter;

                material[i] = new ReadOnlySpan<byte>(keys[i].Material, 64).ToArray();
                imported[i] = new BclCryptoProvider.TicketKeyImport(new ReadOnlySpan<byte>(keys[i].Id, 16).ToArray(), material[i]);
            }

            owner.Tickets.ImportKeys(imported);
            return Status.Success;
        }
        catch (Exception error) { return TlsFailure(error); }
        finally
        {
            if (material != null)
            {
                foreach (var value in material)
                {
                    if (value != null!)
                        CryptographicOperations.ZeroMemory(value);
                }
            }
        }
    }

    private static uint TlsInitialize(void* context, CXPLAT_TLS_CONFIG* config, CXPLAT_TLS_PROCESS_STATE* state, CXPLAT_TLS** output)
    {
        if (output == null)
            return Status.InvalidParameter;

        *output = null;
        if (config == null || state == null || config->SecConfig == null || config->HkdfLabels == null || config->TPType != 0x39 || config->LocalTPLength > ushort.MaxValue || !PacketReadable(config->LocalTPBuffer, config->LocalTPLength) || !PacketReadable(config->ResumptionTicketBuffer, config->ResumptionTicketLength))
            return Status.InvalidParameter;

        var host = FromContext(context);
        TlsConnection? connection = null;
        TlsConnection registered;
        CXPLAT_TLS* token;
        try
        {
            var security = host.Resource<TlsSecurityConfig>(config->SecConfig);
            if (security.Credentials.Server != (config->IsServer != 0))
                return Status.InvalidParameter;

            connection = new TlsConnection(host, security, config, state);
            token = (CXPLAT_TLS*)host.AddResource(connection);
            registered = connection;
            connection = null;
        }
        catch (Exception error)
        {
            return TlsFailure(error);
        }
        finally
        {
            connection?.Dispose();
        }

        registered.AttachToken(token);

        // Failure before registration leaves both original inputs with the C caller.
        // After transfer, allocator ownership violations are fatal host invariants.
        host.FreePlatformMemory(config->LocalTPBuffer, QUIC_POOL_TLS_TRANSPARAMS);
        if (config->ResumptionTicketBuffer != null)
            host.FreePlatformMemory(config->ResumptionTicketBuffer, QUIC_POOL_CRYPTO_RESUMPTION_TICKET);

        *output = token;
        return Status.Success;
    }

    private static void TlsUninitialize(void* context, CXPLAT_TLS* connection)
    {
        if (connection != null)
            FromContext(context).ReleaseResource<TlsConnection>(connection);
    }

    private static void TlsUpdateLabels(void* context, CXPLAT_TLS* connection, QUIC_HKDF_LABELS* labels)
    {
        if (labels == null)
            FatalInvariant("Null TLS HKDF labels");

        var owner = FromContext(context).Resource<TlsConnection>(connection);
        lock (owner.Gate) owner.Labels = *labels;
    }

    private static CXPLAT_TLS_RESULT_FLAGS TlsProcess(void* context, CXPLAT_TLS* connection, CXPLAT_TLS_DATA_TYPE type, byte* input, uint* length, CXPLAT_TLS_PROCESS_STATE* state)
    {
        if (length == null || state == null || connection == null)
            FatalInvariant("Invalid TLS process state");

        var owner = FromContext(context).Resource<TlsConnection>(connection);
        return owner.Process(type, input, length, state);
    }

    private static uint TlsParamSet(void* context, CXPLAT_TLS* connection, uint parameter, uint length, void* buffer)
    {
        _ = FromContext(context).Resource<TlsConnection>(connection);
        return Status.NotSupported;
    }

    private static uint TlsParamGet(void* context, CXPLAT_TLS* connection, uint parameter, uint* length, void* buffer) => FromContext(context).Resource<TlsConnection>(connection).GetParameter(parameter, length, buffer);

    private static uint TlsExport(void* context, CXPLAT_TLS* connection, byte* label, byte* exportContext, uint contextLength, byte* output, uint outputLength)
    {
        _ = FromContext(context).Resource<TlsConnection>(connection);
        return Status.NotSupported;
    }

    private static byte TlsOffload(void* context, CXPLAT_TLS* connection, QUIC_PACKET_KEY* key, byte* name, CXPLAT_QEO_CONNECTION* offload)
    {
        _ = FromContext(context).Resource<TlsConnection>(connection);
        return 0;
    }
}