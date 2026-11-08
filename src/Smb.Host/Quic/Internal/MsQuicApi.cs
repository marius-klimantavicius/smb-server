// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices.Marshalling;
using Managed.Transport.Hosting;
using static Managed.Transport.MsQuic;

namespace Managed.Net.Quic;

internal sealed unsafe partial class MsQuicApi
{
    private static readonly Version s_minMsQuicVersion = new Version(2, 2, 2);

    private static readonly delegate* <uint, void**, uint> MsQuicOpenVersion;
    private static readonly delegate* <QUIC_API_TABLE*, void> MsQuicClose;

    public MsQuicSafeHandle Registration { get; }

    public QUIC_API_TABLE* ApiTable { get; }

    // This is workaround for a bug in ILTrimmer.
    // Without these DynamicDependency attributes, .ctor() will be removed from the safe handles.
    // Remove once fixed: https://github.com/mono/linker/issues/1660
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicConstructors, typeof(MsQuicSafeHandle))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.PublicConstructors, typeof(MsQuicContextSafeHandle))]
    private MsQuicApi(QUIC_API_TABLE* apiTable)
    {
        ApiTable = apiTable;

        fixed (byte* pAppName = "Managed.Net.Quic"u8)
        {
            var cfg = new QUIC_REGISTRATION_CONFIG
            {
                AppName = pAppName,
                ExecutionProfile = QUIC_EXECUTION_PROFILE.QUIC_EXECUTION_PROFILE_LOW_LATENCY
            };

            QUIC_HANDLE* handle;
            ThrowHelper.ThrowIfMsQuicError(ApiTable->RegistrationOpen(&cfg, &handle), "RegistrationOpen failed");

            Registration = new MsQuicSafeHandle(handle, apiTable->RegistrationClose, SafeHandleType.Registration);
        }
    }

    private static readonly Lazy<MsQuicApi> _api = new Lazy<MsQuicApi>(AllocateMsQuicApi);
    internal static MsQuicApi Api => _api.Value;

    internal static Version? Version { get; }

    internal static bool IsQuicSupported { get; }

    internal static string MsQuicLibraryVersion { get; } = "unknown";
    internal static string? NotSupportedReason { get; }

    // Workaround for https://github.com/microsoft/msquic/issues/4132
    internal static bool SupportsAsyncCertValidation => Version > new Version(2, 4);

    // Process lifetime, matching the shared API table and registration.
    internal static Managed.Transport.Hosting.MsQuicHost Host { get; } = new MsQuicHost();

#pragma warning disable CA1810 // Initialize all static fields in 'MsQuicApi' when those fields are declared and remove the explicit static constructor
    static MsQuicApi()
    {
        Version = default;

        // MsQuic is using DualMode sockets and that will fail even for IPv4 if AF_INET6 is not available.
        if (!Socket.OSSupportsIPv6)
        {
            NotSupportedReason = "OS does not support dual mode sockets.";
            if (NetEventSource.Log.IsEnabled())
            {
                NetEventSource.Info(null, NotSupportedReason);
            }

            return;
        }

        Host.Install();
        MsQuicOpenVersion = MsQuicFunctionPointers.MsQuicOpenVersion;
        MsQuicClose = MsQuicFunctionPointers.MsQuicClose;

        if (!TryOpenMsQuic(out var apiTable, out var openStatus))
        {
            // Too low version of the library (likely pre-2.0)
            NotSupportedReason = $"MsQuicOpenVersion for version {s_minMsQuicVersion.Major} returned {openStatus} status code.";
            if (NetEventSource.Log.IsEnabled())
            {
                NetEventSource.Info(null, NotSupportedReason);
            }

            return;
        }

        try
        {
            // Check version
            uint paramSize;
            uint status;

            paramSize = 4 * sizeof(uint);
            var libVersion = stackalloc uint[4];
            status = apiTable->GetParam(null, QUIC_PARAM_GLOBAL_LIBRARY_VERSION, &paramSize, libVersion);
            if (StatusFailed(status))
            {
                if (NetEventSource.Log.IsEnabled())
                {
                    NetEventSource.Error(null, $"Cannot retrieve {nameof(QUIC_PARAM_GLOBAL_LIBRARY_VERSION)} from MsQuic library: '{status}'.");
                }

                return;
            }

            Version = new Version((int)libVersion[0], (int)libVersion[1], (int)libVersion[2], (int)libVersion[3]);

            paramSize = 64 * sizeof(byte);
            var libGitHash = stackalloc byte[64];
            status = apiTable->GetParam(null, QUIC_PARAM_GLOBAL_LIBRARY_GIT_HASH, &paramSize, libGitHash);
            if (StatusFailed(status))
            {
                if (NetEventSource.Log.IsEnabled())
                {
                    NetEventSource.Error(null, $"Cannot retrieve {nameof(QUIC_PARAM_GLOBAL_LIBRARY_GIT_HASH)} from MsQuic library: '{status}'.");
                }

                return;
            }

            var gitHash = Utf8StringMarshaller.ConvertToManaged(libGitHash);

            MsQuicLibraryVersion = $"Managed.MsQuic {Version} ({gitHash})";

            if (Version < s_minMsQuicVersion)
            {
                NotSupportedReason = $"Incompatible MsQuic library version '{Version}', expecting higher than '{s_minMsQuicVersion}'.";
                if (NetEventSource.Log.IsEnabled())
                {
                    NetEventSource.Info(null, NotSupportedReason);
                }

                return;
            }

            if (NetEventSource.Log.IsEnabled())
            {
                NetEventSource.Info(null, $"Loaded MsQuic library '{MsQuicLibraryVersion}'.");
            }

            IsQuicSupported = true;
        }
        finally
        {
            // Gracefully close the API table to free resources. The API table will be allocated lazily again if needed
            MsQuicClose(apiTable);
        }
    }
#pragma warning restore CA1810

    private static MsQuicApi AllocateMsQuicApi()
    {
        Debug.Assert(IsQuicSupported);

        if (!TryOpenMsQuic(out var apiTable, out var openStatus))
        {
            throw ThrowHelper.GetExceptionForMsQuicStatus(openStatus);
        }

        return new MsQuicApi(apiTable);
    }

    private static bool TryOpenMsQuic(out QUIC_API_TABLE* apiTable, out uint openStatus)
    {
        Debug.Assert(MsQuicOpenVersion != null);

        QUIC_API_TABLE* table = null;
        openStatus = MsQuicOpenVersion((uint)s_minMsQuicVersion.Major, (void**)&table);
        if (StatusFailed(openStatus))
        {
            apiTable = null;
            return false;
        }

        apiTable = table;
        return true;
    }

    public static bool StatusSucceeded(uint status)
    {
        return unchecked((int)status) <= 0;
    }

    public static bool StatusFailed(uint status)
    {
        return unchecked((int)status) > 0;
    }
}