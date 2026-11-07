// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics.Tracing;
using Managed.Net.Quic;

namespace System.Net
{
    [EventSource(Name = "Private.InternalDiagnostics.Managed.Net.Quic")]
    internal sealed partial class NetEventSource
    {
        static partial void AdditionalCustomizedToString(object value, ref string? result)
        {
            if (value is MsQuicSafeHandle safeHandle)
            {
                result = safeHandle.ToString();
            }
        }
    }
}