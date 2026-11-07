using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using static Managed.Security.PicoTls;

namespace Managed.Security;

/// <summary>Creates the upstream empty-buffer representation. A null base is a
/// failed/unavailable buffer in picotls, even when its capacity is zero.</summary>
public static unsafe class PicotlsBuffer
{
    private static readonly byte[] _empty;

    static PicotlsBuffer()
    {
        _empty = GC.AllocateUninitializedArray<byte>(1, true);
        _empty[0] = 0;
    }

    public static st_ptls_buffer_t Create() => new st_ptls_buffer_t
    {
        @base = (byte*)Unsafe.AsPointer(ref MemoryMarshal.GetArrayDataReference(_empty))
    };
}