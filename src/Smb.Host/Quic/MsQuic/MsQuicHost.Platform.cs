using static Managed.Transport.MsQuic;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using static Managed.Transport.MsQuic.Libc;

namespace Managed.Transport.Hosting;

public sealed unsafe partial class MsQuicHost
{
    private readonly Lock _allocationGate = new Lock();
    private readonly Dictionary<nuint, PlatformAllocation> _platformAllocations = new Dictionary<UIntPtr, PlatformAllocation>();
    private int _platformLoaded;
    private int _platformInitialized;

    private sealed class PlatformAllocation(byte[] backing, ulong size, uint tag)
    {
        internal readonly byte[] Backing = backing;
        internal readonly ulong Size = size;
        internal readonly uint Tag = tag;
    }

    internal int OutstandingPlatformAllocations
    {
        get
        {
            lock (_allocationGate)
                return _platformAllocations.Count;
        }
    }

    internal void* AllocatePlatformMemory(ulong size, uint tag, bool zero = true)
    {
        // Checked managed backing limit; a rejected allocation never aliases another domain.
        if (size > (ulong)Array.MaxLength - 15)
            return null;

        try
        {
            var bytes = zero ? GC.AllocateArray<byte>((int)size + 15, pinned: true) : GC.AllocateUninitializedArray<byte>((int)size + 15, pinned: true);
            fixed (byte* start = bytes)
            {
                var address = ((nuint)start + 15) & ~(nuint)15;
                lock (_allocationGate)
                    _platformAllocations.Add(address, new PlatformAllocation(bytes, size, tag));

                return (void*)address;
            }
        }
        catch (OutOfMemoryException)
        {
            return null;
        }
    }

    internal void FreePlatformMemory(void* address, uint tag)
    {
        if (address == null) return;

        lock (_allocationGate)
        {
            if (!_platformAllocations.TryGetValue((nuint)address, out var allocation) || allocation.Tag != tag)
                FatalInvariant("CxPlatFree: wrong allocator domain, tag, or double free");

            _platformAllocations.Remove((nuint)address);
        }
    }

    private static void RegisterPlatform(ref MSQUIC_HOST_TABLE table)
    {
        table.CxPlatAlloc = &PlatformAlloc;
        table.CxPlatAllocUninitialized = &PlatformAllocUninitialized;
        table.CxPlatFree = &PlatformFree;
        table.CxPlatCurThreadID = &PlatformThreadId;
        table.CxPlatProcCurrentNumber = &PlatformProcessor;
        table.CxPlatRandom = &PlatformRandom;
        table.CxPlatGetAbsoluteTime = &PlatformAbsoluteTime;
        table.CxPlatGetTimerResolution = &PlatformTimerResolution;
        table.CxPlatTimeEpochMs64 = &PlatformEpoch;
        table.CxPlatTimeUs64 = &PlatformTime;
        table.CxPlatSleep = &PlatformSleep;
        table.CxPlatSchedulerYield = &PlatformYield;
        table.CxPlatLockInitialize = &PlatformLockInitialize;
        table.CxPlatLockAcquire = &PlatformLockAcquire;
        table.CxPlatLockRelease = &PlatformLockRelease;
        table.CxPlatLockUninitialize = &PlatformLockDelete;
        table.CxPlatRwLockInitialize = &PlatformRwInitialize;
        table.CxPlatRwLockAcquireExclusive = &PlatformRwWrite;
        table.CxPlatRwLockAcquireShared = &PlatformRwRead;
        table.CxPlatRwLockReleaseExclusive = &PlatformRwWriteRelease;
        table.CxPlatRwLockReleaseShared = &PlatformRwReadRelease;
        table.CxPlatRwLockUninitialize = &PlatformRwDelete;
        table.CxPlatEventInitialize = &PlatformEventInitialize;
        table.CxPlatInternalEventSet = &PlatformEventSet;
        table.CxPlatInternalEventReset = &PlatformEventReset;
        table.CxPlatInternalEventWaitForever = &PlatformEventWait;
        table.CxPlatInternalEventWaitWithTimeout = &PlatformEventWaitTimed;
        table.CxPlatInternalEventUninitialize = &PlatformEventDelete;
        table.CxPlatThreadCreate = &PlatformThreadCreate;
        table.CxPlatThreadWait = &PlatformThreadWait;
        table.CxPlatThreadDelete = &PlatformThreadDelete;
        table.CxPlatStorageOpen = &PlatformStorageOpen;
        table.CxPlatStorageReadValue = &PlatformStorageRead;
        table.CxPlatStorageClose = &PlatformStorageClose;
        table.CxPlatSystemLoad = &PlatformLoad;
        table.CxPlatInitialize = &PlatformInitialize;
        table.CxPlatUninitialize = &PlatformUninitialize;
        table.CxPlatSystemUnload = &PlatformUnload;
        table.CxPlatLogAssert = &PlatformLogAssert;
        table.quic_bugcheck = &PlatformBugcheck;

        RegisterQueue(ref table);
    }

    private static void* PlatformAlloc(void* context, ulong size, uint tag) => FromContext(context).AllocatePlatformMemory(size, tag);
    private static void* PlatformAllocUninitialized(void* context, ulong size, uint tag) => FromContext(context).AllocatePlatformMemory(size, tag, false);
    private static void PlatformFree(void* context, void* address, uint tag) => FromContext(context).FreePlatformMemory(address, tag);
    private static ulong MonotonicMicroseconds() => (ulong)((UInt128)(ulong)Stopwatch.GetTimestamp() * 1_000_000 / (ulong)Stopwatch.Frequency);
    private static ulong PlatformTime(void* context) => MonotonicMicroseconds();
    private static long PlatformEpoch(void* context) => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    private static ulong PlatformTimerResolution(void* context) => Math.Max(1UL, (1_000_000UL + (ulong)Stopwatch.Frequency - 1) / (ulong)Stopwatch.Frequency);

    private static void PlatformAbsoluteTime(void* context, ulong delta, timespec* time)
    {
        var now = MonotonicMicroseconds();
        if (time == null || delta > (ulong.MaxValue - now) / 1000)
            FatalInvariant("CxPlatGetAbsoluteTime: invalid duration or output");

        var us = now + delta * 1000;
        time->tv_sec = checked((long)(us / 1_000_000));
        time->tv_nsec = (long)(us % 1_000_000) * 1000;
    }

    private static uint PlatformThreadId(void* context) => (uint)Environment.CurrentManagedThreadId;
    private static uint PlatformProcessor(void* context) => (uint)Thread.GetCurrentProcessorId() % FromContext(context).ProcessorCount;
    private static void PlatformYield(void* context) => Thread.Yield();

    private static void PlatformSleep(void* context, uint milliseconds)
    {
        ulong remaining = milliseconds;
        while (remaining > int.MaxValue)
        {
            Thread.Sleep(int.MaxValue);
            remaining -= int.MaxValue;
        }

        Thread.Sleep((int)remaining);
    }

    private static uint PlatformRandom(void* context, uint length, void* buffer)
    {
        if (length > int.MaxValue || (length != 0 && buffer == null))
            return Status.InvalidParameter;

        try
        {
            RandomNumberGenerator.Fill(new Span<byte>(buffer, (int)length));
            return Status.Success;
        }
        catch (CryptographicException)
        {
            return Status.InternalError;
        }
    }

    private static void PlatformLoad(void* context)
    {
        if (Interlocked.CompareExchange(ref FromContext(context)._platformLoaded, 1, 0) != 0)
            FatalInvariant("Platform already loaded");
    }

    private static uint PlatformInitialize(void* context)
    {
        var host = FromContext(context);
        if (Volatile.Read(ref host._platformLoaded) != 1 || Interlocked.CompareExchange(ref host._platformInitialized, 1, 0) != 0)
            return Status.InvalidState;

        return Status.Success;
    }

    private static void PlatformUninitialize(void* context)
    {
        if (Interlocked.CompareExchange(ref FromContext(context)._platformInitialized, 0, 1) != 1)
            FatalInvariant("Platform is not initialized");

        // Pinned library.c drains this one global rundown during normal teardown
        // but omits its event uninitialization (the failure path does uninitialize
        // it). Native inline event storage hid the lifetime; our PAL owns a token.
        // CxPlatUninitialize runs after the cleanup thread and worker pool join.
        // Repair only this exact drained owner, never sweep unrelated resources.
        ref var library = ref Globals.MsQuicLib;
        if (library.RegistrationCloseCleanupRundown.RundownComplete.Handle != 0)
        {
            if (library.RegistrationCloseCleanupShutdown == 0 || library.RegistrationCloseCleanupWorker != 0 || library.RegistrationCloseCleanupRundown.RefCount != 0)
                FatalInvariant("Global registration cleanup rundown is not drained.");
            fixed (CXPLAT_EVENT* complete = &library.RegistrationCloseCleanupRundown.RundownComplete)
                PlatformEventDelete(context, complete);
        }
    }

    private static void PlatformUnload(void* context)
    {
        var host = FromContext(context);
        if (Volatile.Read(ref host._platformInitialized) != 0 || Interlocked.CompareExchange(ref host._platformLoaded, 0, 1) != 1)
            FatalInvariant("Platform unload order");
    }

    private static uint PlatformStorageOpen(void* context, byte* path, delegate*<void*, void> callback, void* state, CXPLAT_STORAGE_OPEN_FLAGS flags, CXPLAT_STORAGE** result)
    {
        if (result == null)
            return Status.InvalidParameter;

        *result = null;
        return Status.NotSupported;
    }

    private static uint PlatformStorageRead(void* context, CXPLAT_STORAGE* storage, byte* name, byte* buffer, uint* length) => Status.NotSupported;

    private static void PlatformStorageClose(void* context, CXPLAT_STORAGE* storage)
    {
        if (storage != null)
            FatalInvariant("Persistent storage is not supported by this host");
    }

    private static string PlatformText(byte* text) => text == null ? "<null>" : Marshal.PtrToStringUTF8((nint)text) ?? "";

    private static void PlatformLogAssert(void* context, byte* file, int line, byte* expression) => Console.Error.WriteLine($"MsQuic assertion {PlatformText(file)}:{line}: {PlatformText(expression)}");

    private static void PlatformBugcheck(void* context, byte* file, int line, byte* expression) => FatalInvariant($"MsQuic assertion {PlatformText(file)}:{line}: {PlatformText(expression)}");

    private sealed class PlatformLock : IDisposable
    {
        private readonly object _gate = new object();
        private int _users;
        private bool _disposed;

        internal void Enter()
        {
            Interlocked.Increment(ref _users);
            Monitor.Enter(_gate);

            if (_disposed)
                FatalInvariant("Acquire disposed recursive lock");
        }

        internal void Exit()
        {
            if (!Monitor.IsEntered(_gate))
                FatalInvariant("Release recursive lock from non-owner");

            Interlocked.Decrement(ref _users);
            Monitor.Exit(_gate);
        }

        public void Dispose()
        {
            lock (_gate)
            {
                if (_disposed || Volatile.Read(ref _users) != 0)
                    FatalInvariant("Destroy active recursive lock");

                _disposed = true;
            }
        }
    }

    private static void PlatformLockInitialize(void* context, CXPLAT_LOCK* value)
    {
        try
        {
            value->Handle = (ulong)FromContext(context).AddResource(new PlatformLock());
        }
        catch (OutOfMemoryException)
        {
            FatalInvariant("Lock initialization allocation failure");
        }
    }

    private static void PlatformLockAcquire(void* context, CXPLAT_LOCK* value) => FromContext(context).Resource<PlatformLock>((void*)value->Handle).Enter();
    private static void PlatformLockRelease(void* context, CXPLAT_LOCK* value) => FromContext(context).Resource<PlatformLock>((void*)value->Handle).Exit();

    private static void PlatformLockDelete(void* context, CXPLAT_LOCK* value)
    {
        FromContext(context).ReleaseResource<PlatformLock>((void*)value->Handle);
        value->Handle = 0;
    }

    private sealed class PlatformRwLock : IDisposable
    {
        private readonly ReaderWriterLockSlim _value = new ReaderWriterLockSlim(LockRecursionPolicy.SupportsRecursion);

        internal void Enter(bool write)
        {
            try
            {
                if (write)
                    _value.EnterWriteLock();
                else
                    _value.EnterReadLock();
            }
            catch (Exception exception)
            {
                FatalInvariant("Invalid RW lock acquire: " + exception);
            }
        }

        internal void Exit(bool write)
        {
            try
            {
                if (write)
                    _value.ExitWriteLock();
                else
                    _value.ExitReadLock();
            }
            catch (Exception exception)
            {
                FatalInvariant("Invalid RW lock release: " + exception);
            }
        }

        public void Dispose()
        {
            try
            {
                _value.Dispose();
            }
            catch (Exception exception)
            {
                FatalInvariant("Invalid RW lock cleanup: " + exception);
            }
        }
    }

    private static void PlatformRwInitialize(void* context, CXPLAT_RW_LOCK* value)
    {
        try
        {
            value->Handle = (ulong)FromContext(context).AddResource(new PlatformRwLock());
        }
        catch (OutOfMemoryException)
        {
            FatalInvariant("RW lock initialization allocation failure");
        }
    }

    private static void PlatformRwRead(void* context, CXPLAT_RW_LOCK* value) => FromContext(context).Resource<PlatformRwLock>((void*)value->Handle).Enter(false);
    private static void PlatformRwWrite(void* context, CXPLAT_RW_LOCK* value) => FromContext(context).Resource<PlatformRwLock>((void*)value->Handle).Enter(true);
    private static void PlatformRwReadRelease(void* context, CXPLAT_RW_LOCK* value) => FromContext(context).Resource<PlatformRwLock>((void*)value->Handle).Exit(false);
    private static void PlatformRwWriteRelease(void* context, CXPLAT_RW_LOCK* value) => FromContext(context).Resource<PlatformRwLock>((void*)value->Handle).Exit(true);

    private static void PlatformRwDelete(void* context, CXPLAT_RW_LOCK* value)
    {
        FromContext(context).ReleaseResource<PlatformRwLock>((void*)value->Handle);
        value->Handle = 0;
    }

    private sealed class PlatformEvent(bool manual, bool signaled) : IDisposable
    {
        private readonly object _gate = new object();
        private bool _signaled = signaled;
        private bool _disposed;
        private int _waiters;

        internal void Set(bool value)
        {
            lock (_gate)
            {
                Check();
                _signaled = value;
                if (value) Monitor.PulseAll(_gate);
            }
        }

        private void Check()
        {
            if (_disposed)
                FatalInvariant("Operation on disposed event");
        }

        internal bool Wait(uint timeout)
        {
            var deadline = timeout == uint.MaxValue ? ulong.MaxValue : MonotonicMicroseconds() + (ulong)timeout * 1000;
            lock (_gate)
            {
                Check();
                _waiters++;

                try
                {
                    while (!_signaled)
                    {
                        var remaining = RemainingWait(deadline);
                        if (remaining == 0) return false;

                        Monitor.Wait(_gate, remaining);
                        Check();
                    }

                    if (!manual)
                        _signaled = false;

                    return true;
                }
                finally
                {
                    _waiters--;
                }
            }
        }

        public void Dispose()
        {
            lock (_gate)
            {
                if (_disposed || _waiters != 0)
                    FatalInvariant("Destroy event with active waiters");

                _disposed = true;
            }
        }
    }

    private static int RemainingWait(ulong deadline)
    {
        if (deadline == ulong.MaxValue)
            return Timeout.Infinite;

        var now = MonotonicMicroseconds();
        if (CxPlatTimeAtOrBefore64(deadline, now) != 0)
            return 0;

        return (int)Math.Min((CxPlatTimeDiff64(now, deadline) + 999) / 1000, int.MaxValue);
    }

    private static void PlatformEventInitialize(void* context, CXPLAT_EVENT* value, byte manual, byte initial)
    {
        try
        {
            value->Handle = (ulong)FromContext(context).AddResource(new PlatformEvent(manual != 0, initial != 0));
        }
        catch (OutOfMemoryException)
        {
            FatalInvariant("Event initialization allocation failure");
        }
    }

    private static void PlatformEventSet(void* context, CXPLAT_EVENT* value) => FromContext(context).Resource<PlatformEvent>((void*)value->Handle).Set(true);
    private static void PlatformEventReset(void* context, CXPLAT_EVENT* value) => FromContext(context).Resource<PlatformEvent>((void*)value->Handle).Set(false);
    private static void PlatformEventWait(void* context, CXPLAT_EVENT* value) => FromContext(context).Resource<PlatformEvent>((void*)value->Handle).Wait(uint.MaxValue);
    private static byte PlatformEventWaitTimed(void* context, CXPLAT_EVENT* value, uint timeout) => FromContext(context).Resource<PlatformEvent>((void*)value->Handle).Wait(timeout) ? (byte)1 : (byte)0;

    private static void PlatformEventDelete(void* context, CXPLAT_EVENT* value)
    {
        FromContext(context).ReleaseResource<PlatformEvent>((void*)value->Handle);
        value->Handle = 0;
    }

    private sealed class PlatformThread : IDisposable
    {
        internal readonly Thread Thread;
        internal bool Started;
        internal bool Joined;

        internal PlatformThread(CXPLAT_THREAD_CONFIG config)
        {
            var callback = config.Callback;
            var context = (nuint)config.Context;

            Thread = new Thread(() =>
            {
                try
                {
                    callback((void*)context);
                }
                catch (Exception exception)
                {
                    FatalInvariant("Exception escaped translated worker: " + exception);
                }
            }) { IsBackground = true, Name = config.Name == null ? "msquic" : PlatformText(config.Name) };
        }

        internal void Join()
        {
            if (Thread == Thread.CurrentThread || !Started)
                FatalInvariant("Invalid worker self-join or unstarted thread");

            Thread.Join();
            Joined = true;
        }

        public void Dispose()
        {
            if (Started && (!Joined || Thread.IsAlive))
                FatalInvariant("Delete unjoined worker thread");
        }
    }

    private static uint PlatformThreadCreate(void* context, CXPLAT_THREAD_CONFIG* config, ulong* output)
    {
        if (output == null || config == null || config->Callback == null)
            return Status.InvalidParameter;

        *output = 0;
        if ((config->Flags & ~1) != 0)
            return Status.NotSupported; // Ideal processor is a hint, not affinity.

        var host = FromContext(context);
        void* token = null;
        try
        {
            var thread = new PlatformThread(*config);
            token = host.AddResource(thread);
            *output = (ulong)token;
            thread.Thread.Start();
            thread.Started = true;
            return Status.Success;
        }
        catch (Exception ex) when (ex is OutOfMemoryException or ThreadStateException)
        {
            *output = 0;
            if (token != null)
                host.ReleaseResource<PlatformThread>(token);

            return Status.OutOfMemory;
        }
    }

    private static void PlatformThreadWait(void* context, ulong* token) => FromContext(context).Resource<PlatformThread>((void*)*token).Join();

    private static void PlatformThreadDelete(void* context, ulong* token)
    {
        FromContext(context).ReleaseResource<PlatformThread>((void*)*token);
        *token = 0;
    }
}