using static Managed.Transport.MsQuic;
using System;
using System.Threading;

namespace Managed.Transport.Hosting;

public sealed unsafe partial class MsQuicHost
{
    private static void RegisterQueue(ref MSQUIC_HOST_TABLE table)
    {
        table.CxPlatEventQInitialize = &PlatformQueueInitialize;
        table.CxPlatEventQCleanup = &PlatformQueueCleanup;
        table.CxPlatEventQEnqueue = &PlatformQueueEnqueue;
        table.CxPlatEventQDequeue = &PlatformQueueDequeue;
        table.CxPlatEventQReturn = &PlatformQueueReturn;
        table.CxPlatSqeInitialize = &PlatformSqeInitialize;
        table.CxPlatSqeCleanup = &PlatformSqeCleanup;
    }

    private sealed class PlatformQueue : IDisposable
    {
        internal readonly object Gate = new object();
        internal readonly PlatformSqe?[] Batch = new PlatformSqe?[16];
        internal PlatformSqe? Head;
        internal PlatformSqe? Tail;
        internal int Registrations;
        internal int BatchCount;
        internal int Consumer;
        internal bool Closed;

        internal void Append(PlatformSqe sqe)
        {
            sqe.Pending = true;
            sqe.Previous = Tail;
            sqe.Next = null;
            if (Tail != null)
                Tail.Next = sqe;
            else
                Head = sqe;

            Tail = sqe;
        }

        internal void Remove(PlatformSqe sqe)
        {
            if (!sqe.Pending)
                return;

            if (sqe.Previous != null)
                sqe.Previous.Next = sqe.Next;
            else
                Head = sqe.Next;

            if (sqe.Next != null)
                sqe.Next.Previous = sqe.Previous;
            else
                Tail = sqe.Previous;

            sqe.Pending = false;
            sqe.Previous = sqe.Next = null;
        }

        public void Dispose()
        {
            lock (Gate)
            {
                if (Closed || BatchCount != 0 || Registrations != 0 || Head != null)
                    FatalInvariant("Destroy event queue before registrations and batches drain");

                Closed = true;
                Monitor.PulseAll(Gate);
            }
        }
    }

    private sealed class PlatformSqe(PlatformQueue queue, CXPLAT_SQE* address) : IDisposable
    {
        internal readonly PlatformQueue Queue = queue;
        internal readonly CXPLAT_SQE* Address = address;
        internal PlatformSqe? Previous;
        internal PlatformSqe? Next;
        internal bool Pending;
        internal bool Closing;
        internal bool Registered;
        internal int InFlight;
        internal bool Disposed;
        internal Action? AfterDrain;
        internal PlatformSqe? DrainNext;

        internal void CloseAndWait()
        {
            lock (Queue.Gate)
            {
                if (Disposed || AfterDrain != null)
                    FatalInvariant("SQE cleanup twice");

                Closing = true;
                Queue.Remove(this);

                if (InFlight != 0 && Queue.Consumer == Environment.CurrentManagedThreadId)
                    FatalInvariant("Cannot synchronously clean up an SQE from its own active completion batch");

                while (InFlight != 0)
                    Monitor.Wait(Queue.Gate);
            }
        }

        public void Dispose()
        {
            CloseAndWait();
            lock (Queue.Gate)
            {
                if (Registered)
                {
                    Queue.Registrations--;
                    Registered = false;
                }

                Disposed = true;
            }
        }
    }

    private static byte PlatformQueueInitialize(void* context, CXPLAT_EVENTQ* output)
    {
        if (output == null)
            return 0;

        output->Handle = 0;
        try
        {
            output->Handle = (ulong)FromContext(context).AddResource(new PlatformQueue());
            return 1;
        }
        catch (OutOfMemoryException)
        {
            return 0;
        }
    }

    private static void PlatformQueueCleanup(void* context, CXPLAT_EVENTQ* queue)
    {
        FromContext(context).ReleaseResource<PlatformQueue>((void*)queue->Handle);
        queue->Handle = 0;
    }

    private static byte PlatformSqeInitialize(void* context, CXPLAT_EVENTQ* queue, delegate*<CXPLAT_CQE*, void> completion, CXPLAT_SQE* output)
    {
        if (output == null || completion == null)
            return 0;

        output->Handle = 0;
        output->Completion = null;

        var host = FromContext(context);
        var owner = host.Resource<PlatformQueue>((void*)queue->Handle);
        void* token = null;
        try
        {
            var record = new PlatformSqe(owner, output);
            token = host.AddResource(record);

            lock (owner.Gate)
            {
                if (owner.Closed)
                    FatalInvariant("SQE initialized on a closed queue");

                owner.Registrations++;
                record.Registered = true;
                output->Completion = completion;
                output->Handle = (ulong)token;
            }

            return 1;
        }
        catch (OutOfMemoryException)
        {
            if (token != null)
                host.ReleaseResource<PlatformSqe>(token);
            return 0;
        }
    }

    private static byte PlatformQueueEnqueue(void* context, CXPLAT_EVENTQ* queue, CXPLAT_SQE* sqe)
    {
        var host = FromContext(context);
        var owner = host.Resource<PlatformQueue>((void*)queue->Handle);
        var record = host.Resource<PlatformSqe>((void*)sqe->Handle);

        lock (owner.Gate)
        {
            if (!ReferenceEquals(record.Queue, owner) || owner.Closed || record.Closing)
                return 0;

            // Queue nodes are allocated during registration; shutdown cannot fail
            // merely because the process cannot allocate another completion object.
            if (!record.Pending)
                owner.Append(record);

            Monitor.Pulse(owner.Gate);
            return 1;
        }
    }

    private static uint PlatformQueueDequeue(void* context, CXPLAT_EVENTQ* queue, CXPLAT_CQE* output, uint capacity, uint timeout)
    {
        if (output == null || capacity == 0)
            FatalInvariant("Invalid CQE output or capacity");

        var owner = FromContext(context).Resource<PlatformQueue>((void*)queue->Handle);
        var deadline = timeout == uint.MaxValue ? ulong.MaxValue : MonotonicMicroseconds() + (ulong)timeout * 1000;
        lock (owner.Gate)
        {
            if (owner.Consumer == 0)
                owner.Consumer = Environment.CurrentManagedThreadId;

            if (owner.Closed || owner.Consumer != Environment.CurrentManagedThreadId || owner.BatchCount != 0)
                FatalInvariant("Concurrent event queue consumers or unreturned batch");

            while (owner.Head == null)
            {
                var remaining = RemainingWait(deadline);
                if (remaining == 0)
                    return 0;

                Monitor.Wait(owner.Gate, remaining);
                if (owner.Closed)
                    FatalInvariant("Active worker queue closed before shutdown");
            }

            var limit = (int)Math.Min(capacity, (uint)owner.Batch.Length);
            while (owner.BatchCount < limit && owner.Head is { } item)
            {
                owner.Remove(item);
                item.InFlight++;
                owner.Batch[owner.BatchCount] = item;
                output[owner.BatchCount].Sqe = item.Address;
                owner.BatchCount++;
            }

            return (uint)owner.BatchCount;
        }
    }

    private static void PlatformQueueReturn(void* context, CXPLAT_EVENTQ* queue, uint count)
    {
        var owner = FromContext(context).Resource<PlatformQueue>((void*)queue->Handle);
        PlatformSqe? drained = null;
        lock (owner.Gate)
        {
            if (owner.Closed || owner.Consumer != Environment.CurrentManagedThreadId || count == 0 || count != owner.BatchCount)
                FatalInvariant("CQE return does not match outstanding consumer batch");

            for (var index = 0; index < owner.BatchCount; index++)
            {
                var item = owner.Batch[index]!;
                if (--item.InFlight != 0)
                    FatalInvariant("Invalid SQE in-flight accounting");

                owner.Batch[index] = null;
                if (item.AfterDrain != null)
                {
                    item.DrainNext = drained;
                    drained = item;
                }
            }

            owner.BatchCount = 0;
            Monitor.PulseAll(owner.Gate);
        }

        // Finalizers may free containing socket storage or unregister other
        // notifications. They run only after the entire batch, without our gate.
        while (drained != null)
        {
            var item = drained;
            drained = item.DrainNext;
            item.DrainNext = null;
            var callback = item.AfterDrain!;
            item.AfterDrain = null;

            try
            {
                callback();
            }
            catch (Exception exception)
            {
                FatalInvariant("Deferred SQE cleanup failed: " + exception);
            }
        }
    }

    private static void PlatformSqeCleanup(void* context, CXPLAT_EVENTQ* queue, CXPLAT_SQE* sqe)
    {
        var host = FromContext(context);
        var owner = host.Resource<PlatformQueue>((void*)queue->Handle);
        var record = host.Resource<PlatformSqe>((void*)sqe->Handle);
        if (!ReferenceEquals(record.Queue, owner))
            FatalInvariant("SQE cleanup through a foreign queue");

        record.CloseAndWait();
        host.ReleaseResource<PlatformSqe>((void*)sqe->Handle);
        sqe->Handle = 0;
        sqe->Completion = null;
    }

    private static void PlatformSqeCleanupDeferred(void* context, CXPLAT_EVENTQ* queue, CXPLAT_SQE* sqe, Action onDrained)
    {
        var host = FromContext(context);
        var owner = host.Resource<PlatformQueue>((void*)queue->Handle);
        var record = host.Resource<PlatformSqe>((void*)sqe->Handle);
        if (!ReferenceEquals(record.Queue, owner))
            FatalInvariant("Deferred SQE cleanup through a foreign queue");

        var token = sqe->Handle;
        var address = (nuint)sqe;

        lock (owner.Gate)
        {
            if (record.Closing || record.Disposed)
                FatalInvariant("Deferred SQE cleanup twice");

            record.Closing = true;
            owner.Remove(record);

            if (record.InFlight != 0)
            {
                record.AfterDrain = Finish;
                return;
            }
        }

        Finish();
        return;

        void Finish()
        {
            host.ReleaseResource<PlatformSqe>((void*)token);
            var storage = (CXPLAT_SQE*)address;
            storage->Handle = 0;
            storage->Completion = null;
            onDrained();
        }
    }
}