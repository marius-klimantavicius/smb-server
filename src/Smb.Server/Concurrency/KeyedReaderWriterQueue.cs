using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Smb.Server.Concurrency;

public sealed class KeyedReaderWriterQueue<TKey> where TKey : notnull
{
    internal sealed class Node
    {
        public readonly TaskCompletionSource Tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        public LinkedListNode<Node>? Link;

        public bool Granted;

        public required LockMode Mode { get; init; }
    }

    internal sealed class KeyState
    {
        public readonly LinkedList<Node> Waiters = new LinkedList<Node>();

        public int ActiveCount;

        public LockMode ActiveMode;

        public int RefCount;
    }

    public readonly struct Reservation
    {
        private readonly KeyedReaderWriterQueue<TKey> _owner;

        private readonly TKey _key;

        private readonly KeyState _ks;

        private readonly Node _node;

        internal Reservation(KeyedReaderWriterQueue<TKey> owner, TKey key, KeyState ks, Node node)
        {
            _owner = owner;
            _key = key;
            _ks = ks;
            _node = node;
        }

        public ValueTask<Releaser> AcquireAsync(CancellationToken cancellationToken = default(CancellationToken))
        {
            return _owner.AcquireAsync(_key, _ks, _node, cancellationToken);
        }
    }

    public readonly struct Releaser : IDisposable
    {
        private readonly KeyedReaderWriterQueue<TKey>? _owner;

        private readonly TKey _key;

        private readonly KeyState _ks;

        private readonly Node _node;

        internal Releaser(KeyedReaderWriterQueue<TKey> owner, TKey key, KeyState ks, Node node)
        {
            _owner = owner;
            _key = key;
            _ks = ks;
            _node = node;
        }

        public void Dispose()
        {
            _owner?.Release(_key, _ks, _node);
        }
    }

    private readonly Dictionary<TKey, KeyState> _keys;

    private readonly Lock _gate = new Lock();

    public int TrackedKeyCount
    {
        get
        {
            lock (_gate)
            {
                return _keys.Count;
            }
        }
    }

    public KeyedReaderWriterQueue(IEqualityComparer<TKey>? comparer = null)
    {
        _keys = new Dictionary<TKey, KeyState>(comparer);
    }

    public Reservation Reserve(TKey key, LockMode mode)
    {
        lock (_gate)
        {
            if (!_keys.TryGetValue(key, out var value))
            {
                value = new KeyState();
                _keys[key] = value;
            }

            value.RefCount++;
            var node = new Node
            {
                Mode = mode,
            };
            node.Link = value.Waiters.AddLast(node);
            Pump(value);
            return new Reservation(this, key, value, node);
        }
    }

    private static void Pump(KeyState ks)
    {
        while (true)
        {
            var first = ks.Waiters.First;
            if (first == null)
            {
                break;
            }

            var value = first.Value;
            if (ks.ActiveCount == 0)
            {
                Grant(ks, first);
                ks.ActiveMode = value.Mode;
                if (value.Mode == LockMode.Exclusive)
                {
                    break;
                }
            }
            else
            {
                if (ks.ActiveMode != LockMode.Shared || value.Mode != LockMode.Shared)
                {
                    break;
                }

                Grant(ks, first);
            }
        }
    }

    private static void Grant(KeyState ks, LinkedListNode<Node> link)
    {
        var value = link.Value;
        ks.Waiters.Remove(link);
        value.Link = null;
        value.Granted = true;
        ks.ActiveCount++;
        value.Tcs.SetResult();
    }

    private async ValueTask<Releaser> AcquireAsync(TKey key, KeyState ks, Node node, CancellationToken ct)
    {
        if (!ct.CanBeCanceled)
        {
            await node.Tcs.Task.ConfigureAwait(continueOnCapturedContext: false);
            return new Releaser(this, key, ks, node);
        }

        Releaser result;
        await using (ct.Register(state =>
                     {
                         var (keyedReaderWriterQueue, key2, ks2, node2, ct2) = ((KeyedReaderWriterQueue<TKey>, TKey, KeyState, Node, CancellationToken))state;
                         keyedReaderWriterQueue.CancelWaiter(key2, ks2, node2, ct2);
                     }, (this, key, ks, node, ct)))
        {
            await node.Tcs.Task.ConfigureAwait(continueOnCapturedContext: false);
            result = new Releaser(this, key, ks, node);
        }

        return result;
    }

    private void CancelWaiter(TKey key, KeyState ks, Node node, CancellationToken ct)
    {
        lock (_gate)
        {
            if (!node.Granted)
            {
                if (node.Link != null)
                {
                    ks.Waiters.Remove(node.Link);
                    node.Link = null;
                }

                node.Tcs.TrySetCanceled(ct);
                Pump(ks);
                DropRef(key, ks);
            }
        }
    }

    private void Release(TKey key, KeyState ks, Node node)
    {
        lock (_gate)
        {
            if (node.Granted)
            {
                node.Granted = false;
                ks.ActiveCount--;
                if (ks.ActiveCount == 0)
                {
                    ks.ActiveMode = LockMode.Shared;
                }

                Pump(ks);
                DropRef(key, ks);
            }
        }
    }

    private void DropRef(TKey key, KeyState ks)
    {
        if (--ks.RefCount == 0)
        {
            _keys.Remove(key);
        }
    }
}
