using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Runtime.CompilerServices;
using Microsoft.Win32.SafeHandles;

namespace Smb.FileSystem.Local;

public sealed partial class LocalFileStore
{
    // All access is protected by _adsLock. Stores pin observed stream families;
    // aliases discover the same family by acquired native identity. The global
    // index is weak so retired stores do not pin another server's stream contents.
    private sealed class StreamTable : IEnumerable<KeyValuePair<string, StreamData>>
    {
        private static readonly Dictionary<string, WeakReference<Dictionary<string, StreamData>>> Index = new(StringComparer.Ordinal);
        private static readonly ConditionalWeakTable<Dictionary<string, StreamData>, SafeFileHandle> Anchors = new();
        private readonly Dictionary<string, Dictionary<string, StreamData>> _families = new(StringComparer.Ordinal);
        private Dictionary<string, StreamData> Family(string key)
        {
            var objectId = key[..key.IndexOf('\0')];
            if (_families.TryGetValue(objectId, out var family)) return family;
            if (!Index.TryGetValue(objectId, out var weak) || !weak.TryGetTarget(out family))
            {
                family = new(StringComparer.Ordinal); Index[objectId] = new(family);
                // Bound stale weak-index metadata without touching live families.
                if (Index.Count > 1024)
                    foreach (var old in Index.Where(pair => !pair.Value.TryGetTarget(out _)).Select(pair => pair.Key).ToArray()) Index.Remove(old);
            }
            _families.Add(objectId, family); return family;
        }
        internal void Observe(string key) => Family(key);
        internal void Pin(string key, string path)
        {
            var family = Family(key);
            // Pin the acquired object while stream state lives. Unlink/recreate cannot
            // recycle its native ID and inherit a previous file's in-memory streams.
            if (!Anchors.TryGetValue(family, out _))
                Anchors.Add(family, File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete));
        }
        internal StreamData this[string key] { get => Family(key)[key]; set => Family(key)[key] = value; }
        internal bool ContainsKey(string key) => Family(key).ContainsKey(key);
        internal bool TryGetValue(string key, out StreamData value) => Family(key).TryGetValue(key, out value!);
        internal void Add(string key, StreamData value) => Family(key).Add(key, value);
        internal bool Remove(string key)
        {
            var family = Family(key); var removed = family.Remove(key);
            if (family.Count == 0 && Anchors.TryGetValue(family, out var anchor))
            {
                Anchors.Remove(family); anchor.Dispose();
            }
            return removed;
        }
        internal IEnumerable<string> Keys => _families.Values.SelectMany(family => family.Keys);
        public IEnumerator<KeyValuePair<string, StreamData>> GetEnumerator() => _families.Values.SelectMany(family => family).GetEnumerator();
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
