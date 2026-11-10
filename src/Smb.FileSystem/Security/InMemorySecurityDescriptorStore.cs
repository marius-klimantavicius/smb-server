using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using Smb.Protocol.Security;

namespace Smb.FileSystem.Security;

public sealed class InMemorySecurityDescriptorStore : ISecurityDescriptorStore
{
    private readonly ConcurrentDictionary<string, SecurityDescriptor> _map = new ConcurrentDictionary<string, SecurityDescriptor>(StringComparer.Ordinal);

    public SecurityDescriptor? TryGet(string key)
    {
        return _map.GetValueOrDefault(key);
    }

    public void Set(string key, SecurityDescriptor descriptor)
    {
        _map[key] = descriptor;
    }

    public void Remove(string key)
    {
        _map.TryRemove(key, out _);
    }
}
