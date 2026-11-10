using System;
using System.Collections.Generic;
using System.Linq;

namespace Smb.Server.Dfs;

public sealed class StandaloneDfsNamespace : IDfsNamespace
{
    private sealed record Link(string Path, IReadOnlyList<string> Targets, bool IsRoot);

    private readonly List<Link> _links = new List<Link>();

    private readonly uint _defaultTtlSeconds;

    public StandaloneDfsNamespace(uint defaultTtlSeconds = 300u)
    {
        _defaultTtlSeconds = defaultTtlSeconds;
    }

    public StandaloneDfsNamespace AddLink(string dfsPath, params string[] targets)
    {
        if (targets == null || targets.Length == 0)
        {
            throw new ArgumentException("A DFS link needs at least one target.", nameof(targets));
        }

        _links.Add(new Link(Normalize(dfsPath), targets, IsRoot: false));
        return this;
    }

    public StandaloneDfsNamespace AddRoot(string dfsRootPath, params string[] targets)
    {
        if (targets == null || targets.Length == 0)
        {
            throw new ArgumentException("A DFS root needs at least one target.", nameof(targets));
        }

        _links.Add(new Link(Normalize(dfsRootPath), targets, IsRoot: true));
        return this;
    }

    public DfsReferralResult? Resolve(string requestFileName)
    {
        if (string.IsNullOrEmpty(requestFileName))
        {
            return null;
        }

        var path = Normalize(requestFileName);
        Link link = null;
        foreach (var link2 in _links)
        {
            if (IsPrefix(path, link2.Path) && ((object)link == null || link2.Path.Length > link.Path.Length))
            {
                link = link2;
            }
        }

        if ((object)link == null)
        {
            return null;
        }

        return new DfsReferralResult
        {
            ConsumedPath = link.Path,
            Targets = link.Targets.Select(t => new DfsTarget(t)).ToArray(),
            TimeToLiveSeconds = _defaultTtlSeconds,
            IsRootReferral = link.IsRoot,
        };
    }

    private static bool IsPrefix(string path, string prefix)
    {
        if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (path.Length != prefix.Length)
        {
            return path[prefix.Length] == '\\';
        }

        return true;
    }

    private static string Normalize(string path)
    {
        var text = path.Trim();
        text = text.TrimEnd('\\');
        if (!text.StartsWith('\\'))
        {
            text = "\\" + text;
        }

        return text;
    }
}
