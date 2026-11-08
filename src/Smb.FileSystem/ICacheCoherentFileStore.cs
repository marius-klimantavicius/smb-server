namespace Smb.FileSystem;

/// <summary>Explicit pre-mutation coherence contract. Stable object/stream identities and all
/// namespace/data/metadata mutations must participate in this server's coordinator. Host
/// watchers are insufficient. False is required for arbitrary shared host access.</summary>
public interface ICacheCoherentFileStore : IFileIdentityStore
{
    bool HasExclusiveServerAccess { get; }
}
