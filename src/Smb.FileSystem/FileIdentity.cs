using System.Threading;
using System.Threading.Tasks;

namespace Smb.FileSystem;

/// <summary>Backend object and stream identity, independent of names and SMB FileIds.</summary>
public readonly record struct FileIdentity(string ObjectId, string StreamId = "")
{
    public string Key => ObjectId.Length + ":" + ObjectId + StreamId.Length + ":" + StreamId;
}

/// <summary>
/// Opt in only when identities survive rename and aliases and match acquired handles.
/// A missing name returns null; the server serializes namespace acquisition and rechecks
/// the acquired identity before publication. External namespace mutations must be coordinated
/// by the backend. Legacy stores are conservatively coordinated as one object per store.
/// </summary>
public interface IFileIdentityStore
{
    ValueTask<FileIdentity?> ResolveIdentityAsync(string path, string streamName = "", CancellationToken cancellationToken = default);
}

/// <summary>
/// Backend guarantees object/stream-wide disposition, rejection of new opens while
/// pending, clearing from any live open, and nonrecursive deletion at final close.
/// CloseAsync reports fallible finalization and DisposeAsync always releases resources.
/// </summary>
public interface ISharedDeleteFileStore : IFileIdentityStore
{
}
