using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Smb.Protocol.Enums;

namespace Smb.FileSystem;

/// <summary>Acquired identities for cache-break discovery. RenameDirectoryAsync must atomically
/// recheck that no descendants remain before mutating a directory, including opens
/// acquired while breaks were outstanding.</summary>
public interface IFileNamespaceStore
{
    ValueTask<IReadOnlyList<FileIdentity>> GetOpenDescendantsAsync(IFileHandle directory, CancellationToken cancellationToken = default);
    ValueTask<NtStatus> RenameDirectoryAsync(IFileHandle directory, string newPath, bool replaceIfExists, CancellationToken cancellationToken = default);
}

/// <summary>Rename a stream within its acquired base file. Names begin with ':';
/// all existing source handles retain stream identity, contents, locks and deletion
/// state. Collision/failure leaves both streams intact. Default-stream promotion
/// moves the stream, preserving handles to the previous unnamed stream.</summary>
public interface IStreamRenameStore
{
    ValueTask<NtStatus> RenameStreamAsync(IFileHandle source, string newStreamName, bool replaceIfExists, CancellationToken cancellationToken = default);
}
