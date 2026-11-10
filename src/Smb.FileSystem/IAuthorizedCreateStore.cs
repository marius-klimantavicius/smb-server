using System;
using System.Threading;
using System.Threading.Tasks;
using Smb.Protocol.Security;

namespace Smb.FileSystem;

/// <summary>
/// Authorizes and acquires against one coherent namespace/descriptor state. Before
/// any creation, truncation, stream reset or attribute change, call authorizeExisting
/// for an existing base object (including a new stream), or authorizeParent for a
/// new base object. The latter receives true for a directory. A false result must
/// return ACCESS_DENIED without mutation. Revalidate after any asynchronous wait;
/// cancellation must also be checked immediately before mutation. Do not call back
/// into SMB from these synchronous predicates. Host/other-server mutation must be
/// coordinated by the backend, as for IFileIdentityStore.
/// Call validateIdentity under the same guard with the identity returned by
/// ResolveIdentityAsync for this name/stream before acquisition. On false, return
/// STATUS_RETRY without mutation; the server drops reservations and readmits.
/// </summary>
public interface IAuthorizedCreateStore
{
    ValueTask<FileStoreResult<FileCreateResult>> CreateAuthorizedAsync(string path, string streamName,
        FileAccessIntent access, CreateDispositionIntent disposition, bool directoryRequired,
        bool nonDirectoryRequired, uint attributes, Func<SecurityDescriptor, bool> authorizeExisting,
        Func<SecurityDescriptor, bool, bool> authorizeParent, Func<FileIdentity?, bool> validateIdentity, CancellationToken cancellationToken = default);

    /// <summary>
    /// Grant-aware acquisition. Pass the backend's supported specific access mask
    /// (including current DOS restrictions) to authorizeExisting under the same guard.
    /// Null denies; otherwise acquire using the returned final access intent. The
    /// original overload remains compatible, but cannot reduce its host access intent.
    /// Wrappers must forward this overload to retain grant-aware acquisition.
    /// </summary>
    ValueTask<FileStoreResult<FileCreateResult>> CreateAuthorizedAsync(string path, string streamName,
        FileAccessIntent access, CreateDispositionIntent disposition, bool directoryRequired,
        bool nonDirectoryRequired, uint attributes, Func<SecurityDescriptor, uint, FileAccessIntent?> authorizeExisting,
        Func<SecurityDescriptor, bool, bool> authorizeParent, Func<FileIdentity?, bool> validateIdentity, CancellationToken cancellationToken = default)
        => CreateAuthorizedAsync(path, streamName, access, disposition, directoryRequired, nonDirectoryRequired, attributes,
            descriptor => authorizeExisting(descriptor, uint.MaxValue).HasValue, authorizeParent, validateIdentity, cancellationToken);
}
