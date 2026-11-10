using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Smb.Protocol.Enums;

namespace Smb.FileSystem;

public interface IExtendedAttributeStore
{
    ValueTask<FileStoreResult<IReadOnlyList<ExtendedAttribute>>> GetExtendedAttributesAsync(IFileHandle handle, CancellationToken cancellationToken = default(CancellationToken));

    ValueTask<NtStatus> SetExtendedAttributesAsync(IFileHandle handle, IReadOnlyList<ExtendedAttribute> entries, CancellationToken cancellationToken = default(CancellationToken));
}
