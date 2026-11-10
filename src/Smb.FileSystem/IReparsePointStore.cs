using System.Threading;
using System.Threading.Tasks;
using Smb.Protocol.Enums;

namespace Smb.FileSystem;

public interface IReparsePointStore
{
    ValueTask<FileStoreResult<byte[]>> GetReparsePointAsync(IFileHandle handle, CancellationToken cancellationToken = default(CancellationToken));

    ValueTask<NtStatus> SetReparsePointAsync(IFileHandle handle, byte[] reparseData, CancellationToken cancellationToken = default(CancellationToken));

    ValueTask<NtStatus> DeleteReparsePointAsync(IFileHandle handle, byte[] reparseData, CancellationToken cancellationToken = default(CancellationToken));
}
