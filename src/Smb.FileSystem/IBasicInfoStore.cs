using System.Threading;
using System.Threading.Tasks;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;

namespace Smb.FileSystem;

public interface IBasicInfoStore
{
    ValueTask<NtStatus> SetBasicInfoAsync(IFileHandle handle, FileBasicInfoUpdate update, CancellationToken cancellationToken = default(CancellationToken));
}
