using System.Threading;
using System.Threading.Tasks;

namespace Smb.FileSystem;

public interface ISymlinkResolver
{
	ValueTask<SymlinkTarget?> ResolveSymlinkAsync(string path, CancellationToken cancellationToken = default(CancellationToken));
}
