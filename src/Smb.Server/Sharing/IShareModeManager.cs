using Smb.FileSystem;

namespace Smb.Server.Sharing;

public interface IShareModeManager
{
    bool TryOpen(string fileKey, object owner, FileAccessIntent access, FileShareMode share);

    void Close(string fileKey, object owner);
}
