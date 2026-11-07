using Smb.Protocol.Security;

namespace Smb.FileSystem.Security;

public interface ISecurityDescriptorStore
{
	SecurityDescriptor? TryGet(string key);

	void Set(string key, SecurityDescriptor descriptor);

	void Remove(string key);
}
