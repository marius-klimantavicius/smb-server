using Smb.Protocol.Security;

namespace Smb.FileSystem.Security;

/// <summary>Descriptor storage with opaque keys. LocalFileStore writes
/// "local-security:" + FileIdentity.Key for the base object (empty StreamId).
/// Legacy absolute-path entries on existing objects are migrated on access.
/// Implementations must support all three operations for opaque keys; pathname-only
/// external updates after migration are not an object-policy update. Native IDs and
/// this interface alone do not provide persistent security across external deletion
/// and ID reuse. Coordinate such changes or manage persistent generations separately.</summary>
public interface ISecurityDescriptorStore
{
    SecurityDescriptor? TryGet(string key);

    void Set(string key, SecurityDescriptor descriptor);

    void Remove(string key);
}
