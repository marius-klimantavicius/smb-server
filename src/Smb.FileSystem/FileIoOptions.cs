namespace Smb.FileSystem;

/// <summary>Wire intentions after dialect validation. RemainingBytes is an advisory hint.
/// Unbuffered is advisory (MS-SMB2 SHOULD); the default adapter uses host buffering.
/// WriteThrough completes FlushAsync before reporting success; implementations must
/// return a failure when their flush cannot provide the backend's storage contract.</summary>
public readonly record struct FileIoOptions(bool WriteThrough = false, bool Unbuffered = false, uint RemainingBytes = 0);

/// <summary>Optional allocation contract, distinct from logical EOF. Implementations must
/// validate their limits/rounding, free surplus on final close and report allocation errors.</summary>
public interface IAllocationFileStore
{
    System.Threading.Tasks.ValueTask<Smb.Protocol.Enums.NtStatus> SetAllocationSizeAsync(IFileHandle handle, long allocationSize, System.Threading.CancellationToken cancellationToken = default);
}
