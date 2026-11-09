using System;
using System.Threading;
using System.Threading.Tasks;
using Smb.Protocol.Enums;

namespace Smb.FileSystem;

public interface IFileHandle : IDisposable
{
	FileIdentity? Identity => null;

	/// <summary>Logical unnamed data stream; independent of its stable stream identity.</summary>
	bool IsDefaultStream => Identity is not { } id || id.StreamId.Length == 0;

	/// <summary>Current shared object/stream disposition, sampled for metadata queries.</summary>
	bool DeletePending => false;

	string Path { get; }

	bool IsDirectory { get; }

	string? PhysicalPath => null;

	FileEntryInfo GetInfo();

	ValueTask<FileEntryInfo> GetInfoAsync(CancellationToken cancellationToken = default(CancellationToken))
	{
		return new ValueTask<FileEntryInfo>(GetInfo());
	}

	/// <summary>
	/// Complete fallible work for an explicit protocol close and return its operation status.
	/// The caller must dispose resources afterwards, even on failure. Disposal must not retry deletion.
	/// Implementations with fallible close/delete work should override this method.
	/// </summary>
	ValueTask<NtStatus> CloseAsync()
	{
		return new ValueTask<NtStatus>(NtStatus.Success);
	}

	ValueTask DisposeAsync()
	{
		Dispose();
		return ValueTask.CompletedTask;
	}
}
