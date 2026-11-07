using System;
using System.Threading;
using System.Threading.Tasks;

namespace Smb.FileSystem;

public interface IFileHandle : IDisposable
{
	string Path { get; }

	bool IsDirectory { get; }

	string? PhysicalPath => null;

	FileEntryInfo GetInfo();

	ValueTask<FileEntryInfo> GetInfoAsync(CancellationToken cancellationToken = default(CancellationToken))
	{
		return new ValueTask<FileEntryInfo>(GetInfo());
	}

	ValueTask DisposeAsync()
	{
		Dispose();
		return ValueTask.CompletedTask;
	}
}
