using System.Collections.Generic;
using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Security;

namespace Smb.Server.Quota;

public interface IQuotaProvider
{
	bool IsSupported { get; }

	IReadOnlyList<FileQuotaInformation> Query(IShare share, IReadOnlyList<Sid> sidFilter);

	NtStatus Set(IShare share, IReadOnlyList<FileQuotaInformation> entries);

	bool TryReserve(IShare share, Sid owner, long additionalBytes);

	void Release(IShare share, Sid owner, long bytes);
}
