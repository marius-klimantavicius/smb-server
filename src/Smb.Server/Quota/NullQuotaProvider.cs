using System;
using System.Collections.Generic;
using Smb.FileSystem;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Security;

namespace Smb.Server.Quota;

public sealed class NullQuotaProvider : IQuotaProvider
{
	public static readonly NullQuotaProvider Instance = new NullQuotaProvider();

	public bool IsSupported => false;

	public IReadOnlyList<FileQuotaInformation> Query(IShare share, IReadOnlyList<Sid> sidFilter)
	{
		return Array.Empty<FileQuotaInformation>();
	}

	public NtStatus Set(IShare share, IReadOnlyList<FileQuotaInformation> entries)
	{
		return NtStatus.NotSupported;
	}

	public bool TryReserve(IShare share, Sid owner, long additionalBytes)
	{
		return true;
	}

	public void Release(IShare share, Sid owner, long bytes)
	{
	}
}
