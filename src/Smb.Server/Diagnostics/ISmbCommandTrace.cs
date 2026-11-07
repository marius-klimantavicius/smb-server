using System;
using Smb.Protocol.Enums;

namespace Smb.Server.Diagnostics;

public interface ISmbCommandTrace : IDisposable
{
	void SetStatus(NtStatus status);
}
