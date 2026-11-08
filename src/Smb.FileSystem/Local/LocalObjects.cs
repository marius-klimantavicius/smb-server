using System.Collections.Generic;
using System.Threading;

namespace Smb.FileSystem.Local;

internal sealed class LocalObject
{
	internal readonly HashSet<LocalFileHandle> Handles = new HashSet<LocalFileHandle>();
	internal string? DeletePath;
	internal bool DeletePending;
}

internal static class LocalObjects
{
	// Short synchronous backend operations only; never held across asynchronous I/O.
	internal static readonly Lock Gate = new Lock();
	internal static readonly Dictionary<FileIdentity, LocalObject> Objects = new Dictionary<FileIdentity, LocalObject>();
}
