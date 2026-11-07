using System.Collections.Generic;

namespace Smb.FileSystem;

public readonly record struct BoundedDirectoryListing(IReadOnlyList<FileEntryInfo> Entries, bool Truncated);
