using System;
using System.Globalization;

namespace Smb.FileSystem.Versioning;

public static class GmtToken
{
	private const string Pattern = @"\@\G\M\T-yyyy.MM.dd-HH.mm.ss";

	public static string Format(DateTime utc)
	{
		return ((utc.Kind == DateTimeKind.Utc) ? utc : utc.ToUniversalTime()).ToString(@"\@\G\M\T-yyyy.MM.dd-HH.mm.ss", CultureInfo.InvariantCulture);
	}

	public static bool TryParse(string? token, out DateTime utc)
	{
		utc = default;
		if (token == null || !token.StartsWith("@GMT-", StringComparison.Ordinal))
		{
			return false;
		}

		return DateTime.TryParseExact(token, @"\@\G\M\T-yyyy.MM.dd-HH.mm.ss", CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out utc);
	}

	public static bool TrySplitSnapshotPath(string? path, out DateTime snapshotUtc, out string remainder)
	{
		snapshotUtc = default;
		remainder = path ?? string.Empty;
		if (string.IsNullOrEmpty(path))
		{
			return false;
		}

		var text = path.Replace('/', '\\').TrimStart('\\');
		var num = text.IndexOf('\\');
		if (!TryParse((num < 0) ? text : text.Substring(0, num), out snapshotUtc))
		{
			return false;
		}

		remainder = ((num < 0) ? string.Empty : text.Substring(num + 1));
		return true;
	}
}
