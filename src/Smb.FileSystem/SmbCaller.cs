using System.Threading;

namespace Smb.FileSystem;

public static class SmbCaller
{
	private static readonly AsyncLocal<CallerInfo?> _current = new AsyncLocal<CallerInfo?>();

	public static CallerInfo? Current
	{
		get => _current.Value;
		set => _current.Value = value;
	}
}
