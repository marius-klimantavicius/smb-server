using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Smb.FileSystem.Local;

// Linux statx has an architecture-independent ABI (unlike struct stat).
// Windows uses FILE_ID_INFO. Neither implementation falls back to pathname identity.
internal static class LocalIdentity
{
	[StructLayout(LayoutKind.Explicit, Size = 256)]
	private struct Stat
	{
		[FieldOffset(0)] public uint Mask;
		[FieldOffset(16)] public uint Links;
		[FieldOffset(32)] public ulong Inode;
		[FieldOffset(136)] public uint DeviceMajor;
		[FieldOffset(140)] public uint DeviceMinor;
	}

	[DllImport("libc", SetLastError = true)]
	private static extern int statx(int dirfd, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags, uint mask, out Stat stat);

	[DllImport("libc", SetLastError = true)]
	private static extern int open([MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags);

	public static void EnsureSupported()
	{
		if (!OperatingSystem.IsLinux() && !OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("LocalFileStore requires Linux statx or Windows FILE_ID_INFO.");
	}

	public static FileIdentity? Resolve(string path, SafeFileHandle? handle = null)
	{
		EnsureSupported();
		if (OperatingSystem.IsWindows()) return WindowsLocalIdentity.Resolve(path, handle);
		var added = false;
		try
		{
			handle?.DangerousAddRef(ref added);
			if (statx(handle == null ? -100 : handle.DangerousGetHandle().ToInt32(), handle == null ? path : "", handle == null ? 0 : 0x1000, 0x7ff, out var s) != 0)
			{
				var error = Marshal.GetLastPInvokeError();
				if (handle == null && (error == 2 || error == 20)) return null;

				throw new IOException("statx identity failed", new Win32Exception(error));
			}

			if ((s.Mask & 0x100) == 0) throw new IOException("Backend did not provide an inode identity.");

			return new FileIdentity($"linux:{s.DeviceMajor}:{s.DeviceMinor}:{s.Inode}");
		}
		finally
		{
			if (added) handle!.DangerousRelease();
		}
	}

	public static SafeFileHandle OpenDirectory(string path)
	{
		EnsureSupported();
		if (OperatingSystem.IsWindows()) return WindowsLocalIdentity.Open(path);

		var fd = open(path, 0x10000 | 0x80000);
		if (fd < 0) throw new IOException("Cannot pin directory identity", new Win32Exception(Marshal.GetLastPInvokeError()));

		return new SafeFileHandle((IntPtr)fd, true);
	}

	internal static uint LinkCount(SafeFileHandle handle)
	{
		if (OperatingSystem.IsWindows()) return WindowsLocalIdentity.LinkCount(handle);

		var added = false;
		try
		{
			handle.DangerousAddRef(ref added);
			if (statx(handle.DangerousGetHandle().ToInt32(), "", 0x1000, 4, out var s) != 0 || (s.Mask & 4) == 0)
				throw new IOException("statx link count failed", new Win32Exception(Marshal.GetLastPInvokeError()));
			return s.Links;
		}
		finally { if (added) handle.DangerousRelease(); }
	}

	internal static uint LinkCount(string path)
	{
		if (OperatingSystem.IsWindows())
		{
			using var handle = WindowsLocalIdentity.Open(path);
			return LinkCount(handle);
		}
		if (statx(-100, path, 0, 4, out var s) != 0 || (s.Mask & 4) == 0)
			throw new IOException("statx link count failed", new Win32Exception(Marshal.GetLastPInvokeError()));
		return s.Links;
	}

	// The wire index has only 64 bits. Keep Linux's inode and project Windows' full
	// native identity deterministically. Coordination always compares the full ID.
	public static long IndexNumber(FileIdentity identity)
	{
		if (identity.ObjectId.StartsWith("linux:", StringComparison.Ordinal))
			return unchecked((long)ulong.Parse(identity.ObjectId.AsSpan(identity.ObjectId.LastIndexOf(':') + 1), System.Globalization.CultureInfo.InvariantCulture));

		ulong hash = 14695981039346656037;
		foreach (var c in identity.ObjectId) hash = unchecked((hash ^ c) * 1099511628211);
		return unchecked((long)hash);
	}
}
