using System;
using System.Buffers.Binary;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Smb.FileSystem.Local;

// All native structs contain only blittable fields; SafeFileHandle parameters keep
// handles alive across P/Invoke. No reflection, runtime-generated marshaler or ID fallback.
internal static class WindowsLocalIdentity
{
	[StructLayout(LayoutKind.Sequential)]
	private struct FileIdInfo
	{
		public ulong VolumeSerialNumber;
		public ulong IdLow;
		public ulong IdHigh;
	}

	[DllImport("kernel32.dll", EntryPoint = "CreateFileW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
	private static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

	[DllImport("kernel32.dll", EntryPoint = "ReOpenFile", ExactSpelling = true, SetLastError = true)]
	private static extern SafeFileHandle ReOpenFile(SafeFileHandle original, uint access, uint share, uint flags);

	[DllImport("kernel32.dll", EntryPoint = "GetDiskFreeSpaceExW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool GetDiskFreeSpace(string directory, out ulong available, out ulong total, out ulong free);

	[DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", ExactSpelling = true, SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool GetFileInformation(SafeFileHandle handle, int informationClass, out FileIdInfo info, uint size);

	[DllImport("kernel32.dll", EntryPoint = "SetFileInformationByHandle", ExactSpelling = true, SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool SetFileInformation(SafeFileHandle handle, int informationClass, [In] byte[] info, uint size);

	// Extended syntax supports long drive and UNC roots, with explicit UTF-16 APIs.
	private static string NativePath(string path)
	{
		var full = Path.GetFullPath(path);
		if (full.StartsWith(@"\\?\", StringComparison.Ordinal)) return full;

		return full.StartsWith(@"\\", StringComparison.Ordinal) ? @"\\?\UNC\" + full.Substring(2) : @"\\?\" + full;
	}

	internal static SafeFileHandle Open(string path, bool deleteAccess = false)
	{
		// FILE_READ_ATTRIBUTES, optional DELETE, all three shares, OPEN_EXISTING,
		// FILE_FLAG_BACKUP_SEMANTICS (needed for directories; legal for files).
		var handle = CreateFile(NativePath(path), 0x80u | (deleteAccess ? 0x10000u : 0), 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
		if (!handle.IsInvalid) return handle;

		var error = Marshal.GetLastPInvokeError();
		handle.Dispose();
		throw Error("Cannot acquire native local handle", error);
	}

	internal static VolumeInfo Volume(string directory)
	{
		// DriveInfo explicitly excludes UNC names. Query the actual root directory
		// instead; UNC paths require the trailing separator and counts are 64-bit.
		var path = NativePath(directory).TrimEnd('\\') + "\\";
		if (!GetDiskFreeSpace(path, out var available, out var total, out _))
			throw Error("Native volume capacity query failed", Marshal.GetLastPInvokeError());

		return new VolumeInfo("SMBLOCAL", 0, checked((long)total), checked((long)available));
	}

	internal static FileIdentity? Resolve(string path, SafeFileHandle? handle)
	{
		if (handle != null) return ResolveHandle(handle);

		try
		{
			using var pin = Open(path);
			return ResolveHandle(pin);
		}
		catch (IOException e) when ((e.HResult & 0xffff) is 2 or 3) { return null; }
	}

	internal static SafeFileHandle OpenMetadata(SafeFileHandle original)
	{
		// Reopen the acquired object, including directories and renamed/unlinked
		// files, for FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES. No name lookup.
		var handle = ReOpenFile(original, 0x180, 7, 0x02000000);
		if (!handle.IsInvalid) return handle;

		var error = Marshal.GetLastPInvokeError();
		handle.Dispose();
		throw Error("Cannot reopen native metadata handle", error);
	}

	private static FileIdentity ResolveHandle(SafeFileHandle handle)
	{
		// FileIdInfo = 18; FILE_ID_INFO = ULONGLONG + FILE_ID_128, 24 bytes.
		if (!GetFileInformation(handle, 18, out var info, 24))
			throw Error("FILE_ID_INFO identity query failed", Marshal.GetLastPInvokeError());

		return new FileIdentity(FormattableString.Invariant($"windows:{info.VolumeSerialNumber:x16}:{info.IdLow:x16}{info.IdHigh:x16}"));
	}

	private static SafeFileHandle MutationHandle(string path, FileIdentity expected)
	{
		var handle = Open(path, deleteAccess: true);
		try
		{
			if (ResolveHandle(handle) != expected) throw Error("Native local object was replaced", 2);

			return handle;
		}
		catch
		{
			handle.Dispose();
			throw;
		}
	}

	internal static void Delete(string path, FileIdentity expected)
	{
		using var handle = MutationHandle(path, expected);
		// FILE_DISPOSITION_INFO.DeleteFile is BOOLEAN (one byte), not Win32 BOOL.
		if (!SetFileInformation(handle, 4, new byte[] { 1 }, 1))
			throw Error("Native nonrecursive disposition failed", Marshal.GetLastPInvokeError());
		// The final backend pin closes immediately after this returns. Other host
		// handles must share DELETE; the OS retains deletion until its last close.
	}

	internal static void Rename(string path, string destination, FileIdentity expected, bool replace)
	{
		using var handle = MutationHandle(path, expected);
		var name = Encoding.Unicode.GetBytes(NativePath(destination));
		// FILE_RENAME_INFO: BOOLEAN, padding to HANDLE alignment, HANDLE (NULL),
		// DWORD byte length, WCHAR[]. Both pointer-size layouts are explicit.
		var lengthOffset = IntPtr.Size * 2;
		var nameOffset = lengthOffset + 4;
		var buffer = new byte[Math.Max(nameOffset + name.Length + 2, IntPtr.Size == 8 ? 24 : 16)];
		buffer[0] = replace ? (byte)1 : (byte)0;
		BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(lengthOffset), (uint)name.Length);
		name.CopyTo(buffer, nameOffset);
		if (!SetFileInformation(handle, 3, buffer, (uint)buffer.Length))
			throw Error("Native rename failed", Marshal.GetLastPInvokeError());
	}

	private static IOException Error(string message, int error)
		=> new IOException(message + ": " + new Win32Exception(error).Message, unchecked((int)(0x80070000u | (uint)error)));
}
