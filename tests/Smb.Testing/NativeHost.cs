using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Smb.Testing;

// Native fixture APIs, independent of production identity implementation; no shell dependency.
public static class NativeHost
{
    [DllImport("libc", SetLastError = true)]
    static extern int link([MarshalAs(UnmanagedType.LPUTF8Str)] string existing, [MarshalAs(UnmanagedType.LPUTF8Str)] string alias);
    [DllImport("kernel32.dll", EntryPoint = "CreateHardLinkW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CreateHardLink(string alias, string existing, IntPtr security);

    [DllImport("kernel32.dll", EntryPoint = "GetDiskFreeSpaceExW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetDiskFreeSpace(string directory, out ulong available, out ulong total, out ulong free);

    public static long VolumeTotalBytes(string directory)
    {
        if (!OperatingSystem.IsWindows()) return new DriveInfo(Path.GetPathRoot(directory)!).TotalSize;
        if (!GetDiskFreeSpace(directory.TrimEnd('\\', '/') + "\\", out _, out var total, out _))
            throw new IOException("Volume fixture failed", new Win32Exception(Marshal.GetLastPInvokeError()));
        return checked((long)total);
    }

    public static void HardLink(string existing, string alias)
    {
        if (OperatingSystem.IsWindows() ? !CreateHardLink(alias, existing, IntPtr.Zero) : link(existing, alias) != 0)
            throw new IOException("Hardlink fixture failed", new Win32Exception(Marshal.GetLastPInvokeError()));
    }
    public static int HandleCount()
    {
        if (OperatingSystem.IsLinux()) return Directory.GetFiles("/proc/self/fd").Length;
        using var process = Process.GetCurrentProcess();
        return process.HandleCount;
    }

    // Fixture inspection must coexist with production handles on Windows too.
    public static byte[] ReadAllBytes(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var copy = new MemoryStream(); stream.CopyTo(copy); return copy.ToArray();
    }
    public static string ReadAllText(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream); return reader.ReadToEnd();
    }
}
