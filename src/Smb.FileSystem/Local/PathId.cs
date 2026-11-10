namespace Smb.FileSystem.Local;

internal static class PathId
{
    public static long Of(string fullPath)
    {
        var num = 14695981039346656037uL;
        foreach (var c in fullPath)
        {
            num ^= c;
            num *= 1099511628211L;
        }

        return (long)(num & 0x7FFFFFFFFFFFFFFFL);
    }
}
