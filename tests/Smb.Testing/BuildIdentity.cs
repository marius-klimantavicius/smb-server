using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Smb.Auth;
using Smb.Crypto;
using Smb.FileSystem;
using Smb.Host;
using Smb.Protocol.Enums;
using Smb.Server;

namespace Smb.Testing;

public static class BuildIdentity
{
    private static readonly Assembly[] Stack = [typeof(SmbServer).Assembly, typeof(Smb2Dispatcher).Assembly,
        typeof(IFileStore).Assembly, typeof(ISpnegoNegotiator).Assembly, typeof(NtlmCryptography).Assembly, typeof(NtStatus).Assembly];
    public static void Print(TextWriter writer)
    {
        writer.WriteLine($"runtime={System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription} dynamicCode={RuntimeFeature.IsDynamicCodeSupported} executable={Environment.ProcessPath}");
        foreach (var assembly in Stack)
        {
            // Location is deliberately read only on JIT. Native AOT has no individually loaded assembly files.
#pragma warning disable IL3000
            var location = RuntimeFeature.IsDynamicCodeSupported ? assembly.Location : "<linked into native executable>";
#pragma warning restore IL3000
            if (RuntimeFeature.IsDynamicCodeSupported)
                Check.That(string.Equals(Path.GetDirectoryName(location), Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory), OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal), "assembly must load from rebuilt application output");
            var hash = RuntimeFeature.IsDynamicCodeSupported ? Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(location))) : "n/a";
            writer.WriteLine($"{assembly.FullName} | mvid={assembly.ManifestModule.ModuleVersionId} | location={location} | sha256={hash}");
        }
    }
}
