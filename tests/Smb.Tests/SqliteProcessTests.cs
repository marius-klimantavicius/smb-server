using System.Buffers;
using System.Diagnostics;
using System.Threading.Channels;
using Smb.FileSystem;
using Smb.FileSystem.Sqlite;
using Smb.Protocol.Enums;
using Smb.Protocol.Security;
using Smb.Testing;

internal static class SqliteProcessTests
{
    public static IEnumerable<(string Name, Func<Task> Run)> Cases()
    {
        yield return ("sqlite.compatibility.prior-provider-schema1", Compatibility);
        foreach (var mode in new[] { "clean", "ownership", "rollback", "pending", "replacement" })
            yield return ($"sqlite.process.{mode}", () => Run(mode));
    }
    internal sealed class Scratch : IDisposable
    {
        public string Root { get; } = Path.Combine(Path.GetTempPath(), "smb-sqlite-process-" + Guid.NewGuid().ToString("N"));
        public string Database => Path.Combine(Root, "files.db");
        public Scratch() => Directory.CreateDirectory(Root);
        public void Dispose() => Directory.Delete(Root, true);
    }
    static readonly byte[] Original = Enumerable.Range(0, 150000).Select(i => (byte)(i * 13 + 7)).ToArray();
    static SecurityDescriptor Descriptor() => SecurityDescriptor.Create(WellKnownSids.LocalSystem, WellKnownSids.BuiltinUsers,
        new Acl { Aces = [new Ace { Type = AceType.AccessAllowed, Sid = WellKnownSids.Everyone, AccessMask = AccessMask.FileGenericRead }] });
    static async Task<IFileHandle> Open(SqliteFileStore store, string name, bool directory = false)
    {
        var result = await store.CreateAsync(name, FileAccessIntent.ReadWrite | FileAccessIntent.Delete, CreateDispositionIntent.OpenIf, directory, !directory);
        Check.Equal(NtStatus.Success, result.Status, "child acquisition"); return result.Value.Handle;
    }
    static async Task Compatibility()
    {
        using var scratch = new Scratch();
        var database = Path.Combine(scratch.Root, "old.db");
        using (var resource = typeof(SqliteProcessTests).Assembly.GetManifestResourceStream("Smb.Tests.Fixtures.sqlite-schema1.db.gz")!)
        using (var gzip = new System.IO.Compression.GZipStream(resource, System.IO.Compression.CompressionMode.Decompress))
        using (var output = File.Create(database)) gzip.CopyTo(output);
        using (var store = new SqliteFileStore(database))
        {
            Check.Equal("72:sqlite:d3dc957ae7934c9e8a90194e1f00eb7d:91545d145d9f4ff78373c13489b253ee0::3:72:sqlite:d3dc957ae7934c9e8a90194e1f00eb7d:833f7ba796de4605b1b0892f0d7599ac0::134387127386383884", await Inspect(store), "prior provider IDs, bytes, security, times and tree");
            using var added = await Open(store, "managed-added");
            Check.Equal(3, (await store.WriteAsync(added, 65535, new byte[] { 0, 37, 255 })).Value, "write old-format database");
        }
        using (var store = new SqliteFileStore(database))
        {
            Check.Equal("72:sqlite:d3dc957ae7934c9e8a90194e1f00eb7d:91545d145d9f4ff78373c13489b253ee0::3:72:sqlite:d3dc957ae7934c9e8a90194e1f00eb7d:833f7ba796de4605b1b0892f0d7599ac0::134387127386383884", await Inspect(store), "old objects survive new commit");
            using var added = await Open(store, "managed-added");
            var bytes = new byte[4]; Check.Equal(4, (await store.ReadAsync(added, 65534, bytes)).Value, "new cross-chunk EOF");
            Check.That(bytes.SequenceEqual(new byte[] { 0, 0, 37, 255 }), "new sparse bytes after reopen");
        }
        using var db = new SqliteConnection(new SqliteConnectionString(database, true));
        using var r = db.ExecuteReader("SELECT (SELECT user_version FROM pragma_user_version),(SELECT application_id FROM pragma_application_id),(SELECT integrity_check FROM pragma_integrity_check)");
        Check.That(r.Read(), "format row"); Check.Equal(1L, r.GetInt64(0), "schema unchanged"); Check.Equal(0x534D4253L, r.GetInt64(1), "application unchanged"); Check.Equal("ok", r.GetString(2)!, "integrity after writes");
    }
    static async Task Seed(SqliteFileStore store)
    {
        using var dir = await Open(store, "tree", true); using var h = await Open(store, "tree/bytes");
        Check.Equal(Original.Length, (await store.WriteAsync(h, 0, Original)).Value, "seed bytes");
        Check.Equal(NtStatus.Success, await store.SetEndOfFileAsync(h, 200123), "seed sparse EOF");
        Check.Equal(NtStatus.Success, await store.SetBasicInfoAsync(h, new() { CreationTime = 132000000000000000, LastAccessTime = 132000000000000001, LastWriteTime = 132000000000000002, ChangeTime = 132000000000000003, Attributes = 2 }), "seed metadata");
        Check.Equal(NtStatus.Success, await store.SetSecurityAsync(h, Descriptor()), "seed security");
        Check.Equal(NtStatus.Success, await store.FlushAsync(h), "seed flush");
    }
    static async Task<string> Inspect(SqliteFileStore store)
    {
        using var dir = await Open(store, "TREE", true); using var h = await Open(store, "tree/BYTES");
        var bytes = new byte[200124]; var read = await store.ReadAsync(h, 0, bytes);
        Check.Equal(200123, read.Value, "persistent EOF"); Check.That(bytes.AsSpan(0, Original.Length).SequenceEqual(Original), "persistent exact bytes");
        Check.That(bytes.AsSpan(Original.Length).IndexOfAnyExcept((byte)0) < 0, "persistent sparse tail");
        var info = h.GetInfo(); Check.Equal(132000000000000000L, info.CreationTime, "persistent creation"); Check.Equal(132000000000000001L, info.LastAccessTime, "persistent access");
        Check.Equal(132000000000000002L, info.LastWriteTime, "persistent write time"); Check.Equal((SmbFileAttributes)2, info.Attributes, "persistent attributes");
        Check.That((await store.GetSecurityAsync(h)).Value!.ToBytes().SequenceEqual(Descriptor().ToBytes()), "persistent descriptor");
        Check.That((await store.QueryDirectoryAsync(dir, "*")).Value!.Select(e => e.Name).SequenceEqual(new[] { "bytes" }), "persistent exact tree");
        return h.Identity!.Value.Key + ":" + info.IndexNumber + ":" + dir.Identity!.Value.Key + ":" + info.ChangeTime;
    }
    // GetSpan is entered by ReadOnlyMemory.CopyTo inside the production write transaction.
    // The second copy means a first 64KiB UPDATE has already executed, with no COMMIT.
    sealed class BlockingMemory(byte[] bytes) : MemoryManager<byte>
    {
        bool armed; int copies;
        public void Arm() => armed = true;
        public override Span<byte> GetSpan()
        {
            if (armed && ++copies == 2)
            {
                Console.WriteLine("BARRIER uncommitted-second-chunk"); Console.Out.Flush();
                Check.Equal("release", Console.ReadLine()!, "parent barrier release");
            }
            return bytes;
        }
        public override MemoryHandle Pin(int elementIndex = 0) => throw new NotSupportedException();
        public override void Unpin() { }
        protected override void Dispose(bool disposing) { }
    }
    public static async Task<int> Child(string mode, string database)
    {
        try
        {
            if (mode == "reject")
            {
                try { using var unexpected = new SqliteFileStore(database); throw new InvalidOperationException("second owner acquired database"); }
                catch (IOException e) when (e.InnerException is SqliteException { Result: 5 or 6 }) { Console.WriteLine("REJECTED sqlite-lock"); return 0; }
            }
            using var store = new SqliteFileStore(database);
            if (mode == "seed") { await Seed(store); Console.WriteLine("SNAPSHOT " + await Inspect(store)); return 0; }
            if (mode == "inspect") { Console.WriteLine("SNAPSHOT " + await Inspect(store)); return 0; }
            if (mode == "rollback")
            {
                using var h = await Open(store, "tree/bytes"); using var manager = new BlockingMemory(Enumerable.Repeat((byte)99, 250000).ToArray());
                var memory = manager.Memory; manager.Arm(); await store.WriteAsync(h, 0, memory);
                throw new InvalidOperationException("parent failed to kill blocked writer");
            }
            if (mode == "pending")
            {
                using var pending = await Open(store, "pending"); await store.WriteAsync(pending, 0, new byte[] { 8 });
                Check.Equal(NtStatus.Success, await store.SetDeleteOnCloseAsync(pending, true), "committed pending disposition");
                Console.WriteLine("BARRIER pending-committed"); Console.Out.Flush(); Console.ReadLine(); return 0;
            }
            if (mode == "replacement")
            {
                using var source = await Open(store, "source"); using var target = await Open(store, "target");
                await store.WriteAsync(source, 0, new byte[] { 7, 11 }); await store.WriteAsync(target, 0, new byte[] { 99 });
                Check.Equal(NtStatus.Success, await store.RenameAsync(source, "target", true), "committed replacement");
                Console.WriteLine("REPLACEMENT " + source.Identity!.Value.Key); Console.WriteLine("BARRIER replacement-committed"); Console.Out.Flush(); Console.ReadLine(); return 0;
            }
            if (mode == "hold") { Console.WriteLine("BARRIER owner-held"); Console.Out.Flush(); Console.ReadLine(); return 0; }
            throw new ArgumentException("Unknown child mode");
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
    sealed class ChildProcess : IAsyncDisposable
    {
        readonly Process process; readonly Channel<string> lines = Channel.CreateUnbounded<string>();
        readonly List<string> stdout = []; readonly List<string> stderr = []; readonly Task output, errors;
        public ChildProcess(string mode, string database)
        {
            var executable = Environment.ProcessPath ?? throw new InvalidOperationException("missing executable path");
            var start = new ProcessStartInfo(executable) { RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true, UseShellExecute = false };
            // dotnet <assembly> is needed for framework-dependent invocation; apphost/AOT self-execute.
            if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
                start.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory, "Smb.Tests.dll"));
            start.ArgumentList.Add("--sqlite-child"); start.ArgumentList.Add(mode); start.ArgumentList.Add(database);
            process = Process.Start(start) ?? throw new InvalidOperationException("child not started");
            output = Pump(process.StandardOutput, stdout, true); errors = Pump(process.StandardError, stderr, false);
        }
        async Task Pump(StreamReader reader, List<string> destination, bool signal)
        { while (await reader.ReadLineAsync() is { } line) { destination.Add(line); if (signal) await lines.Writer.WriteAsync(line); } if (signal) lines.Writer.TryComplete(); }
        string Diagnostics => string.Join("\n", stdout.Concat(stderr));
        public async Task<string> Line(string prefix)
        {
            try
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
                await foreach (var line in lines.Reader.ReadAllAsync(timeout.Token)) if (line.StartsWith(prefix, StringComparison.Ordinal)) return line;
                throw new IOException("child exited before handshake");
            }
            catch (Exception e) { throw new IOException("Child handshake failed: " + prefix + "\n" + Diagnostics, e); }
        }
        public async Task<string[]> Finish(bool kill = false)
        {
            if (kill) process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15)); await Task.WhenAll(output, errors).WaitAsync(Check.Timeout);
            if (!kill) Check.Equal(0, process.ExitCode, "child exit: " + Diagnostics);
            else Check.That(process.ExitCode != 0, "killed process exits unsuccessfully");
            return stdout.ToArray();
        }
        public async ValueTask DisposeAsync()
        { if (!process.HasExited) { process.Kill(entireProcessTree: true); await process.WaitForExitAsync().WaitAsync(Check.Timeout); } await Task.WhenAll(output, errors).WaitAsync(Check.Timeout); process.Dispose(); }
    }
    static async Task<string[]> Execute(string mode, string database)
    { await using var child = new ChildProcess(mode, database); return await child.Finish(); }
    static async Task Run(string mode)
    {
        using var scratch = new Scratch(); var database = scratch.Database;
        var baseline = (await Execute("seed", database)).Single(s => s.StartsWith("SNAPSHOT "));
        if (mode == "ownership")
        {
            await using var owner = new ChildProcess("hold", database); await owner.Line("BARRIER owner-held");
            Check.That((await Execute("reject", database)).Contains("REJECTED sqlite-lock"), "second process fenced");
            var alias = Path.Combine(scratch.Root, "alias.db"); if (OperatingSystem.IsWindows()) NativeHost.HardLink(database, alias); else File.CreateSymbolicLink(alias, database);
            Check.That((await Execute("reject", alias)).Contains("REJECTED sqlite-lock"), "filesystem alias fenced");
            Check.That((await Execute("reject", Path.Combine(scratch.Root, ".", "files.db"))).Contains("REJECTED sqlite-lock"), "lexical alias fenced");
            await owner.Finish(kill: true);
        }
        else if (mode != "clean")
        {
            await using var child = new ChildProcess(mode, database);
            string? replacement = mode == "replacement" ? await child.Line("REPLACEMENT ") : null;
            await child.Line(mode == "rollback" ? "BARRIER uncommitted-second-chunk" : "BARRIER " + mode + "-committed");
            await child.Finish(kill: true);
            using var store = new SqliteFileStore(database);
            if (mode == "pending") Check.That(await store.ResolveIdentityAsync("pending") is null, "abandoned committed pending delete finalized");
            if (mode == "replacement")
            {
                Check.That(await store.ResolveIdentityAsync("source") is null, "source name removed"); using var h = await Open(store, "target");
                Check.Equal(replacement!, "REPLACEMENT " + h.Identity!.Value.Key, "replacement identity retained");
                var bytes = new byte[3]; Check.Equal(2, (await store.ReadAsync(h, 0, bytes)).Value, "replacement EOF"); Check.That(bytes.AsSpan(0, 2).SequenceEqual(new byte[] { 7, 11 }), "replacement bytes retained");
            }
        }
        Check.Equal(baseline, (await Execute("inspect", database)).Single(s => s.StartsWith("SNAPSHOT ")), "separate executable restart identity, bytes, metadata, security and tree");
        using var db = new SqliteConnection(new SqliteConnectionString(database, true));
        using (var reader = db.ExecuteReader("PRAGMA integrity_check")) { Check.That(reader.Read(), "integrity row"); Check.Equal("ok", reader.GetString(0)!, "post-restart integrity"); }
        using (var reader = db.ExecuteReader("PRAGMA foreign_key_check")) Check.That(!reader.Read(), "post-restart foreign keys");
        using (var reader = db.ExecuteReader("SELECT COUNT(*) FROM objects WHERE parent IS NULL AND name<>''")) { Check.That(reader.Read(), "count row"); Check.Equal(0L, reader.GetInt64(0), "abandoned unlinked rows reclaimed"); }
    }
}
