using System.Globalization;
using System.Net;
using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.FileSystem.Sqlite;
using Smb.Host;
using Smb.Server;
using Smb.Server.Durable;
using Smb.Testing;

try
{
    BuildIdentity.Print(Console.Out);
    if (args is ["--sqlite-engine-proof"]) { SqliteEngineProof.Print(Console.Out); return 0; }
    if (args is ["sqlitetest"]) { await SqliteWorkload.RunAsync(log: Console.WriteLine); Console.WriteLine("PASS SQLite TCP workload"); return 0; }
    if (args is ["localtest"]) { await LocalWorkload.RunAsync(log:Console.WriteLine); Console.WriteLine("PASS local TCP workload"); return 0; }
    if (args.Length == 0 || args is ["selftest"])
    {
        await HostFixture.NormalAsync(Console.WriteLine).WaitAsync(TimeSpan.FromSeconds(60));
        Console.WriteLine("PASS normal wire host fixture"); return 0;
    }
    if (args is ["serve-sqlite", var databasePath, var sqliteAddress, var sqlitePort, var sqliteDomain, var sqliteUser, var sqlitePasswordFile])
    {
        if (!IPAddress.TryParse(sqliteAddress, out var listenAddress)) throw new ArgumentException("A numeric listen IP address is required.");
        if (!int.TryParse(sqlitePort, NumberStyles.None, CultureInfo.InvariantCulture, out var listenPort) || listenPort is < 1 or > 65535)
            throw new ArgumentException("The listen port must be between 1 and 65535.");
        if (string.IsNullOrWhiteSpace(sqliteDomain) || string.IsNullOrWhiteSpace(sqliteUser))
            throw new ArgumentException("An explicit nonempty domain and user are required.");
        var database = Path.GetFullPath(databasePath); var credentials = Path.GetFullPath(sqlitePasswordFile);
        if (string.Equals(database, credentials, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            throw new ArgumentException("The password file must differ from the database.");
        var sqlitePassword = (await File.ReadAllTextAsync(credentials)).TrimEnd('\r', '\n');
        if (string.IsNullOrEmpty(sqlitePassword)) throw new ArgumentException("A nonempty password file is required.");
        await using var sqliteStore = new SqliteFileStore(database);
        await using var sqliteServer = SmbServerBuilder.Create().WithEndpoint(listenAddress, listenPort)
            .UseAuthentication(new NtlmSpnegoNegotiator(new InMemoryIdentityBackend().AddUser(sqliteDomain, sqliteUser, sqlitePassword)))
            .AddShare(new Share { Name = "P0", FileStore = sqliteStore }).WithLogger(Console.WriteLine).Build();
        Console.WriteLine("provider=SQLite profile=Restricted persistent=false continuous-availability=false");
        await ServeAsync(sqliteServer); return 0;
    }
    if (args is ["serve", var root, var port, var domain, var user, var passwordFile])
    {
        // User supplied disposable directory + credential file; same existing NTLM/signing configuration.
        if (!Directory.Exists(root)) throw new DirectoryNotFoundException(root);
        var password = (await File.ReadAllTextAsync(passwordFile)).TrimEnd('\r', '\n');
        await using var server = HostFixture.Build(new LocalFileStore(Path.GetFullPath(root), false), int.Parse(port), domain, user, password, Console.WriteLine);
        await ServeAsync(server); return 0;
    }
    if (args is ["serve-recovery", var recoveryRoot, var address, var recoveryPort, var recoveryDomain, var recoveryUser, var recoveryPasswordFile, "--exclusive-server-access"])
    {
        // Explicit test deployment assertion: every access to this disposable root,
        // including aliases/streams, must use this one server. This is not an OS fence.
        if (!Directory.Exists(recoveryRoot)) throw new ArgumentException("An existing disposable root is required.");
        var fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(recoveryRoot));
        if (fullRoot == Path.TrimEndingDirectorySeparator(Path.GetPathRoot(fullRoot)!))
            throw new ArgumentException("The disposable root must not be a filesystem root.");
        if (!IPAddress.TryParse(address, out var listenAddress)) throw new ArgumentException("A numeric listen IP address is required.");
        if (!int.TryParse(recoveryPort, NumberStyles.None, CultureInfo.InvariantCulture, out var listenPort) || listenPort is < 1 or > 65535)
            throw new ArgumentException("The listen port must be between 1 and 65535.");
        if (string.IsNullOrWhiteSpace(recoveryDomain) || string.IsNullOrWhiteSpace(recoveryUser))
            throw new ArgumentException("An explicit nonempty domain and user are required.");
        var fullPasswordFile = Path.GetFullPath(recoveryPasswordFile);
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (fullPasswordFile.StartsWith(Path.TrimEndingDirectorySeparator(fullRoot) + Path.DirectorySeparatorChar, comparison))
            throw new ArgumentException("Keep the password file outside the shared disposable root.");
        var recoveryPassword = (await File.ReadAllTextAsync(fullPasswordFile)).TrimEnd('\r', '\n');
        if (string.IsNullOrEmpty(recoveryPassword)) throw new ArgumentException("A nonempty password file is required.");
        await using var recoveryServer = SmbServerBuilder.Create()
            .WithEndpoint(listenAddress, listenPort)
            .UseAuthentication(new NtlmSpnegoNegotiator(new InMemoryIdentityBackend().AddUser(recoveryDomain, recoveryUser, recoveryPassword)))
            .Configure(o => o.FeaturePolicy = SmbFeaturePolicy.DurableWithMultichannel)
            .EnableMultichannel()
            .UseDurableHandleStore(new InMemoryDurableHandleStore())
            .AddShare(new Share { Name = "P0", FileStore = new LocalFileStore(fullRoot, readOnly: false, securityStore: null, exclusiveServerAccess: true) })
            .WithLogger(Console.WriteLine)
            .Build();
        Console.WriteLine("profile=DurableWithMultichannel durable-store=in-memory exclusive-server-access=asserted persistent=false continuous-availability=false");
        await ServeAsync(recoveryServer); return 0;
    }
    Console.Error.WriteLine("Usage: Smb.TestHost [selftest | localtest | sqlitetest | serve-sqlite <database-path> <listen-address> <port> <domain> <user> <password-file> | serve <disposable-root> <port> <domain> <user> <password-file> | serve-recovery <disposable-root> <listen-address> <port> <domain> <user> <password-file> --exclusive-server-access]");
    Console.Error.WriteLine("serve retains Restricted. serve-recovery opts in to in-memory recovery only; --exclusive-server-access asserts that all access to the disposable root uses this server.");
    return 2;
}
catch (Exception e) { Console.Error.WriteLine(e); return 1; }

static async Task ServeAsync(SmbServer server)
{
    using var stop = new CancellationTokenSource();
    ConsoleCancelEventHandler cancel = (_, e) => { e.Cancel = true; stop.Cancel(); };
    Console.CancelKeyPress += cancel;
    try
    {
        await server.StartAsync();
        Console.WriteLine($"share=P0 endpoint={server.Endpoint}; Ctrl-C to stop");
        try { await Task.Delay(Timeout.InfiniteTimeSpan, stop.Token); }
        catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
    }
    finally
    {
        Console.CancelKeyPress -= cancel;
        await server.StopAsync(TimeSpan.FromSeconds(2));
    }
}
