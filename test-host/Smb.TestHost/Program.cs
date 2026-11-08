using Smb.FileSystem.Local;
using Smb.Testing;

try
{
    BuildIdentity.Print(Console.Out);
    if (args is ["localtest"]) { await LocalWorkload.RunAsync(log:Console.WriteLine); Console.WriteLine("PASS local TCP workload"); return 0; }
    if (args.Length == 0 || args is ["selftest"])
    {
        await HostFixture.NormalAsync(Console.WriteLine).WaitAsync(TimeSpan.FromSeconds(60));
        Console.WriteLine("PASS normal wire host fixture"); return 0;
    }
    if (args is ["serve", var root, var port, var domain, var user, var passwordFile])
    {
        // User supplied disposable directory + credential file; same existing NTLM/signing configuration.
        if (!Directory.Exists(root)) throw new DirectoryNotFoundException(root);
        var password = (await File.ReadAllTextAsync(passwordFile)).TrimEnd('\r', '\n');
        await using var server = HostFixture.Build(new LocalFileStore(Path.GetFullPath(root), false), int.Parse(port), domain, user, password, Console.WriteLine);
        using var stop = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.Cancel(); };
        await server.StartAsync(); Console.WriteLine($"share=P0 endpoint={server.Endpoint}; Ctrl-C to stop");
        try { await Task.Delay(Timeout.InfiniteTimeSpan, stop.Token); } catch (OperationCanceledException) { }
        await server.StopAsync(TimeSpan.FromSeconds(2)); return 0;
    }
    Console.Error.WriteLine("Usage: Smb.TestHost [selftest | serve <disposable-root> <port> <domain> <user> <password-file>]");
    return 2;
}
catch (Exception e) { Console.Error.WriteLine(e); return 1; }
