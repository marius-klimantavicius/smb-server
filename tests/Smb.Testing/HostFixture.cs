using System.Net;
using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.FileSystem;
using Smb.Host;

namespace Smb.Testing;

public sealed class HostFixture : IAsyncDisposable
{
    public const string Domain = "WORKGROUP";
    public const string User = "p0-fixture";
    // Public fixture credential, confined to ephemeral loopback hosts and fake storage.
    public const string Password = "p0-fixture-only-7!";
    public FakeFileStore Store { get; } = new FakeFileStore();
    public FakeWatcher Watcher { get; } = new FakeWatcher();
    public SmbServer Server { get; }
    public HostFixture(Action<string>? log = null)
    {
        Server = Build(Store, 0, Domain, User, Password, log, Watcher);
    }
    public static SmbServer Build(IFileStore store, int port, string domain, string user, string password, Action<string>? log = null, FakeWatcher? watcher = null)
    {
        var builder = SmbServerBuilder.Create().WithEndpoint(IPAddress.Loopback, port)
            .UseAuthentication(new NtlmSpnegoNegotiator(new InMemoryIdentityBackend().AddUser(domain, user, password)))
            .AddShare(new Share { Name = "P0", FileStore = store });
        if (log is not null) builder.WithLogger(log);
        if (watcher is not null) builder.Configure(o => o.DirectoryWatcher = watcher);
        return builder.Build(); // Retains signing, anonymous/guest rejection, dialect and feature defaults.
    }
    public Task StartAsync() => Server.StartAsync().WaitAsync(Check.Timeout);
    public async Task<WireClient> ConnectAsync(Action<string>? trace = null)
    {
        var client = new WireClient { Trace = trace };
        try { await client.ConnectAsync(Server.Endpoint, Domain, User, Password); return client; }
        catch { await client.DisposeAsync(); throw; }
    }
    public async ValueTask DisposeAsync()
    {
        await Server.StopAsync(TimeSpan.FromSeconds(1)).WaitAsync(Check.Timeout);
        await Server.DisposeAsync();
    }
    public static async Task NormalAsync(Action<string>? trace = null)
    {
        await using var host = new HostFixture(trace);
        await host.StartAsync();
        await using var client = await host.ConnectAsync(trace);
        var file = await client.CreateAsync("hello.txt");
        var payload = "P0 independent wire payload"u8.ToArray();
        await client.WriteAsync(file, payload);
        Check.That((await client.ReadAsync(file, (uint)payload.Length)).SequenceEqual(payload), "wire read/write roundtrip");
        await client.CloseAsync(file);
        var dir = await client.CreateAsync("", true);
        Check.That((await client.EnumerateAsync(dir)).Contains("hello.txt"), "directory names include created file");
        await client.CloseAsync(dir);
        await client.CreateAsync("tree-owned.txt");
        await client.DisconnectTreeAsync();
        Check.Equal(0, host.Store.ActiveHandles, "normal fixture backend handles quiescent");
        Check.Equal(0, host.Watcher.ActiveCount, "normal fixture watchers quiescent");
    }
}
