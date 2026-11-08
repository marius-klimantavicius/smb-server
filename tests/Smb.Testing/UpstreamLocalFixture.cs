using Smb.FileSystem.Local;
using Smb.Host;

namespace Smb.Testing;

// Real loopback TCP + LocalFileStore. Authentication/signing retain HostFixture's
// existing configuration; these tests make no external-client interoperability claim.
public sealed class UpstreamLocalFixture : IAsyncDisposable
{
    public string RootPath { get; }
    public SmbServer Server { get; }

    private UpstreamLocalFixture()
    {
        RootPath = Path.Combine(Path.GetTempPath(), "smb-upstream-create-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(RootPath);
        try
        {
            Server = HostFixture.Build(new LocalFileStore(RootPath, false), 0,
                HostFixture.Domain, HostFixture.User, HostFixture.Password);
        }
        catch
        {
            Directory.Delete(RootPath, true);
            throw;
        }
    }

    public string PathFor(string name) => Path.Combine(RootPath, name);

    public static async Task<UpstreamLocalFixture> StartAsync()
    {
        var fixture = new UpstreamLocalFixture();
        try
        {
            await fixture.Server.StartAsync().WaitAsync(Check.Timeout);
            return fixture;
        }
        catch
        {
            await fixture.DisposeAsync();
            throw;
        }
    }

    public async Task<WireClient> ConnectAsync()
    {
        var client = new WireClient();
        try
        {
            await client.ConnectAsync(Server.Endpoint, HostFixture.Domain, HostFixture.User, HostFixture.Password);
            return client;
        }
        catch
        {
            await client.DisposeAsync();
            throw;
        }
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            await Server.StopAsync(TimeSpan.FromSeconds(1)).WaitAsync(Check.Timeout);
        }
        finally
        {
            try { await Server.DisposeAsync().AsTask().WaitAsync(Check.Timeout); }
            finally { Directory.Delete(RootPath, true); }
        }
    }
}
