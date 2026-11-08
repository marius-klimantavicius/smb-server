# Configuring multichannel and in-memory durable reconnect

Select an explicit recovery profile before enabling multichannel. The default
`Restricted` profile and the test host's existing `serve` command remain
restricted. `serve-recovery` selects `DurableWithMultichannel`, enables
multichannel, supplies `InMemoryDurableHandleStore`, and creates a `P0` share
backed by `LocalFileStore` with `exclusiveServerAccess: true`.

That backend setting is a deployment assertion: every access to the backing
objects, including aliases and streams, must use this server's coordination
state. It does not fence other processes or coordinate another server. Use a
disposable directory for the test host. Keep the password file outside it.
The supplied NTLM identity need not be a host operating-system account. Signing
remains required; encryption negotiation remains enabled.

From the repository root, with .NET 10 installed, supply `SMB_TEST_DOMAIN`,
`SMB_TEST_USER`, and `SMB_PASSWORD_FILE`. The existing UTF-8 password file contains
the test password, optionally followed by a newline. Its contents are not passed
in the command line.

Linux / Bash:

```sh
: "${SMB_TEST_DOMAIN:?Set the test domain}"
: "${SMB_TEST_USER:?Set the test user}"
: "${SMB_PASSWORD_FILE:?Set an existing password-file path outside the share}"
share_root=$(mktemp -d)
dotnet run --project test-host/Smb.TestHost -c Release -- \
  serve-recovery "$share_root" 127.0.0.1 1445 \
  "$SMB_TEST_DOMAIN" "$SMB_TEST_USER" "$SMB_PASSWORD_FILE" \
  --exclusive-server-access
```

Windows / PowerShell:

```powershell
if (!$env:SMB_TEST_DOMAIN -or !$env:SMB_TEST_USER -or !$env:SMB_PASSWORD_FILE) {
    throw 'Set SMB_TEST_DOMAIN, SMB_TEST_USER and SMB_PASSWORD_FILE first.'
}
$shareRoot = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $shareRoot | Out-Null
dotnet run --project test-host/Smb.TestHost -c Release -- `
  serve-recovery $shareRoot 127.0.0.1 1445 `
  $env:SMB_TEST_DOMAIN $env:SMB_TEST_USER $env:SMB_PASSWORD_FILE `
  --exclusive-server-access
```

These commands listen on loopback port 1445 and export share `P0`. Specify another
numeric address and free port when testing from another machine. Ctrl-C stops
and disposes the server; the disposable share directory remains for inspection.
Windows commands describe the portable configuration; native Windows execution
remains an outstanding validation gate.

For an application using `Smb.Host`, the equivalent builder configuration is:

```csharp
using System.Net;
using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Host;
using Smb.Server;
using Smb.Server.Durable;

await using var server = SmbServerBuilder.Create()
    .WithEndpoint(IPAddress.Loopback, 1445)
    .UseAuthentication(new NtlmSpnegoNegotiator(
        new InMemoryIdentityBackend().AddUser(domain, user, password)))
    .Configure(options => options.FeaturePolicy = SmbFeaturePolicy.DurableWithMultichannel)
    .EnableMultichannel()
    .UseDurableHandleStore(new InMemoryDurableHandleStore())
    .AddShare(new Share
    {
        Name = "P0",
        FileStore = new LocalFileStore(root, readOnly: false,
            securityStore: null, exclusiveServerAccess: true)
    })
    .Build();
await server.StartAsync();
// Keep the application alive while serving requests.
// On application shutdown:
await server.StopAsync(TimeSpan.FromSeconds(2));
```

Supply `domain`, `user`, `password` and `root` from the application's configuration.
The `Durable` profile enables caching and reconnect without multichannel;
`DurableWithMultichannelAndCopy` also enables coordinated server-side copy.
Changing the durable store alone does not enable grants. Persistent stores and
continuous-availability shares remain rejected by the supported profiles.

Durable retention lasts only within the running server process and its configured
timeout. A client must request and receive a durable grant, then authenticate and
send the appropriate reconnect context. Ordinary opens do not become durable
merely because the profile permits durability. Closing the server releases retained
handles; restarting it cannot recover them. Persistent handles, clustering and
crash recovery are separate features.

The optional [native-client runner](../../scripts/recovery-interop.py) takes explicit
host/tool/password/share/output paths. It downloads nothing and is separate from
ordinary offline tests. Run `python3 scripts/recovery-interop.py --help` (or
`python` on Windows) for bounded suite, dialect and required-encryption selections.
Native skips remain skips and make its aggregate result fail; use its individual
results and logs when assessing client/version limits.
