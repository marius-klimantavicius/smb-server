# SQLite filesystem provider

`Smb.FileSystem.Sqlite` is an optional project. Its public constructor is
`SqliteFileStore(string databasePath, bool readOnly = false)`. All names, file
content, timestamps, DOS attributes and security descriptors live in the database;
there is no mirrored host tree or `PhysicalPath`.

```csharp
using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.FileSystem;
using Smb.FileSystem.Sqlite;
using Smb.Host;
using System.Net;

// Runtime configuration supplies databasePath, domain, user and password.
await using var store = new SqliteFileStore(databasePath);
await using var server = SmbServerBuilder.Create()
    .WithEndpoint(IPAddress.Loopback, 1445)
    .UseAuthentication(new NtlmSpnegoNegotiator(
        new InMemoryIdentityBackend().AddUser(domain, user, password)))
    .AddShare(new Share { Name = "DATA", FileStore = store })
    .Build(); // Restricted, required signing; authentication remains enabled.
await server.StartAsync();
// Keep both alive until application shutdown. Reverse declaration order disposes
// the server and its opens before the provider. A server does not own the store.
```

One active store owns each database through a retained exclusive SQLite
rollback-journal lock, including across processes and filesystem aliases. Reuse
that same instance for shares in **one server state**. Separate server states
have separate share/lock/cache coordinators and must not share an instance.
Do not access the database through raw SQLite writers or use a SQLite editor
while serving it. Use storage with working SQLite file locks and fsync. Stop the
server and dispose the provider before copying/backing up the database; preserve
any hot rollback journal needed for recovery after interruption.

## Format and naming

The schema has `application_id=0x534D4253`, `user_version=1` and a persistent
random database UUID. Object UUIDs survive rename and reopen; monotonic wire
indexes are separate from SMB FileIds. Foreign applications, unsupported schema
versions, non-DELETE journal modes and failed integrity/reference checks reject
startup. There is no migration or automatic conversion of arbitrary SQLite files.

Names use invariant uppercase case comparison on Linux and Windows. `/` and `\`
separate components; a leading separator denotes the logical root. Empty interior
components, dot/dotdot, controls, invalid UTF-16, reserved filename characters and
trailing dots/spaces are rejected. Components allow at most 255 UTF-16 units;
paths allow at most 32767. Unicode canonical-equivalence folding and DOS short
names are unsupported. Enumeration returns actual children without synthetic dot
entries, uses bounded SQL keysets, and is forward-only rather than a snapshot.
Concurrent changes after the cursor may appear; names before it are not revisited.

## Persistence and recovery

Content is stored in sparse 64KiB chunks with signed 64-bit offsets and logical
EOF. Holes read as zero; shrink removes/zeroes the tail. Allocation size describes
stored chunks. Sparse content does not imply support for SMB sparse-file IOCTLs.
Every successful mutation commits an explicit transaction with
`PRAGMA synchronous=FULL`. `FlushAsync` validates the handle and serializes after
prior mutations: there is no deferred dirty provider buffer. Write-through has
the same commit durability. Actual power-loss durability depends on SQLite,
filesystem and storage guarantees; process-kill tests do not emulate power loss.

The supplied Ews.Common.Sqlite framework executes synchronously under a per-store gate. Async method
names do not imply asynchronous I/O. Cancellation is checked around gate
entry, chunks and commit, and rolls back uncommitted changes; it cannot interrupt
an OS fsync already executing.

Shared pending deletion rejects new opens, can be cleared through another live
DELETE-granted handle, and finalizes at the last close. Directory deletion is
nonrecursive. Replacing a live name keeps its old object available to existing
handles. Writable startup purges abandoned unlinked replacements and finalizes
committed pending files/empty directories. Nonempty pending directories have
pending cleared to preserve children. Invalid orphan directories with children
reject startup. Uncommitted mutations recover through SQLite's rollback journal.

`readOnly` is a **logical filesystem restriction**: an existing, writable database
is still required to acquire the exclusive lock. It does not provide read-only
media access, a SQLite read-only connection, or parallel readers. A dirty database
requiring provider cleanup must first be opened writable. Missing databases are
not created in this mode.

SMB opens, byte locks, leases, oplocks, durable records and replay state are
process memory. Explicit `Caching` or `Durable` profiles can use the coherent
provider contracts. In-memory durable reconnect retains bytes, object identity
and locks after transport loss within that server lifetime. Shutdown/restart
retains filesystem data by default, with no SMB persistent
handles, continuous availability or failover claim. Optional
[restart recovery](durable-recovery.md) can retain eligible durable handles through
an abstract journal, with fresh authentication and stable-identity backend reopening.
Restricted remains default.

## Supported surface

Ordinary create/open/read/write/flush/EOF, directories, rename/replacement,
shared deletion, bounded enumeration, basic timestamps/DOS attributes and basic
security descriptor storage/inheritance are implemented. Authorization and
CREATE mutation are atomic. Unsupported DACL forms reject before mutation;
this is the existing basic ACL profile, not full Windows security semantics.
Writes set archive and update write/change times; there is no access-time-on-read
policy. Per-open write-time suppression is process state. Supersede/overwrite
truncate the existing object while preserving its identity.

Only the unnamed data stream is supported. ADS CREATE and EA SET return
`STATUS_NOT_SUPPORTED`; EA QUERY returns a successful empty list. Stream QUERY
reports only `::$DATA` for a file. CHANGE_NOTIFY returns `STATUS_NOT_SUPPORTED`
because no physical watcher path exists. CopyRange/copy chunk, allocation
control, sparse IOCTLs, snapshots, quotas, reparse points and hard-link creation
are unsupported. Volume space reports the SQLite page limit and unused page
capacity, not reserved host free space or a quota.

## Host and engine packaging

From the repository root, using the pinned .NET SDK:

```sh
dotnet run --project test-host/Smb.TestHost -c Release -- sqlitetest
# Explicit runtime paths; protect the credential file and keep it separate.
dotnet run --project test-host/Smb.TestHost -c Release -- serve-sqlite "$SMB_DATABASE" 127.0.0.1 1445 "$SMB_DOMAIN" "$SMB_USER" "$SMB_PASSWORD_FILE"
```

PowerShell (native Windows execution remains unexecuted in this delivery):

```powershell
dotnet run --project test-host/Smb.TestHost -c Release -- sqlitetest
dotnet run --project test-host/Smb.TestHost -c Release -- serve-sqlite $env:SMB_DATABASE 127.0.0.1 1445 $env:SMB_DOMAIN $env:SMB_USER $env:SMB_PASSWORD_FILE
```

`serve-sqlite` serves `P0`, requires a numeric listen IP, a valid port, explicit
nonempty credentials, and stops with Ctrl-C. It disposes the server before the
provider. `sqlitetest` uses automatically cleaned, unique runtime scratch data,
actual signed SMB311 TCP and a second store/server lifetime.

The sole database execution path is the supplied `Managed.Database.Sqlite`
transpiled C# engine, SQLite **3.54.0**, with the supplied `Ews.Common.Sqlite`
framework. `Library/HostVfs*.cs` implements the VFS and OS services. The framework
uses unmanaged memory and temporary pins; text and BLOB bindings are copied with
`SQLITE_TRANSIENT`. Empty BLOBs remain distinct from NULL. Repeated named values
share their SQLite parameter index; offsets and timestamps bind as Int64. A small
store helper maps its named parameters to the framework binder and scopes readers.
There is no alternate provider or ADO.NET compatibility layer.

The unbound framework execution overload follows SQLite parser tails, including
quoted semicolons and comments, and stops on the first error. Parameterized store
queries each contain one statement. Store bind failures release their statement and
surface SQLite result codes. Store transactions retain explicit BEGIN IMMEDIATE,
COMMIT and ROLLBACK; startup takes BEGIN EXCLUSIVE before schema inspection.

Publish the whole output directory for the chosen .NET deployment mode. There is
**no native SQLite library to install or copy**, including with NativeAOT. OS
P/Invoke for file locks, file identity and fsync remains. The only new package
reference is Microsoft.Extensions.Logging.Abstractions 10.0.0 for the supplied
framework's logging API. Microsoft.Data.Sqlite and SQLitePCLRaw are absent from
active restore and publish. See [source/dependency notices](notices/sqlite-dependencies.txt)
and the [retained framework license](../src/Smb.FileSystem.Sqlite/LICENSE.txt).
The SQLite engine is public domain; the framework and embedded dotcc runtime
retain their MIT notices. This integration does not claim a generator-lineage audit.

The portable driver executes `--sqlite-engine-proof` in each fresh host/harness
output. That command runs SQL through the framework and verifies the result against
the compiled engine version/source ID. The packaging gates inspect every restored
assets graph and each published output for the removed packages and native SQLite
assets. The full harness runs subprocess recovery with its current executable in
both JIT and NativeAOT modes. Native Windows execution remains a separate gate.

## Focused validation

Run `dotnet run --project tests/Smb.Tests -c Release -- --filter sqlite.`.
The original **87 SQLite cases** (54 backend + 33 integration) and **3,897 baseline
names** are retained. Seven additional cases cover parser tails, NULL/empty BLOB,
copy lifetime/repeated named binding/Int64, binding result errors, failed-binding
statement disposal, transaction errors/rollback/reuse, and prior-provider format
compatibility. The complete published Linux harness passes **3,991/3,991** in both JIT and
NativeAOT, including **94** SQLite cases. All **30** platform stages pass with
stable source; all 60 stage source manifests and 440 artifact hashes verify.

The four framework repairs have compiling behavioral RED/GREEN evidence: ignored
tails, empty BLOB becoming NULL, ignored invalid bind index and leaked statement
after a throwing binder. Text/blob copy and Int64 behavior already passed. Build
setup failures are recorded separately; mechanical API adaptation has no invented
behavioral RED. The generated engine and VFS source required no changes.

The portable embedded [schema-1 fixture](../tests/Smb.Tests/Fixtures/README.txt)
was created by the prior published Microsoft.Data.Sqlite/SQLitePCLRaw provider,
using native SQLite 3.53.3. Its hashes and provenance are retained beside it.
Routine tests need no old package/runtime or external evidence. They validate old
UUIDs/indexes, bytes, sparse EOF, timestamps, security and tree, then commit new
cross-chunk sparse data and reopen with unchanged format and integrity.

Integration includes signed TCP across all five SMB dialects, denied mutations,
metadata/security, live replacement/deletion, bounded cursors, capability declines,
lease/oplock breaks and ACKs, durable reconnect and store reopen. Process tests
retain second-owner/alias rejection, controlled kill during an uncommitted chunk
write, committed pending deletion and committed live replacement. These tests do
not emulate power loss or persistent SMB recovery/continuous availability.

Published Linux JIT/AOT final results are recorded in the
[platform validation report](correctness/platform-validation.md).
Native Windows JIT/AOT remains unexecuted. Windows cross-builds, when recorded,
are compilation evidence only. Older native-SQLite captures are historical.
