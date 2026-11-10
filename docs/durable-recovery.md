# Optional durable-handle restart recovery

`Smb.Server` defines `IServerRecoveryStore`; it has no SQLite dependency. The
optional `Smb.Persistence.Sqlite` project implements that interface using the
supplied transpiled C# SQLite engine. Existing configurations use in-memory
durable handles and create no recovery database. Enabling a journal requires an
explicit durable feature profile, a retained-open registry and a lock manager
that implements `IRecoveryLockManager`.

Clients authenticate again after restart. The journal stores session ID,
authenticated owner, client GUID and authentication time as ownership lineage.
It stores no passwords, session/signing/encryption keys, nonce state or live
connections, and does not recreate an authenticated session. Session IDs and
durable IDs are allocated transactionally and are not reused across restart.
The server GUID comes from the journal and remains stable.

## Configuration

Reference `Smb.Persistence.Sqlite` in the application in addition to `Smb.Host`.
Use two distinct, application-configured database paths:

```csharp
using Smb.FileSystem;
using Smb.FileSystem.Sqlite;
using Smb.Host;
using Smb.Persistence.Sqlite;
using Smb.Server;

await using var files = new SqliteFileStore(fileDatabasePath);
using var recovery = new SqliteServerRecoveryStore(recoveryDatabasePath);
await using var server = SmbServerBuilder.Create()
    .WithEndpoint(listenAddress, port)
    .UseAuthentication(authenticator)
    .Configure(options => options.FeaturePolicy = SmbFeaturePolicy.Durable)
    .UseServerRecoveryStore(recovery)
    .AddShare(new Share { Name = "DATA", FileStore = files })
    .Build();
await server.StartAsync();
// Keep these alive until shutdown. Dispose server before recovery and file stores.
```

`UseServerRecoveryStore` does not select a feature profile or take ownership of
the journal. A custom implementation can be supplied through the same interface
or `SmbServerOptions.RecoveryStore`. `IRetainedDurableHandleStore` abstracts the
live reconnect registry separately from restart storage. Existing durable-v1/v2
eligibility and dialect restrictions remain: a file needs a batch oplock or a
lease containing HANDLE caching. Directories and pipes are not journaled.

Each backend that participates must implement `IRecoverableFileStore`: stable
backend/object/stream identity, durable retention tokens, reopening by token and
identity, and retention release. `SqliteFileStore` implements it, including
pending deletion, unlinked replacement objects and per-open write-time
suppression. Use writable participating SQLite stores; logical read-only stores do not create
recovery retention tokens. Other backends keep ordinary in-memory durability. LocalFileStore
has no restart-reopen contract in this delivery.

One server owns each journal and each participating backend. Do not share a
backend instance between server states. Keep file and recovery databases as a
pair; do not replace/reset just one, edit them while serving, or copy a live pair
as a backup. Stop the server and dispose both stores before backing them up.
The journal is sensitive metadata and should have the application's normal
access restrictions. Storage must provide working file locks and fsync.

## Ordering and restart

The SQLite journal has an application/schema identity, integrity/reference checks,
a retained exclusive ownership lock and FULL synchronous transactions. Snapshots
use source-generated JSON stored as bound BLOBs; IDs and lock offsets retain all
64 bits. No reflection serializer or native SQLite library is needed with AOT.

A backend retention token commits before its handle snapshot. A terminal journal
record is removed before releasing its retention token. Interruption between the
two stores can leave an orphan token; startup releases tokens without records.
The stores are separate transactions, not a distributed transaction. An operation
interrupted before its response may have committed file changes; this is not an
exactly-once replay or SMB continuous-availability implementation.

Before opening listeners, startup validates every recorded share/backend,
reopens the exact retained object, and restores sharing reservations, byte-range
locks, lock-sequence replay slots, channel sequence and cache promises. It also
restores client/CreateGuid ownership, so another CREATE cannot reuse a recovered
transaction key. Missing/mismatched objects or inconsistent recovery state fail
startup instead of opening a replacement pathname. Expired records and orphan
retention tokens are released before admission.

A disconnected handle keeps its original deadline across repeated restarts.
An active handle found after a crash starts its negotiated retention interval at
recovery. A successful reconnect clears that disconnected deadline, attaches the
open to the new authenticated session and persists its new volatile ID. Explicit
CLOSE, LOGOFF, tree disconnect, timeout and revoked durability remove recovery
state. Normal shutdown detaches journaled durable opens and releases physical
resources while preserving their recovery records and backend retention.

Journal work is synchronous and currently flushes qualifying open snapshots at
command completion; workload-specific throughput tuning is not claimed.
Snapshots commit before synchronous responses and asynchronous LOCK completion.
A cache break invalidates restart state before notification or destructive
mutation. Journal failure aborts the competing operation while preserving the
original promise. A crash during an unresolved cache break can deliberately lose
restart recovery for that open. This conservative rule prevents restoration of
an obsolete client caching promise. A qualifying open can be journaled again
after the break finishes and an operation persists its current state.

## Validation and scope

`--filter recovery.` includes store round trips, exclusive journal ownership,
monotonic IDs, retained pending objects, signed TCP restart recovery across all
five dialects, batch/lease recovery, restored sharing/byte locks, fresh sessions,
foreign-owner rejection, expiry, delete-pending cleanup, changed-backend startup
rejection, duplicate CreateGuid rejection, failed-close retry, failed cache
invalidation, graceful active shutdown and real process-kill recovery. Child
processes launch the current harness executable, including NativeAOT; tests kill
a serving process after acknowledged writes/locks, then recover with a new process.

Compiling behavioral RED captures precede the journal, backend-retention and TCP
lifecycle implementations. Further focused RED/GREEN covers duplicate recovered
CreateGuid, destructive mutation after failed invalidation and active shutdown
cache breaks. Compilation scaffolding/fixture corrections are recorded separately.
Published Linux JIT and NativeAOT each pass **4,013/4,013**, retaining all 3,991
previous names and adding 22 cases. The focused selection passes **26/26**. All
30 platform stages pass with stable source; 60 source manifests and 443 published
artifact hashes verify. Windows x64 JIT cross-publications pass; native Windows
execution remains unexecuted. See [platform validation](correctness/platform-validation.md).

This provides optional single-server durable recovery after reauthentication.
SMB persistent-handle flags, continuous availability, cluster failover, witness
recovery, arbitrary command replay and exact authenticated-session resurrection
remain unsupported. Native Windows execution and power-loss durability remain
unexecuted. Protocol basis: [durable-open reestablishment](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/3309c3d1-3daf-4448-9faa-81d2d6aa3315)
and [connection-loss retention](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/eb5bfe99-47fe-4e87-8e87-08a084dcefb6).
