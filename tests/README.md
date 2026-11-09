# Test entry points

`dotnet run --project tests/Smb.Tests -c Release -- [--list | --filter substring]`
runs the dependency-free executable harness. Tests register explicitly as
`(string Name, Func<Task> Run)` in `Smb.Tests/Program.cs`; no reflection discovery
or test adapter is needed. Empty selection exits 2, assertion failure exits 1,
all selected tests passing exits 0. Each test has a 60-second outer bound; I/O,
barriers and cleanup have shorter 10-second bounds. Default runs now require F08 to pass. Historical P0 logs preserve its original failure; later final-source gates require all tests green.

The historical second campaign registers **3,144** cases. That campaign adds
2,068 source-derived public protocol/auth cases and 136 repair regressions to the
previous 940. Published Linux JIT and Native AOT each pass **2,917/3,144**; the
same **227 failures remain** in both, including compatibility expectations and
unresolved cache/notify reproducers. No skip or expected-failure mechanism is used.
Both modes' host selftests, real local TCP workloads and stress/expiry checks pass.
Native Windows remains unexecuted.

The subsequent [multichannel/durable delivery](../docs/correctness/multichannel-durable-reconnect.md)
adds **371** cases, for **3,515 unique registrations**. Its settled integration
run passes **3,415**, with **100 inherited failures** and no new failing names.
Published Linux JIT and Native AOT both reproduce **3,415/3,515**, with identical
failing names. Both local TCP workloads and repeated stress/expiry checks pass.
Focused TCP filters are `channel-wire.` (131), `durable.tcp.` (151),
`cache.sequence.tcp.` (28) and `channel-composition.` (60); the additional
`p7c.reconnect.deadline-during-preparation` covers suspended expiry. The composition
matrix covers signed/encrypted SMB300/302/311 v1/v2 Batch and file leases,
one-channel/final-channel loss, reconnect, replay and controlled teardown races.
See [platform validation](../docs/correctness/platform-validation.md) for final
published-mode counts and [the exact failure differences](../docs/correctness/recovery-failure-differences.txt).

The [remaining-failure repair campaign](../docs/correctness/remaining-failure-repairs.md)
adds **382** ordinary regressions, for **3,897 unique registrations**. Its settled
full integration run passes **3,897/3,897**, including all 100 formerly failing
names, the original 940 and all 371 recovery-feature additions. Production
repairs and specification/profile-backed fixture corrections are documented
separately; no tests are skipped or converted to expected failures. Final native
Linux JIT/AOT, host/TCP and stress results are in platform validation. Native
Windows execution and full Windows ACL/stream fidelity remain outside that claim.

`--filter upstream.` selects all upstream-related cases, including the first
campaign's 86 (`upstream.create.` 29, `upstream.protocol.` 27, `upstream.state.` 30).
The broader source selections are `upstream.samba.` (811 plus 737 under
`upstream.samba.more.`), `upstream.go.` (83), `upstream.microsoft.` (297), and
`upstream.inventory.` (140). They include meaningful matrix partitions, not a
claim that every registration is an unrelated workflow. The five Go sources
include three servers and two clients. The [source map and findings](../docs/correctness/upstream-tests.md)
identify pinned upstream filenames/symbols, exact local references, independent assertions, specification
differences and execution results. Builds require no upstream checkout, network
access or evidence archive. CREATE/namespace and multi-credit cases use signed
TCP; deterministic direct-session cases are identified separately and do not
claim external-client interoperability. Authentication/signing configuration
remains unchanged. Authentication coverage is explicitly included by the updated
user scope; internal-only upstream APIs/helpers are excluded from new adaptations.

To capture every independent gate even with failing selections, run
`python3 scripts/validate-platform.py --out "$SMB_VALIDATION_OUTPUT" --keep-going`.
The output directory must be new and external. Failed publications block their
dependent executions; the aggregate result/exit remains failing. Default mode
still stops at the first failure. No upstream download is part of either mode.

`Smb.Testing` is shared with the JIT/AOT executable host. Future phases can add
focused tests here without creating new fixtures or loading original DLLs.

| Helper | Integration contract |
| --- | --- |
| `HostFixture` | Real `Smb.Host.SmbServer`, loopback ephemeral port, fake storage, existing authenticated session configuration and required signing. Exposes `Server.State`, `Store`, `Watcher`; async disposal shuts the server down with a bounded drain. |
| `WireClient` | Authenticated SMB 2.0.2–3.1.1 primary connection using independent raw SMB packets; optional dialect argument, with SMB300/302/311 binding helpers. `Session`, `Tree`, `NextMessageId()` and `ExchangeAsync(request, expectedStatus, structureSize)` support new command-specific tests. IDs increase per connection. It uses existing NTLM/KDF/signing primitives; the newer acceptance peers provide separate transcript, KDF and signature oracles. |
| `RawSmb` | Byte builders for negotiate/session/tree/create/read/write/close/enumeration/disconnect. Public little endian accessors permit deliberate boundary mutations. `Response`, `Buffer`, `Names` validate independent wire structure; no production protocol serializers or decoders are used. |
| `FakeFileStore` | In-memory nodes, normal create/read/write/query/resize/rename/flush. `Seed`, `Contents`, `Handles`, `ActiveHandles` expose state. No real files or external share access. `Control` counts each method invocation before blocking/faulting. |
| `FakeFileHandle` | `DisposeCalls`, `IsDisposed`, path/metadata. Async disposal is countable, blockable and throwable. `PhysicalPath` is a synthetic watcher input only. |
| `OperationControl` | `Enqueue("Create", new(Barrier: gate, Error: new IOException(...)))` injects a one-use ordered step. `Status` injects a returned NTSTATUS on store methods. `Error` injects an exception on any controlled operation. Names: Create, Read, Write, QueryDirectory, SetEndOfFile, Rename, SetDeleteOnClose, Flush, GetInfo, Dispose, Send. GetInfo/Dispose/Send have no status return; use Error for their failures. |
| `AsyncBarrier` | Await `Entered` to establish ordering, assert the operation remains pending, then `Release` in a finally block. Waits are bounded and continuations never inline into a caller's critical section. Accepts cancellation. One-shot by design. |
| `RecordingTransport` | Attach to `SmbConnection.SendRawAsync`. `Sends` snapshots committed byte arrays/encryption flags; `Control` can park/fail Send before commit; `WaitForSendAsync` is bounded. Attach directly to public state for future dispatcher tests. |
| `FakeWatcher` | Records path/subtree/filter and active/disposal counts. `OnWatch` can emit synchronously before Watch returns to force pending-registration races; `Subscription.Emit` drives later events without sleeps. The five-argument watcher overload reports overflow/backend errors; the four-argument compatibility overload cannot claim loss reporting. |
| `ManualClock` | `TimeProvider` with UTC, monotonic timestamps, timers, `Advance` and active timer count. Pass to existing `SmbServerOptions.TimeProvider`. Timers coalesce periodic occurrences when advancing a large interval; this is a deterministic test clock, not a wall-clock scheduler. Callbacks run outside its lock. |
| `BuildIdentity` | Prints all six assemblies' identities/MVIDs plus JIT loaded paths and SHA-256. Enforces JIT assemblies load from the rebuilt application output. AOT prints linked identities and native executable path; Native AOT has no per-assembly loaded file paths. |

Fake storage intentionally does not model NTFS, durable persistence, symlinks,
share reservations, locks, oplocks, security descriptors or deletion semantics.
`SetDeleteOnClose` only records the flag. Test those contracts against production
state managers/local storage with disposable roots, rather than treating the fake
as a conformance oracle. A backend's cancellation token can be tested directly;
P0 does not assert the dispatcher forwards cancellation correctly.

For each later production repair, add a focused assertion, run it against the
unfixed source and retain the observed intended failure before editing production
behavior. P0 scaffolding/compiler setup is not behavioral RED/GREEN. Do not change
expected wire constants to match a serializer under test.

## Historical phase handoffs

The P1–P6 notes below describe each phase at its own completion. Later P7/P8 support and final counts are given in the final integration section and root README; intermediate restrictions and totals are not the current support matrix.

## P1 restrictions and deletion regressions

`--filter p1.` runs the P1 backend, configuration and independent wire cases.
They use disposable local roots for directory deletion, preserve signing-required
sessions, and offer SMB 2.1/3.0 where a feature's dialect requires it. SMB3 session
setup reuses existing key derivation/signing helpers only; request layouts,
capability masks, CREATE context bytes and expected statuses remain independent.
This is not a crypto validation claim. Existing SMB 2.0.2 fixtures keep independent
HMAC signing and their original expectations.

P1 adds `IFileHandle.CloseAsync(): ValueTask<NtStatus>` for fallible protocol close
work. The dispatcher always disposes afterwards, including a returned failure.
The default close hook succeeds without disposing, so existing backends receive
one disposal. Backends with fallible delete/close work must override the hook.
Local handles cache the result and never retry pathname deletion on disposal.

`SmbServerOptions.FeaturePolicy` is the fixed `SmbFeaturePolicy.Restricted` profile.
Supplied caching managers or durable stores do not enable grants/reconnects;
persistent stores, CA shares and explicit multichannel enablement are rejected.
The default dialect range and signing requirement remain intact. Shared identity,
multihandle delete-pending state, F08 and mandatory SMB3 channel sequencing remain
later-phase work in that historical phase. Current limits are in [capabilities](../docs/correctness/capabilities.md).

## P2 lifecycle

`--filter p2.` runs the session-ID, transaction, operation-drain, local identity,
rename/alias, stream and shared-deletion regressions. `--filter p2.stress.` runs
bounded stress after the deterministic gates. The full suite now requires F08 to
pass; `scripts/validate-platform.py` is the maintained native-host JIT/AOT driver.
Historical P0/P1 evidence and their original expected-baseline handling are unchanged.

`P2Tests.Direct` is a signed internal dispatcher fixture. It uses independent raw
packets, authenticated-session state already established in memory, and controlled
backend barriers. Real TCP fixtures still require the original authentication and
signing configuration. No on-wire multichannel is enabled by the shared-session
allocation tests. `HostFixture.NormalAsync` also leaves an ordinary open for tree
teardown so the standalone JIT/native host exercises F08.

The historical P2 backend used Linux `statx`; the active correction requires both
Windows and Linux with handle-based stable identities. Backend opt-in contracts
and conservative legacy fallback are described in [capabilities](../docs/correctness/capabilities.md). The two FSCC serializer changes
carry the shared DeletePending bit into standard/all information; they do not
implement the deferred P5 output-size work.

## P4 pending, control and notifications

`--filter p4.` runs the deterministic pending/sender, lock callback inversion,
notification FIFO/buffering/error, signed compound continuation and real signed
TCP cancellation/teardown cases. `p4.stress.` and `p4.lock.` add bounded resource
and release/unlock/cancellation stress. Historical per-case evidence is external;
[acceptance](../docs/correctness/acceptance.md) retains unresolved chronology. P3's resource-rejection regression now sets
an explicit zero pending-resource limit; default compound async processing uses
P4 continuations.

A successful sender calls `SmbConnection.ResponseSent(rawResponse)` after the
complete ordered write/flush, including compounded interims. Failure abandons
pending work and closes the transport. `RecordingTransport.Attach` installs this
acknowledgement; direct dispatcher fixtures simulate it by default. P4 sender tests
set `CommitResponses=false` and commit through the recording sender explicitly.
`WireClient.SendAsync`/`ReceiveAsync` allow independently signed multiplexed frames.
The original authentication and required-signing settings are preserved.

`OperationStep.IgnoreCancellation=true` models a backend that cannot stop admitted
physical I/O. P2/P3 drain tests use it explicitly and retain their handle-liveness,
ordering and disposal assertions. P4 distinguishes early cancelled responses from
physical retirement: close and operation scopes retain ownership until backend
completion. Shutdown tests order queued retirement before releasing physical I/O.

Watchers can override the compatible five-argument `IDirectoryWatcher.Watch`
overload to report lost events or a backend status. Existing four-argument adapters
remain usable but cannot claim loss reporting without implementing that overload.
The first directory request fixes the open's filter/subtree policy; buffering is
bounded by its initial output allowance, capped at 64 KiB. Watcher callbacks must
supply only events matching that subscription. Local watcher delivery is best
effort, with explicit rescan on FileSystemWatcher.Error. No physical cancellation,
external-client conformance or optional-feature restoration is inferred.

## P6 file caching

`--filter p6.` covers shared lease/oplock conflict state, pre-mutation barriers,
signed two-client TCP acquisition/content/overwrite/rename/delete/copy workflows,
compound CREATE continuations, sender/ACK ordering, virtual-clock timeout, cancellation,
disconnect, stable aliases/streams, backend policy and bounded resource stress.
`--filter p6.stress.` repeats resource and concurrent-ACK checks after deterministic gates.
See [capabilities](../docs/correctness/capabilities.md) and [acceptance](../docs/correctness/acceptance.md) for limits and historical chronology qualifications.

Restricted remains the default. Explicit `Caching` and `CachingWithCopy` profiles use
one built-in coordinator even when legacy managers are supplied. File grants require
`ICacheCoherentFileStore.HasExclusiveServerAccess` and stable handle identities.
Local shared host access never grants caching. Its four-argument constructor's explicit
exclusive-server assertion requires all mutation through one server state; watchers
are not a substitute. Existing three-argument constructor behavior is preserved.
No directory leases, multichannel, durable/persistent handles or CA are restored.

## P7/P8 final integration

P7a/b/c add mandatory SMB3 sequence state, explicit SMB300/302 multichannel and in-memory durable/replay cases. P8 adds `p8.audit.` (120 supplemental profile/dialect/backend rows) and `p8.local.` (five real local-backend TCP workflows). Historical published JIT/native harnesses passed 837/837; that result does not validate later source. `Smb.TestHost localtest` runs actual local TCP rounds and prints resource samples; `selftest` uses fake storage. Run `python3 scripts/validate-platform.py --out "$SMB_VALIDATION_OUTPUT"` from the repository root on Linux, or `python scripts/validate-platform.py --out $env:SMB_VALIDATION_OUTPUT` in Windows PowerShell. Set the variable to a new output directory outside the source tree. Native AOT requires the host C++ toolchain. Both Windows and Linux must run the full harness and actual LocalFileStore workload; native Windows execution remains outstanding.

`LocalWorkload` wraps the production OS watcher with a counting adapter. It uses a private disposable root and public loopback fixture credential, retains required signing, and asserts quiescent handles/pending/watchers/locks/shares/cache/recovery plus warm OS resource/managed-memory bounds. It never loads archived DLLs. These GREEN cases do not waive [historical acceptance gaps](../docs/correctness/acceptance.md). The second campaign repairs the earlier NTLM negotiation blocker and records fresh signed Samba/Go selections separately. Ordinary builds/tests need no external evidence directory, archived assemblies or storage mount.
