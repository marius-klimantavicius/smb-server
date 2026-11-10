# Windows and Linux platform correction — 2026-11-08

The local backend now has Windows and Linux implementations. Optional durable
restart recovery passes 4,013/4,013 in both published Linux modes, with all 30
platform stages passing. Its settled capture follows the historical campaigns
below, including the 3,991-case supplied SQLite engine integration, previous
3,984-case SQLite delivery and valid 3,897-case failure-repair baseline. Native Windows JIT/AOT
execution is unexecuted; the user will test it later. Both-platform acceptance
remains open.

## Implementation

Windows uses UTF-16 Win32 APIs and SafeFileHandle lifetime management. Identity
is the volume serial and all 128 file-ID bits returned by
[GetFileInformationByHandleEx](https://learn.microsoft.com/en-us/windows/desktop/api/winbase/nf-winbase-getfileinformationbyhandleex).
Microsoft documents comparison of the complete volume/file-ID pair for object
identity in [FILE_ID_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info).
There is no pathname-derived identity fallback. Linux retains statx device/inode
identity and pinned descriptors. The deterministic 64-bit wire index is separate
from the full coordination identity.

Windows directory pins use backup semantics and read/write/delete sharing through
[CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).
Native rename/disposition handles verify the expected full identity before mutation;
final nonrecursive deletion runs while the last backend pin remains held. Metadata
access reopens the acquired object through
[ReOpenFile](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-reopenfile).
Rename and disposition layouts follow
[FILE_RENAME_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info)
and [FILE_DISPOSITION_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_disposition_info).

The repair covers same-name/case-only rename, descendant names and pending-delete
paths, shared hard-link disposition, pinned metadata, stable enumeration indexes,
host case matching, Unicode/drive/UNC API paths, directory pin cleanup and native
handle sampling. Shell hard-link fixtures and the Linux-only case expectation
were replaced with portable native fixtures and explicit host expectations.
The actual LocalFileStore workload still uses TCP and the production OS watcher.

Five Linux-reproducible defects had observed behavioral REDs before their repairs:
same-name rename, enumeration object indexes, metadata after pathname replacement,
named-stream indexes after rename, and pending-child deletion after parent rename.
All passed GREEN. Some captures observed concurrent user formatting; those records
do not claim frozen source. Windows-only contracts remain prospective tests,
without fabricated REDs or runtime results. A timing-sensitive cache test was also
corrected to await the owner's final WRITE before inspecting its bytes.

## Reproduce

Install the SDK selected by `global.json`, Python 3.9 or later, and the native
host toolchain. Linux needs clang and development dependencies; Windows needs the
Visual Studio Desktop development with C++ workload and Windows SDK. See
[Native AOT prerequisites](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/).

Set `SMB_VALIDATION_OUTPUT` to a fresh directory outside the source tree, then run
from the repository root:

```sh
python3 scripts/validate-platform.py --out "$SMB_VALIDATION_OUTPUT"
```

Windows PowerShell:

```powershell
python scripts/validate-platform.py --out $env:SMB_VALIDATION_OUTPUT
```

The same runner restores/rebuilds, publishes both JIT and Native AOT harness/host,
runs the full harness, selftest and actual localtest, and repeats stress/expiry
checks three times per mode. It selects the native host RID and records commands,
host identity, source hashes and artifact hashes. Optional `--temp-root` accepts
an existing writable scratch root, including a configured UNC share, for fixture
coverage. It never treats cross-publish or Wine as native Windows validation.

Ordinary restore/build/test and the runner require no evidence archive. The
optional `scripts/audit_evidence.py` utility requires `--evidence-archive` or
`SMB_EVIDENCE_ARCHIVE`, plus fresh `--out`; it accepts optional `--baseline` and
`--quic-source`/`SMB_QUIC_SOURCE`. Invalid configuration fails before output writes.
Run its focused configuration checks with:

```sh
python3 scripts/test_portable_tools.py
```

## Observed supervisor results

Linux x64, kernel 6.8, glibc 2.39, SDK 10.0.114, Python 3.12.3: all 26 delivery
steps exited zero. Published JIT and Native AOT each passed 854/854 tests, both
host selftests and 12-round real LocalFileStore TCP workloads. Each mode also
passed three 8-test stress selections and three 1-test expiry-race selections.
All 52 per-step source manifests matched the initial and current source; all
430 published artifact hashes verified. No source drift occurred in this run.
The only analyzer categories recorded were existing IL2026/IL3050 at persistent
JSON sites; supported profiles reject that persistent store.

The portable-tool suite passed 12/12 checks. A final maintained-tree audit checked 483
files and found no machine-specific evidence dependencies or broken Markdown
links. The raw evidence tree was relocated losslessly: 6,180 files and
1,244,875,645 bytes; the historical review was preserved byte-for-byte. Three
earlier temporary script edits were reversed with edited copies and restoration
hashes retained externally. The separate original 360-file archive still matches
its baseline. No repository evidence directory, symlink, GitHub configuration,
staging operation, commit or push was introduced by the agents.

## First adapted upstream campaign — historical Linux delivery

The later [upstream-test campaign](upstream-tests.md) added 86 cases to the
854-test platform baseline. Six groups of correctness defects were reproduced
and repaired: CREATE semantic validation, rename record/root validation,
same-owner and intra-request lock conflicts, ordered partial unlock effects,
shared-lock owner WRITE admission, and SMB wildcard matching. The preceding
854/854 result is historical; that first campaign's harness had 940 tests.

On the same native Linux x64 host (kernel 6.8, glibc 2.39, SDK 10.0.114,
Python 3.12.3), the maintained driver completed all **26 steps** successfully:

| Executed mode | Full harness | Host selftest | Actual local TCP workload | Repeated selections |
|---|---|---|---|---|
| Published self-contained JIT | 940/940 | Pass | 12 rounds, pass | 3 × 8 stress cases; 3 × 1 expiry-race case, all pass |
| Published Native AOT | 940/940 | Pass | 12 rounds, pass | 3 × 8 stress cases; 3 × 1 expiry-race case, all pass |

All 52 before/after source manifests matched the initial/current executable
source; no source drift occurred. All 430 published artifact hashes verified.
Every local-workload resource sample ended with zero opens, pending requests,
watchers, locks, waiters, share reservations and recovery records. The portable
script suite also passed 12/12 checks. No registered tests were skipped.
The final audit of 488 maintained files found no machine-specific evidence
dependencies, broken Markdown links or maintained symlinks. Pre-existing ignored
artifact history was left untouched; this campaign's evidence is external.

Only the pre-existing IL2026/IL3050 persistent JSON diagnostics were recorded;
supported profiles still reject that persistent store. Two new nullable fixture
diagnostics found during coordinator review were corrected with explicit
non-null assertions before this final gate; the earlier exploratory publish
is retained externally and is not this final-source result.

Commands remain those in Reproduce above: configure a new external
`SMB_VALIDATION_OUTPUT`, then run `scripts/validate-platform.py --out` with that
value. Focused commands and immutable source/case mappings are in the campaign
record. The raw baseline, RED/GREEN runs, source captures and final published
artifacts are external; no maintained file depends on their location.

## Outstanding validation and limits

Native Windows and UNC execution, Windows error/cleanup behavior, case-only rename,
disposition and Native AOT interop still need actual host runs. FILE_ID_INFO-capable
filesystems are required. Specialized Windows per-directory case-sensitive setups
are unvalidated. External OS handles can defer Windows final deletion; coordinated
namespace access remains required. Streams/EAs are process-memory, ChangeTime is
approximate and notifications are best effort. Historical TDD exceptions,
historical external setup failures, persistent/CA and QUIC provenance limitations
remain in [acceptance](acceptance.md) and [provenance](provenance.md).

## Second upstream campaign — settled Linux capture

The expanded [protocol/auth campaign](upstream-tests.md) has **3,144 unique
registrations**. The native Linux x64 runner executed all **26 stages**, using
new external output and scratch directories:

```sh
python3 scripts/validate-platform.py --out "$SMB_VALIDATION_OUTPUT" --keep-going --stress-rounds 3 --temp-root "$SMB_TEST_SCRATCH"
```

`SMB_VALIDATION_OUTPUT` must be a new external directory; `SMB_TEST_SCRATCH` must
already exist and be writable. The actual argument array and host details are
retained in the capture. Neither location is a source/runtime dependency.

Published self-contained JIT and published Native AOT each execute **3,144 cases:
2,917 PASS, 227 FAIL**, with identical failing names. The two full-harness stages
exit 1. Both hosts' selftests and actual 12-round LocalFileStore TCP workloads
pass. Each mode's three eight-case stress runs and three one-case expiry-race
runs pass. Restore/rebuild, all four publications and native dependency inspection
also pass. The driver records **24 passing stages, two failing stages, no blocked
stages**, aggregate **fail**, exit **1**. Continued capture does not turn failures
into passes, skip cases or retry them away.

Per-allocation outcomes in each mode are previous baseline 940/940, Go 83/83,
Microsoft 297/297, original Samba plus auth 810/811, Samba continuation 526/737,
inventory audit 125/140 and focused repair regressions 136/136. The source-derived
additions and exact family/remaining-failure groups are in the campaign report.
The failure set matches the prior assessed set exactly; there are no newly
failing names in either final mode. Bounded cache/notification reproducers remain
unresolved, alongside documented source-policy and unsupported-profile differences.
No all-green or full-SMB conformance claim is made.

All executable-source hashes stay unchanged across the 26 stages. All **430
published artifact hashes** verify. Logs retain assembly/native identities,
first assertions, resource samples and source snapshots. Final diagnostics are
the existing IL2026/IL3050 categories in unsupported persistent JSON APIs. No
analyzer warning was suppressed.

Runtime evidence is the new campaign's `final-linux-settled/`, with coordinator
failure-set/artifact verification under its `manifests/`. The interim
`coordinator-native-host/` was a successful earlier AOT host/TCP check, not a
substitute for this final full capture. Reports and `tests/README.md` were refreshed
after the gates; the post-documentation audit distinguishes those Markdown
changes from the unchanged executable source and published artifacts.

Native Windows, UNC and actual Windows AOT execution remain **unexecuted**.
No Wine, cross-build or simulated runner branch is presented as native evidence.
The test-port inventory is complete for the stated surveyed families; functional
acceptance and both-platform acceptance remain open.


## Multichannel and in-memory durable delivery — Linux

The [recovery delivery](multichannel-durable-reconnect.md) adds 371 ordinary
regressions and implements explicit SMB300/302/311 channels plus legal v1/v2
in-memory durable reconnection. Its initial clean `1def1af` baseline reproduced
2,917/3,144 and exactly the previous 227 failing names before implementation.

The native Linux x64 driver uses the unchanged portable command:

```sh
python3 scripts/validate-platform.py --out "$SMB_VALIDATION_OUTPUT" --keep-going
```

Choose a new external output directory. This runs restore/rebuild, all four
publications, full harnesses, selftests, actual local-backend TCP workloads,
three stress and three expiry-race selections per mode, and dependency inspection.

| Published mode | Full harness | Host selftest | Actual LocalFileStore TCP | Repeated selections |
|---|---|---|---|---|
| Self-contained JIT | 3,415 PASS / 100 FAIL / 3,515 total | Pass | 12 rounds, pass | 3 x 8 stress and 3 x 1 expiry, all pass |
| Native AOT | 3,415 PASS / 100 FAIL / 3,515 total | Pass | 12 rounds, pass | 3 x 8 stress and 3 x 1 expiry, all pass |

The two modes have identical failing names. Relative to the clean baseline,
127 previously failing names now pass, zero new failing names appear, and all
371 added cases pass. [Exact name differences and retained first diagnostics](recovery-failure-differences.txt)
are maintained separately. Of the remaining failures, 84 are Samba continuation
and 16 are inherited inventory/original-Samba rows. Their primary-spec, source
compatibility and unresolved-workflow distinctions are in the recovery report.
The full harness and aggregate platform result remain **fail**, exit **1**.
There are 24 passing stages, two failed full-harness stages and no blocked stages.

The first published capture recorded documentation-only source drift:
`tests/README.md` changed during Native AOT execution. Every executable and test
code hash remained unchanged; both modes had exactly equal results and first
failure diagnostics. Its 430 artifact hashes verified. That capture is preserved
with its original drift indication; it is not relabeled fully source-stable.
After freezing the tracked inputs, a separate complete platform capture was
completed with the same counts and failing names, without changing executable
behavior or test expectations. All 52 per-stage before/after source manifests
match its initial manifest; no source drift occurred. All 430 published artifact
hashes verify. No further broad retest followed this settled gate.
One retained case, `upstream.samba.more.notify.delete-directory.False.False`,
reports "No recorded send" in JIT and the general timeout in Native AOT; its
failing name is unchanged. The exact per-mode diagnostics are in the name report.

The Release builds add no warnings. Publication retains the existing
IL2026/IL3050 diagnostics in unsupported persistent JSON APIs; no analyzer
suppression or persistent capability was introduced. Native client selections
are recorded separately: Samba 36/39 processes pass (three older v2 filename
status expectations retained), and the pinned public Go client passes 6/6.
Those selections include SMB311 binding; they are not whole-client-suite or
all-cipher/domain certification.

Native Windows JIT/AOT and UNC execution remain **unexecuted**. The portable
implementation and runnable Windows configuration are provided, with no Wine,
cross-build or Linux substitute presented as native Windows acceptance.


## Remaining-failure repair delivery — settled Linux capture

The [follow-up repair campaign](remaining-failure-repairs.md) starts at clean
`c296735` and reproduces 3,415/3,515 with the same 100 failing names before
implementation. The final source retains every original registration and adds
382 ordinary wire/lifecycle cases. Original source failures, intermediate
regressions and specification/profile fixture corrections remain externally
preserved and are distinguished in the report.

The unchanged portable driver ran once after final integration and test-input
freeze, with a new external output directory:

```sh
python3 scripts/validate-platform.py --out "$SMB_VALIDATION_OUTPUT" --keep-going
```

| Executed mode | Full harness | Host selftest | Actual LocalFileStore TCP | Repeated selections |
|---|---|---|---|---|
| Published self-contained JIT | 3,897/3,897 PASS | Pass | 12 rounds, pass | 3 x 8 stress; 3 x 1 expiry, all pass |
| Published Native AOT | 3,897/3,897 PASS | Pass | 12 rounds, pass | 3 x 8 stress; 3 x 1 expiry, all pass |

All **26 stages pass**, aggregate **pass**, exit **0**. Restore/rebuild, all four
publications and native dependency inspection pass. All 52 stage before/after
source manifests equal the initial manifest; there is no source drift. All
**430 published artifact hashes** verify. The test README was updated before
freeze; later documentation changes are outside the captured input set.

The comparison finds **100 resolved original failing names**, zero retained
failures, zero new failures, zero missing baseline registrations and all 382
new registrations passing in each mode. Both modes retain the original 940 and
all 371 recovery tests. Samba continuation is 737/737, all maintained Samba
registrations 1,548/1,548, inventory 140/140, Go adaptations 83/83 and Microsoft
adaptations 297/297. These are maintained adaptations and profile oracles, not
execution or certification of entire original upstream suites.

[Exact original-name dispositions](remaining-failure-results.txt) and the
[repair/specification report](remaining-failure-repairs.md) describe the change.
No test was skipped, removed, retried into success or converted to expected
failure. Corrected backend-convention/invalid-profile oracles are explicit and
include complete data, identity, rights, rejection/retry and cleanup assertions.
This does not claim 100 independent production defects or full Windows fidelity.

Release builds add no warnings. Publication retains the known IL2026/IL3050
categories in unsupported persistent JSON APIs; no suppression or persistent
capability was added. No further broad Linux test loop follows this settled gate.
Native Windows JIT/AOT and UNC execution remain **unexecuted**. Historical strict
acceptance qualifications, broader conformance and provenance limits remain open.

A subsequent bounded independent native Samba check against this published
Native AOT host passes 27/27 processes: eighteen signed/default and nine required
encryption probes across SMB300/302/311, including actual channel binding and
durable reconnect. Both test hosts stop normally. These processes are separate
from the 3,897-case harness and do not certify the complete native client suite.

## SQLite integration — settled Linux capture

This subsection records the previous native-SQLite delivery. The supplied-engine
capture below supersedes its current dependency, packaging and test-count claims.

The [optional SQLite provider](../sqlite-provider.md) adds `sqlitetest` and
native SQLite packaging inspections per published mode to the portable driver.
All original stages/assertions remain. The default three-round driver adds four
stages (30 on Linux, 29 on Windows); earlier 26-stage results above are historical.

On 2026-11-09, the coordinator completed the final native Linux x64 capture
(kernel 6.8, glibc 2.39, SDK 10.0.114, Python 3.12.3) after executable-source freeze,
using a new external output directory:

```sh
python3 scripts/validate-platform.py --out "$SMB_VALIDATION_OUTPUT" --keep-going
```

Published self-contained JIT and published Native AOT each pass **3,984/3,984**.
Each retains all **3,897** baseline names and adds **87 SQLite cases**
(54 backend + 33 integration), with zero missing, failed or duplicate names.
The full harness includes the separate-process clean/crash recovery cases.
All **30 stages pass**, aggregate **pass**, exit **0**. Both hosts pass selftest,
12-round actual LocalFileStore TCP and actual SQLite TCP across two provider/server
lifetimes. Each mode passes 3 x 8 stress and 3 x 1 expiry-race cases.

Restore/rebuild, all four publications, native dependency inspection and both
SQLite packaging gates pass. All four host/harness outputs load their bundled
native SQLite **3.53.3**. The win-x64 native asset is restored and inspected,
not executed. The portable-tool suite separately passes **12/12**.

All **60** stage before/after source manifests equal the initial manifest;
the capture is source-stable. All **448 published artifact SHA-256 hashes** verify.
Core production source remained unchanged throughout integration. These
documentation updates follow the frozen executable-source capture; the updated
documents are not claimed as frozen capture inputs. Raw evidence remains external.

The Release rebuild has **0 warnings, 0 errors**. Publications retain only the
existing IL2026/IL3050 diagnostics at unsupported persistent JSON sites, with no
new SQLite warnings or suppressions. Native Windows JIT/AOT remains **unexecuted**;
restored assets on Linux are packaging evidence only. Process-kill recovery does
not test power loss or supply persistent SMB recovery/continuous availability.
The provider's documented ADS, EA, CHANGE_NOTIFY and other limits remain.


## Supplied SQLite engine — settled Linux capture

On 2026-11-09, a clean capture after executable-source freeze used SDK 10.0.114,
native Linux x64 (kernel 6.8, glibc 2.39), and the portable command:

```sh
python3 scripts/validate-platform.py --out "$SMB_VALIDATION_OUTPUT" --keep-going
```

Published self-contained JIT and NativeAOT each pass **3,991/3,991**. Both retain
all **3,897 baseline names** and all **3,984 prior names**, with exactly seven
additions, zero missing/failed/duplicate names, and **94 SQLite cases**. The
additions exercise statement tails, empty BLOB versus NULL, binding copy lifetime
and Int64, binding errors, statement disposal after binding failure, transaction
errors/rollback/reuse, and an independent prior-provider schema-1 fixture.

All **30 stages pass**, aggregate **pass**, exit **0**: SDK, restore, rebuild,
four publications; each mode's full harness, selftest, LocalFileStore TCP,
SQLite TCP, engine/packaging gate, three stress and three expiry-race runs;
and Linux native dependency inspection. Both LocalFileStore hosts complete
12 rounds; both SQLite hosts complete actual signed SMB311 TCP across two
store/server lifetimes. Full harnesses retain signed SQLite TCP dialect matrices,
separate-process owner/alias rejection and controlled process-kill recovery.
Each mode passes 3 x 8 stress cases and 3 x 1 expiry-race cases.

All four fresh outputs execute supplied **Managed.Database.Sqlite 3.54.0** through
**Ews.Common.Sqlite**, verifying SQL version/source ID against compiled constants.
All ten restored assets graphs and published directories exclude Microsoft.Data.Sqlite,
SQLitePCLRaw and native SQLite assets. Native host dependencies are libc/libm and
the platform loader; no native SQLite. OS P/Invoke remains for VFS services.
The portable tool suite separately passes **12/12**.

All **60** stage before/after source manifests equal the initial manifest;
source is stable. All **440** published artifact SHA-256 hashes verify. The
Release rebuild has **0 warnings, 0 errors**; publication retains the existing
IL2026/IL3050 warnings in unsupported persistent JSON APIs. No new SQLite warning
or suppression was introduced. Raw commands, logs, archives, manifests, name
audits and artifact hashes remain external. These summary documentation changes
follow the executable-source capture and do not alter captured executable inputs.

Four focused repairs first failed behaviorally against a compiling framework,
then passed unchanged tests: ignored SQL tails, empty BLOB bound as NULL, ignored
bind result codes, and leaked statements on a throwing bind callback. Compilation
setup (logging reference and binder delegate signatures) is recorded separately.
The transpiled generated engine, VFS source and supplied LICENSE.txt are unchanged.
The initial staged index is byte-identical; nothing was staged or committed.

The embedded pre-migration fixture was generated by the previous published
Microsoft.Data.Sqlite 10.0.14/SQLitePCLRaw 2.1.13 provider with SQLite 3.53.3.
Its original IDs, bytes, security, timestamps and schema pass through the new
provider, followed by new sparse cross-chunk writes and reopen/integrity checks.
A separate new-engine commit into an old database remains readable by the old
published provider with an identical snapshot. Fixture hashes/provenance are
retained beside the portable fixture; routine tests need no old runtime.

Both host and harness also cross-publish successfully as self-contained
**win-x64 JIT**; ten restored graphs and 420 cross-published file hashes are
captured, with no old provider or native SQLite assets. This is compilation and
packaging evidence only. **Native Windows JIT/AOT remains unexecuted**; Windows
AOT was not cross-published. Process-kill recovery does not emulate power loss.
Persistent SMB recovery/continuous availability and the provider's documented
ADS, EA, CHANGE_NOTIFY and broader platform/provenance limits remain unchanged.


## Optional durable restart journal — settled Linux capture

The optional recovery delivery adds `IServerRecoveryStore` and the separate
`Smb.Persistence.Sqlite` implementation, plus stable-identity backend retention.
Clients authenticate again; no authenticated sessions or keys are resurrected.
[Configuration, contracts and limits](../durable-recovery.md) describe this
single-server recovery surface. SMB persistent-handle flags and continuous
availability remain disabled.

The final clean Linux x64 capture on 2026-11-09 runs the same portable command:

```sh
python3 scripts/validate-platform.py --out "$SMB_VALIDATION_OUTPUT" --keep-going
```

Published self-contained JIT and published NativeAOT each pass **4,013/4,013**.
Both retain all **3,991 prior names**, including every original 3,897 baseline
name, and add **22** recovery cases with zero missing, duplicate or failed names.
The focused `recovery.` selection passes **26/26** (22 new and four existing).
New cases cover journal round trips/ownership/IDs, retained pending objects,
signed TCP restart across SMB202/210/300/302/311, batch and lease recovery,
pre-reconnect lock/share reservations, fresh sessions and owner rejection,
expiry, pending deletion, changed-backend rejection, duplicate CreateGuid,
failed-close retry, destructive-mutation prevention after journal invalidation
failure, graceful active shutdown, and actual serving-process kill/restart.

All **30 stages pass**, aggregate **pass**, exit **0**. Both modes pass full
harness, host selftest, 12-round LocalFileStore TCP, two-lifetime SQLite TCP,
compiled-engine/packaging checks, 3 x 8 stress cases and 3 x 1 expiry-race cases.
Restore, rebuild, all four publications and Linux native dependency inspection
pass. All **60** stage source manifests match the initial source; all **443**
published artifact SHA-256 hashes verify. The Release rebuild has **0 warnings,
0 errors**. Publication retains only the existing legacy persistent-JSON
IL2026/IL3050 warnings; the new source-generated recovery serializer adds none.
The portable-tool suite separately passes **12/12**.

An earlier complete capture passed both 4,013-case harnesses but rejected the
new managed recovery assembly in the old JIT packaging allowlist. That
intermediate capture remains external with its failure intact. The runner now
allows precisely the repository filesystem and recovery managed SQLite
assemblies and verifies their PE/CLR metadata, while retaining every old-package
and native-SQLite exclusion. The complete clean final rerun above passes all
30 stages; it supersedes the intermediate result.

Both fresh modes prove execution of supplied SQLite **3.54.0**. All eleven
restored assets graphs and published directories exclude Microsoft.Data.Sqlite,
SQLitePCLRaw and native SQLite libraries. Engine/VFS/generated library sources
and both licenses remain unchanged from this delivery's starting checkout.

Both host and harness also cross-publish successfully as self-contained
**win-x64 JIT**. Eleven restored graphs and **422** cross-published artifact
hashes are captured, with old-provider/native-SQLite assets absent. Native
Windows JIT/AOT and power-loss testing remain **unexecuted**. These documentation
updates follow the executable-source capture. Raw commands, behavioral RED/GREEN,
fixture corrections, intermediate failures, source archives and final audits
remain external. No commit or staging operation was performed.
