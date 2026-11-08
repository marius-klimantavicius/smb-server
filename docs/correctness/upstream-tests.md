# Adapted upstream correctness campaign

Campaign started 2026-11-08 against the 854-test baseline; the initial Linux JIT
harness passed 854/854 before additions or production repairs. This campaign
adapts test scenarios and independent expected results, without importing server
implementations or adding runtime dependencies. Test selection does not require
a license-check workflow, per the user's explicit instruction.

## Source selection and initial gap map

Inspected first-party test trees at these immutable revisions:

- [Samba source4/torture/smb2](https://github.com/samba-team/samba/tree/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2),
  revision `2816d12d5346c4e6258d8263f68eb653fd44fd5e`.
- [SMBLibrary.Tests](https://github.com/TalAloni/SMBLibrary/tree/582635541d2ec0c84eac5f66cbebd41e2d35c7ae/SMBLibrary.Tests),
  revision `582635541d2ec0c84eac5f66cbebd41e2d35c7ae`.
- [Microsoft FileServer tests](https://github.com/microsoft/WindowsProtocolTestSuites/tree/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer),
  revision `29ddb4238a5443b7499e82934c90cc898861c5e7`. This is a Windows-server
  conformance suite, not an SMB server implementation.

The following map precedes implementation. Final case mappings, observations and
dispositions below refine these selections; a candidate is not a claimed pass.

| Priority / upstream case | Existing coverage | Selected additional assertion |
|---|---|---|
| P0 Samba `create.c:test_smb2_open` | Basic CREATE and rollback; no complete independent disposition table | Existing/missing file dispositions, response action and preservation/truncation through real TCP/LocalFileStore |
| P0 Samba `create.c:test_create_gentest`; Microsoft `CreateClose.cs` | Parser boundaries and delete tests | Invalid semantic combinations fail before mutation; directory/file mismatch |
| P0 Samba namespace/share scenarios; Microsoft FSA `FileInfo_Set_FileRenameInformation.cs` | Stable identity, alias reservations and deletion regressions | Two-open sharing, rename collision/replacement and old-handle behavior with independent expectations |
| P0 Samba `lock.c:test_stacking`, `test_unlock`, `test_multiple_unlock`, `test_cancel`, `test_lock_read_write` | Callback inversion, cancellation races and replay | Ownership/stacking, exact unlock, atomic failed acquisition, I/O conflict and cancellation followed by retry |
| P0 Samba `compound.c:test_compound_related6`, related/invalid cases; Microsoft `Compound.cs` | Basic chain and failed CREATE propagation | Mixed dependency groups and errors with normative SHOULD differences recorded explicitly |
| P1 Samba `credits.c:test_crediting_skipped_mid`; Microsoft `MultiCredit.cs:BVT_MultiCredit_OneRequestWithMultiCredit` | Credit arithmetic and undercharge matrix | Independent skipped-ID/reuse sequences and multi-credit data round trips |
| P0 Microsoft FSA `QueryDirectory_FileNameInExpression_FileNamesInformation.cs`; Samba `dir.c:test_one_file`, `test_modify_search` | Pagination, reopen/restart and host case | Independent wildcard name sets, per-open cursors, empty/no-match/end/restart transitions |
| P1 SMBLibrary `NTFileStoreTests.TestCancel`; Samba `notify.c` | Notify FIFO, cancellation and overflow races | Cancel/close/rearm lifecycle and independent subscriptions without sleep-based upstream loops |
| P1 Samba `lease.c`, `durable_open.c`, `replay.c`; Microsoft durable/replay tests | Broad profile, replay and reconnect regressions | Supported profile combinations and adversarial duplicate/grant/recovery sequences missing from current cases |

Upstream behavior is evidence, not normative truth. In particular,
[MS-SMB2 3.3.5.2.7.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/46dd4182-62d3-4e30-9fe5-e2ec124edca1)
recommends propagating a previous related FileId operation's error. Samba's
`test_compound_related6` continues READ/CLOSE after a denied WRITE; that difference
alone does not establish a mandatory-protocol defect.

Native Windows execution remains unavailable. Direct-session fixtures establish
state before dispatch and are not external-client interoperability. Existing
external NTLM/signing blockers remain blockers. Security settings are preserved.
Raw downloads, logs, source snapshots and manifests are external; ordinary tests
need neither those files nor network access.

## Registered CREATE and namespace cases

`UpstreamCreateTests.Cases()` registers 29 cases under `upstream.create.`.
All use signed loopback TCP and the actual LocalFileStore. `UpstreamLocalFixture`
provides disposable host-neutral roots and retains the existing authentication
and required-signing configuration.

| Case suffix / group | Pinned upstream case | Adaptation and independent assertion |
|---|---|---|
| `disposition.*` (14) | [Samba create.c `test_smb2_open`, `open_funcs`](https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/create.c#L704-L867) | Six dispositions against existing/missing files plus invalid value 6; literal status table, CREATE action/EOF, nonempty content preservation or truncation, rejected-operation retry |
| `semantic.*` (7) | [Samba create.c `test_create_gentest`](https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/create.c#L135-L229) | Reserved options, DEVICE/VOLUME attributes, mutually exclusive directory/file flags, type mismatch and directory overwrite; rejected destructive requests preserve bytes/children and permit valid retry |
| `share.*` (3) | [Samba sharemode.c `test_smb2_sharemode_access`, `test_smb2_access_sharemode`](https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/sharemode.c#L471-L631) | Both directions of sharing conflict, READ/WRITE/DELETE, compatible-reader control, close/retry and no premature truncation |
| `rename.collision-replace-old-name-reuse` | [Samba rename.c `torture_smb2_rename_open`](https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/rename.c#L1690-L1768) | Two sessions retain source FileIds through collision and replacement; reuse old pathname as independent object and compare exact bytes through old/new handles |
| `rename.nonzero-root-atomic-retry`, `rename.short-record-atomic-retry` | [Microsoft FSA `FileInfo_Set_FileRenameInformation_SMB2_RootDirectory_NonZero`, `_BufferSize`](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileInformation/FileInfo_Set_FileRenameInformation.cs#L27-L140) | Nonzero root returns INVALID_PARAMETER; complete 23-byte record lacks required padding and returns INFO_LENGTH_MISMATCH; no mutation, usable FileId, valid retry |
| `delete.failed-create-does-not-arm` | [Samba delete-on-close.c `test_doc_create_exist`](https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/delete-on-close.c#L359-L410) | Colliding CREATE with DELETE_ON_CLOSE cannot arm deletion; query DeletePending, read, close and physical bytes |
| `delete.overwrite-if-close-stale-id-recreate` | [Samba delete-on-close.c `test_doc_overwrite_if`](https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/delete-on-close.c#L199-L249) | Temporary file deletes on close; recreate same name and reject stale FileId without touching replacement |

The disposition action/data extensions follow
[MS-SMB2 2.2.13](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e8fb45c1-a03d-44ca-b7ae-47385cfd7997)
and [2.2.14](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d166aa9e-0b53-410e-b35e-3933d8131927).
Rename record validation follows
[MS-SMB2 3.3.5.21.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/43cf22fe-84cb-49cf-b3e7-e3d7d766a7b7)
and [MS-FSCC 2.4.42.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/52aa0b70-8094-4971-862d-79793f41e6a8).
Microsoft's separator test marks itself inconclusive and contains contradictory
status commentary; it is excluded from adaptation, not counted as passing.

The first unfixed-source run passed 20/29. Nine observed failures: both invalid-6
dispositions, reserved options, DEVICE/VOLUME attributes, both type flags,
directory overwrite, nonzero rename root and short rename record. All but the
missing-file invalid disposition returned success; that row returned
OBJECT_NAME_NOT_FOUND instead of INVALID_PARAMETER. The captured production
hashes were unchanged. Another agent added a test file during this capture;
there is no claim that the entire checkout was frozen.

## Registered lock, compound and credit cases

`UpstreamProtocolTests.Cases()` registers 27 cases under `upstream.protocol.`.
The 26 deterministic cases use existing direct-session fixtures and independent
raw packets; the multi-credit transfer negotiates SMB2.1/LARGE_MTU through TCP.
Direct-session cases do not establish external-client interoperability.

| Case suffix / group | Upstream source and symbols | New assertion beyond nearest old tests |
|---|---|---|
| `lock.shared-stack-count`, `exclusive-shared-unlock-order`, `failed-upgrade-preserves-shared`, `exclusive-does-not-stack` | [Samba lock.c `test_stacking`, `test_unlock`](https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/lock.c#L1591-L2346) | Ordinary same-open lock multiplicity/ownership; peer probes verify exact release count and exclusive-first unlock, beyond P7b sequence-replay tests |
| `lock.unlock-other-open`, `unlock-exact-range`, `unlock-cannot-coalesce`, `invalid-unlock-flags-preserve` | [Samba lock.c `test_lock`, `test_unlock`, `test_overlap`](https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/lock.c) | Wrong FileId, partial/shifted/union ranges and invalid flags cannot release exact owner locks; peer probes and valid retry |
| `lock.multiple-unlock-first-missing`, `multiple-unlock-stops-at-gap`, `acquire-rollback-preserves-prior`, `acquire-internal-conflict-rollback`, `unlock-prefix-before-invalid-lock` | [Samba lock.c `test_multiple_unlock`, `test_stacking`, `test_overlap`](https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/lock.c#L1832-L2346) | Ordered partial unlock versus acquisition rollback; preserve old grants and foreign blockers; no ordinary multi-element counterpart in P4/P7b |
| `lock.shared-io-and-release`, `exclusive-io-boundaries` | [Samba lock.c `test_lock_read_write`, `test_lock_rw_shared`, `test_lock_rw_exclusive`](https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/lock.c#L354-L531) | Owner/peer READ/WRITE, crossing/adjacent ranges, backend nonentry on denial and exact resulting bytes; complements COPY and manager-only coverage |
| `lock.cancel-message-id-retry`, `cancel-async-id-retry` | [Samba lock.c `test_cancel`](https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/lock.c#L867-L995) | Waiter cannot unlock, CANCEL targets either identity, one final response, surviving blocker and fresh retry; complements notify and callback-race tests |
| `compound.*` (6) | [Samba compound.c `test_compound_related2/6`, `test_compound_invalid2/3`](https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/compound.c), [Microsoft `BVT_Compound_RelatedRequests`, `BVT_Compound_UnRelatedRequests`](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/Compound/Compound.cs) | Two related groups and failure reset, unrelated ECHO clears inherited FileId, unrelated error isolation, stale inherited CLOSE, explicit SHOULD error-propagation policy; extends P3 single-group chains |
| `credit.skipped-ids-survive-grants`, `multi-credit-interior-consumed`, `overlap-rejection-preserves-holes` | [Samba credits.c `test_crediting_skipped_mid`](https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/credits.c#L157-L264), Microsoft MultiCredit below | Keep lower IDs unused across 64 grants, consume charged interior IDs, reject overlap without spending holes; exact bytes and backend mutation counts beyond P3 arithmetic/two-ECHO tests |
| `credit.tcp-negotiated-roundtrip` | [Microsoft `BVT_MultiCredit_OneRequestWithMultiCredit`](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/Basic/MultiCredit.cs) | Actual negotiated grants/charges, 131073-byte exact round trip, 64KiB-crossing patch and cleanup; no injected server credit ledger |

Lock expectations follow
[MS-SMB2 processing unlocks](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/79eb3c91-563b-4d48-a51c-0974f9d144f8),
[processing locks](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/670c7eda-e683-4923-9477-414303959613)
and [MS-FSA range conflicts](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/124bb289-eeef-4653-b9c6-4fb93dd07a21).
Samba's inverse mixed LOCK-then-UNLOCK rollback case conflicts with current
MS-SMB2 text and is excluded. Credit rejection's INVALID_PARAMETER is the
existing direct-harness policy; the specification recommends disconnecting an
invalid sequence sender rather than mandating that response status.

The first protocol run passed 20/27 against production unchanged from baseline,
with no source drift during the capture. Seven failures: own shared-to-exclusive
upgrade, repeat exclusive acquisition, invalid unlock flags, unlock prefix before
missing range, internally conflicting acquisition, unlock prefix before invalid
lock, and a write by a shared-lock owner. All compound and credit cases passed
immediately, including the negotiated multi-credit TCP workflow.

## Registered enumeration, notification and profile cases

`UpstreamStateTests.Cases()` registers 30 cases under `upstream.state.`.
Enumeration uses LocalFileStore through signed direct dispatch; notification
events use the existing controlled watcher, without OS timing assumptions.
Advanced cases obtain actual grants through direct dispatch with a coherent local
backend, explicit Caching/Durable profiles, SMB3.0 and fresh direct-session state.
They do not seed recovery records or use reflection to create a grant.

| Case suffix / group | Pinned upstream case | New assertion beyond nearest old coverage |
|---|---|---|
| `enum.star`, `star-dot-star`, `question`, `suffix`, `dos-star`, `dos-question`, `dos-dot` | [Microsoft FSA `BVT_QueryDirectoryBySearchPattern_FileNamesInformation_*`](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/QueryDirectory/QueryDirectory_FileNameInExpression_FileNamesInformation.cs) | Literal name sets for seven wildcard forms, small-page progress, no duplicates and stable EOF; complements P5 host-case/restart tests |
| `enum.no-match-restart`, `independent-cursors`, `partial-restart`, `modified-restart`, `empty-close-reopen` | [Samba dir.c `test_one_file`, `test_modify_search`](https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/dir.c#L481) | Initial NO_SUCH_FILE versus later NO_MORE_FILES, per-open patterns/cursors, partial reset, post-mutation restart and closed/new cursor identity; no host ordering or active-scan snapshot assumption |
| `notify.cancel-rearm`, `cancel-middle`, `independent-delivery`, `close-one-open`, `cancel-close-reopen`, `independent-policies` | [SMBLibrary `NTFileStoreTests.TestCancel`](https://github.com/TalAloni/SMBLibrary/blob/582635541d2ec0c84eac5f66cbebd41e2d35c7ae/SMBLibrary.Tests/NTFileStore/NTFileStoreTests.cs#L26), [Samba notify.c `torture_smb2_notify_double`, `_close`, `_tree`](https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/notify.c#L1347) | Bounded cancellation/rearm replaces upstream sleep loops; middle FIFO cancellation, two opens/subscriptions, cleanup of one open, stale callback and independent initial policies; complements P4 single-open races |
| `lease.subset-sidegrade`, `close-one-member`, `reuse-after-last-close`, `no-self-break`, `epoch-stale-upgrade` | [Samba lease.c `test_lease_upgrade`, `test_lease_upgrade2`, `test_lease_nobreakself`, `test_lease_v2_epoch2`](https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/lease.c#L208) | Same-key RH sidegrade/subset/superset, rights survive partial close, final close frees key, only foreign key receives READ-to-NONE break, common v2 epoch wraps across stale-input promotions; extends P6 promotion and collision tests |
| `durable.bad-guid-then-valid`, `bad-lease-then-valid`, `v1-second-disconnect`, `v2-second-disconnect`, `independent-records` | [Samba durable_open.c `test_durable_open_reopen2`, `_reopen2_lease`](https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/durable_open.c#L731), [Microsoft `BVT_DurableHandleV2_Reconnect_WithBatchOplock`, `_WithLeaseV1`](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/DurableHandle/DurableHandleV2.cs#L440) | Rejected claims followed by valid recovery of granted opens, two disconnect/deadline cycles, two independent records with crossed GUID claim and exact recovered bytes; extends P7c single-cycle/individual rejection tests |
| `replay.repeated-and-duplicate`, `unrelated-open-io` | [Samba replay.c `test_replay_dhv2_oplock1`, `test_replay_twice_durable`](https://github.com/samba-team/samba/blob/2816d12d5346c4e6258d8263f68eb653fd44fd5e/source4/torture/smb2/replay.c#L354), [Microsoft `Replay_NonPersistentHandle_Write_ReplayEligibleCleared`](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/Replay/ReplayIsReplayEligible.cs#L787) | Repeated replay retains IDs/action/EOF/Batch/context, duplicate nonreplay rejection cannot erase owner, another open's WRITE/CLOSE cannot invalidate this open; extends P7c isolated duplicate and same-open invalidation cases |

Enumeration follows
[MS-FSA 2.1.4.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/0b034646-4e23-4874-8488-2adac231ff23)
for `*.*` and DOS wildcard semantics on either host. DOS_DOT uses extensionless
names, avoiding Windows's normalization of trailing periods in upstream setup.
The case-sensitive/case-insensitive host contract remains separate. Notification
fixtures validate dispatch/routing/lifetime, not native watcher filtering. Profile
fixtures validate supported SMB3.0 in-memory recovery, not persistent/CA recovery,
process restart or SMB3.1.1 recovery. The repeated-replay adaptation stays in an
active session; recovery is independently tested using reconnect contexts.

The first state run passed 26/30 with stable source during the capture. The
CREATE/rename validation repair had already been applied to that checkout;
enumeration, notifications and advanced state were still unfixed. Four failures:
`*.*` omitted extensionless names, and DOS_STAR/DOS_QM/DOS_DOT returned
NO_SUCH_FILE. All six notification and twelve advanced-profile cases passed.

For a common unchanged-production comparison, all 86 additions were also executed
externally against the original captured production source with the new tests
and explicit registration added to that external copy. This did not restore or
overwrite any shared-checkout file. Result: **66/86 passed, 20 failed**, matching
the three focused runs' failures exactly. The comparison source, production
hash manifest and output are retained externally. This is baseline comparison
evidence, not a claim that all three focused runs preceded the first repair.

## Repairs and regression assessment

The 20 failing new cases exposed six related defect groups. Every group has
observed behavioral RED on the original production bytes and unchanged expected
statuses/name sets in GREEN. Existing tests needed two fixture corrections below;
none was skipped or converted to an expected failure.

| Finding | Observed defect | Focused repair and evidence |
|---|---|---|
| U01 / A01, F16 | Ordinary CREATE accepted out-of-range disposition, reserved high option bits, DEVICE/VOLUME attributes, contradictory type flags and directory overwrite (7 failing rows) | Validate before file admission/backend mutation; preserve pipe disposition ignore behavior and existing replay/reconnect paths. All 29 CREATE cases pass. |
| U02 / A01, F09 | Rename accepted nonzero RootDirectory and a complete but unpadded 23-byte record (2 cases) | Require 24-byte minimum and zero root before namespace mutation; INFO_LENGTH_MISMATCH / INVALID_PARAMETER respectively. No backend API change. |
| U03 / F05 | Own shared/exclusive locks failed to conflict with exclusive acquisition; earlier elements of one request were invisible to later acquisition checks (3 cases) | Check each grant under the existing gate, including this request's earlier grants; rollback removes only its new suffix and preserves prior/foreign locks. |
| U04 / F05 | Invalid shared/exclusive unlock flags were lost; multi-unlock validation incorrectly withheld successful prefix effects (3 cases) | Retain raw flags in LockElement, process unlocks in order, stop on invalid/missing entry, retain and wake waiters after successful prefix. Exact unlock prefers exclusive before shared. |
| U05 / F05 | A shared-lock owner could WRITE its own locked bytes (1 case) | Separate I/O from acquisition conflict rules: all shared locks deny writes; an exclusive owner can still perform its own I/O. Rejected operations do not enter storage. |
| U06 / F13 | Host simple globbing omitted extensionless names for `*.*` and rejected DOS wildcard matches (4 wire cases; additional backend assertions exposed dot-entry leakage) | Stream host candidates and apply BCL SMB/Win32 expression matching to real and dot names; normalize `*.*` to `*`, retain raw `?`/DOS tokens and existing host case contract. Cursor, both listing overloads and versioning wrapper share expectations. |

The extra backend assertions were written and run before the wildcard repair:
the 12 enumeration cases then passed 6 and failed 6. `Fi?e` and `*ile` also
exposed unconditional dot entries in the listing APIs, while their wire paths
already passed. These independent literal name sets now run through cursor,
unbounded/bounded listings and the versioning wrapper. Result batches stay
bounded; cancellation is checked while scanning filtered-out candidates.

CREATE/rename repair regressions passed 478/478 selected cases. The stricter
rename validation first exposed old one-character rename builders producing
22-byte records: P2 passed 62/64, P6 passed 82/88 and P8 local passed 0/5.
Only required padding/enclosing length changed in `P2Tests.RenamePacket`,
`P6Tests.Rename` and `LocalWorkload`; target names and all behavioral assertions
were retained. Their final results were 64/64, 88/88 and 5/5.

The first full run after lock/wildcard repair passed 937/940. Three P7b replay
fixtures (`lock.changed`, `lock.skip.0`, `lock.skip.1041`) assumed that repeated
same-open exclusive acquisitions succeed, contrary to MS-FSA 2.1.4.10. Their
purpose is to test sequence replay/reapplication. They now acquire legally
stackable shared locks, preserving every status, application-count, unlock and
cleanup assertion. P7b then passed 44/44 and the full harness passed **940/940**.
The 86 upstream cases passed unchanged in their original expectations.

There are no quarantined or skipped registered cases. The upstream/spec-policy
and unsupported-source exclusions above are selection dispositions, not passes.
No runtime dependency or foreign production implementation was introduced.

## Reproduction

From the repository root, choose fresh external build/output directories via
environment variables. Normal test execution uses only maintained source:

```sh
dotnet run --project tests/Smb.Tests -c Release --artifacts-path "$SMB_TEST_BUILD" -- --filter upstream.
python3 scripts/validate-platform.py --out "$SMB_VALIDATION_OUTPUT"
```

Windows PowerShell uses the same native-host driver:

```powershell
dotnet run --project tests/Smb.Tests -c Release --artifacts-path $env:SMB_TEST_BUILD -- --filter upstream.
python scripts/validate-platform.py --out $env:SMB_VALIDATION_OUTPUT
```

Set `SMB_VALIDATION_OUTPUT` to a new directory outside the checkout. The driver
records commands, source snapshots/hashes, published artifact identities and
mode-specific counts; it publishes and executes the full harness and real local
TCP workload in JIT and Native AOT, plus repeated stress/expiry checks. It never
downloads upstream tests. Native Windows execution requires an actual Windows
host and remains outstanding. Final published Linux results are recorded in
[platform validation](platform-validation.md).

Final native Linux delivery completed all 26 driver steps with stable executable
source: published self-contained JIT **940/940**, published Native AOT **940/940**,
both host selftests, both 12-round actual LocalFileStore TCP workloads, and three
8-test stress plus three 1-test expiry-race repetitions per mode. All 430
published artifact hashes verified. The only analyzer categories were existing
IL2026/IL3050 in the unsupported persistent JSON store. Native Windows and real
external-client file-operation coverage remain outstanding; no cross-build,
direct-session test or adapted local client is counted as that coverage.

## Second campaign: protocol and authentication scope

The broader second campaign's port/disposition work and Linux gates are complete;
functional acceptance remains failed. Its fresh Linux JIT baseline passed 940/940
before additions. The first campaign's selections and results above are historical
evidence, not an inventory of complete upstream suites.

The user's subsequent instruction explicitly includes authentication tests:
"port as many tests as possible (only related to protocol/auth, not the internal
tests that test their server/code)". This supersedes the earlier exclusion of
authentication test coverage for this campaign. Applicable NTLM/SPNEGO session
setup, authentication success/failure and malformed input, session/key lifecycle,
and authentication-related signing/integrity cases join negotiation, framing,
dialect/capability and file protocol/state tests. Existing authentication blockers
must be reproduced and investigated; they are not blanket source exclusions.
Missing Kerberos/domain infrastructure may be recorded as a specific blocker.
Authentication, signing and encryption settings must not be weakened for a pass.
Focused repairs require valid observed failures; broader security design changes
remain findings requiring separate assessment.

New adaptations must assert independently meaningful behavior at the public SMB
protocol/authentication boundary. Backend observations may corroborate wire
effects. Internal-only managers, queues, caches, helper algorithms, object layouts
without a wire contract, server VFS APIs, client bookkeeping/error wrappers,
dependency mocks and Go-only io/fs implementation details are excluded. Existing
internal regression tests remain in place.

The source inventory includes the actual test trees of the Go servers
`macos-fuse-t/go-smb2`, `sonroyaalmerol/go-smb-server` and
`fiddyschmitt/portable-smb-server`, and the Go clients `CloudSoda/go-smb2` and
`hirochachacha/go-smb2`, alongside expanded pinned Samba and Microsoft FileServer
families. Every inventoried function and materially distinct subcase must have a
source revision and an honest disposition: adapted here, already covered with
exact local tests, unsupported feature, internal/client-only semantics, normative
mismatch, external/platform blocker, or remaining work. Each mapped group must
explain its protocol/auth relevance. Matrix rows and independent test scenarios
must be counted separately; duplicate assertions do not establish new coverage.
Feasible cases cannot be left as remaining merely because the inventory is large.

Test-port completion and functional acceptance are separate: failures remain
failures while other feasible cases continue to be ported. Final functional gates
require settled-source Linux JIT and Native AOT harnesses and actual local TCP
workloads with external output directories. Native Windows remains unexecuted.
Transient downloads, snapshots, build outputs and logs belong exclusively to the
new externally configured campaign; maintained tests remain offline and portable.

### Second-campaign source and repair records

| Record | Coverage and interpretation |
|---|---|
| [Go source inventory](upstream-go-tests.md) | All five pinned server/client trees: 147 test files, 1,401 Test functions; 83 registered protocol/auth cases, plus exact cross-source mappings and exclusions. Server and client projects are distinguished. |
| [Microsoft source inventory](upstream-microsoft-tests.md) | 3,205 entry methods in 176 files within the stated FileServer families; 297 registered cases. Generated graph positions are not independent executions. |
| [Independent inventory audit](upstream-inventory-audit.md) | 140 additional public cases and corrected Go/Microsoft mappings. The historical 2,694-selector regex extraction included non-calls; the corrected ledger contains 2,224 normalized member-call signatures, including source-only calls. Neither is a conformance count. |
| [Samba original inventory and auth extension](upstream-samba-tests.md) | Complete pinned directory symbol/table census, 751 initial cases and 60 further session/auth cases. The original untranslated rows must be reconciled with the continuation; the initial symbol census alone does not establish full adaptation. |
| [Samba continuation](upstream-samba-continuation.md) | Additional file/state/protocol workflows and exact source dispositions; retains source-policy differences and unresolved findings rather than converting them to passes. |
| [File/protocol repairs](upstream-repairs.md) | Observed CREATE, sharing, metadata, stream, I/O, lock, compression, negotiation, replay and delivery defects, independent reproducers, and regression evidence. |
| [Cache/auth parser repairs](upstream-cache-repairs.md) | Cache wait/revalidation, level-II invalidation, packet bounds, NTLM field layouts and explicit strict-Unicode policy, with original failures and specification qualifications. |
| [Descriptor repairs](upstream-descriptor-repairs.md) | Stable base-object policy across aliases/streams, partial SET serialization and bounded existing ACE semantics; 25 independent wire cases and explicit persistence/host-mutation limits. |
| [CREATE authorization](upstream-create-authorization.md) | Authorization before truncation/creation, parent add rights and post-wait identity revalidation; 34 independent cases. Descriptor-aware legacy backends have explicit guarded-acquisition restrictions. |
| [Maximal grants/control flags](upstream-grant-repairs.md) | Readonly file/backend and share grant bounds, host access from the final grant, and stored DACL controls; 24 independent cases. The separate Samba inherited-ACE marker policy still differs. |
| [Final IOCTL/reauth repair](upstream-final-protocol-repairs.md) | Server-control FileId/Flags ordering and response-local signing after failed reauth; 17 independent cases. One compound RED was a verified credit-window fixture error, with the original expected vector retained. |

The 15 retained failures in the audit's final 140-case capture are compatibility
expectations: ten optional information-class rejection statuses, two ARCHIVE
reassertion workflows, two undefined LOCK-flag combinations and the maximum
uint16 dialect-array offer versus the parser's bounded profile. These are not
15 established MUST violations or passing exclusions. Surrogate rejection is an
explicit namespace policy: Unicode 5 C10 permits replacement handling and does
not itself require INVALID_PARAMETER. Source-only grant targets and retention
choices are likewise distinguished from mandatory cache safety.

Fresh independent Go clients now authenticate and perform signed operations
across all five supported dialects after the NTLM SIGN negotiation repair.
Native Samba signed file operations and a required-encryption Go selection also
execute. Their exact versions, selected functions, baseline source hashes and
failures are recorded in the linked reports. These results supersede the first
campaign's blanket external-auth blocker for those configurations; they do not
claim an entire upstream suite or native Windows validation.

The native-host driver supports an optional continued capture:

```sh
python3 scripts/validate-platform.py --out "$SMB_VALIDATION_OUTPUT" --keep-going --stress-rounds 3
```

Default behavior remains fail-fast. With `--keep-going`, independent JIT, Native
AOT and host/TCP gates still execute after a harness failure. Failed publication
blocks its dependent executions; failed and blocked stages remain explicit, and
the overall result and exit code remain failing. No case is skipped or changed
into an expected-failure pass. The final settled-source results are recorded
separately from the historical intermediate captures above.

### Final second-campaign results

The settled harness has **3,144 unique registrations**: the prior 940, **2,068
additional source-derived protocol/auth cases**, and **136 focused repair
regressions**. These are executable registrations, including distinct protocol
matrix rows; they are not 2,068 unrelated upstream workflows. Inner operation,
packet-cut and dialect rows are not added to this count. Normal tests remain
offline, portable C# without a Go runtime or upstream implementation dependency.

| Allocation | Added registrations | Passed per Linux mode | Failed per Linux mode |
|---|---:|---:|---:|
| Samba initial expansion and auth/session | 811 | 810 | 1 |
| Samba continuation | 737 | 526 | 211 |
| Five Go server/client trees | 83 | 83 | 0 |
| Microsoft FileServer families | 297 | 297 | 0 |
| Independent inventory corrections | 140 | 125 | 15 |
| Source-derived additions | **2,068** | **1,841** | **227** |
| Focused repair regressions | 136 | 136 | 0 |
| Previous baseline | 940 | 940 | 0 |
| Full harness | **3,144** | **2,917** | **227** |

The following family counts partition the 2,068 source-derived additions by their
registered prefix; a workflow can exercise other commands but is counted once.
Source symbols, exact local names and adaptations are in the linked inventories.

| Public protocol family | Added | Pass | Fail |
|---|---:|---:|---:|
| Auth/session/negotiation/framing/compression/tree | 324 | 322 | 2 |
| CREATE/sharing/access/descriptors/attributes | 631 | 630 | 1 |
| Data/copy/EOF/metadata/timestamps/close | 145 | 143 | 2 |
| Namespace/streams/rename/delete/identity/snapshots | 134 | 125 | 9 |
| Directory/information classes/quota | 149 | 139 | 10 |
| Byte-range locks | 74 | 72 | 2 |
| Compounds/credits | 40 | 36 | 4 |
| Notify/cleanup | 33 | 25 | 8 |
| Leases/oplocks/caching | 216 | 88 | 128 |
| Durable/replay | 290 | 229 | 61 |
| Generated file-operation workflows | 20 | 20 | 0 |
| Other file protocol/IOCTL validation | 12 | 12 | 0 |

The native Linux x64 driver completed **26 stages** with stable executable source.
Published self-contained JIT and Native AOT each report **2,917 PASS / 227 FAIL**
with identical failing names. Both selftests, both actual LocalFileStore TCP
workloads, three stress and three expiry-race runs per mode, and native dependency
inspection pass. The only failed stages are the two full harnesses; the aggregate
status is **fail**, exit 1. All **430** published artifact hashes verify. There
were no skips, expected-failure conversions or retries substituting later success
for a failed execution. Final analyzer categories remain IL2026/IL3050 in the
unsupported persistent JSON store; no warning suppression was added.

External output is the new campaign's `final-linux-settled/` capture. It includes
the exact argument arrays, initial/per-stage source archives and hashes, loaded
assembly/native identities, every failed assertion and resource samples. Native
Windows is **unexecuted**; no Wine or cross-build result substitutes for it.

### Remaining findings and completion boundary

All 227 failures remain ordinary failing tests. They are not 227 confirmed
mandatory defects, nor passing exclusions:

- **211 Samba continuation cases:** 149 source cache grant/break choices; eight
  disconnected durable keep/purge choices; three lease epoch/version choices;
  six reconnect-context conventions; fifteen directory/descendant rename/share
  host choices; eight session recovery/replay and two completed CREATE replay
  conventions; three compound precedence choices; six unsupported stream-rename
  variants; one inheritance-marker convention; **two bounded cache sequences and
  eight notification event/cleanup reproducers still unresolved**. First failures
  can prevent later source assertions from being reached. A timeout is not assumed
  compliant merely because another row permits a conservative grant.
- **15 inventory cases:** ten optional information-class rejection SHOULDs, two
  deferred ARCHIVE reassertion expectations, two undefined LOCK-flag SHOULDs, and
  the maximum dialect-array cardinality versus the parser's bounded profile.
- **One original Samba case:** the OS2 legacy filename policy expectation.

The continuation's final source handoff originally had 214 failures. Three names
now pass: an IOCTL sentinel-order repair, failed-reauth signing, and the corrected
compound credit-window fixture. The final full runs contain exactly the expected
remaining names; no new failing name was observed in either mode. Original REDs
and every fixture/oracle correction remain retained in their own captures.

The Samba directory has a complete symbol/table census; the continuation resolves
all 445 originally remaining registered definitions and 37 helper symbols in its
allocation, with no feasible public partition left undecided. The Go audit covers
all 147 test files/1,401 Test functions. Microsoft covers the explicitly listed
FileServer families and generated public selector partitions, not all FileServer
protocols or an executed TestManager graph. Optional unsupported features,
source/private/client-only behavior, platform/KDC/domain blockers and normative
mismatches retain per-function dispositions. No whole upstream suite pass follows.

This completes the requested broad port/inventory campaign and its Linux
validation. It does **not** establish all-green functional acceptance, native
Windows support validation, full security conformance or production readiness.
Detailed reproducers and limits remain in the source/repair reports rather than
being hidden behind a test-port completion claim.
