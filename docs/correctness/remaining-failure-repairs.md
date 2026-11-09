# Repairs following the 100-case failure inventory

This campaign starts at `c296735`, after the multichannel/durable delivery. Its
fresh baseline reproduces 3,515 tests, 3,415 passing and the same 100 failing
names, with unchanged source. The original inventory is retained in
[recovery failure differences](recovery-failure-differences.txt). Earlier reports
and their original results remain historical evidence.

## Production changes

| Area | Repair and maintained source |
|---|---|
| Mixed file caching | [FileCacheCoordinator](../../src/Smb.Server/Caching/FileCacheCoordinator.cs) permits compatible READ leases and classic level II, rearms read caching and promotes shared RH rights while blocking unsafe WRITE promotions and new rights during physical I/O. Classic and lease state remain distinct. |
| Lease lifetime | Common lease version and epoch survive additional opens. The response context format follows the incoming request version, while retained durable state records the common lease version. A declined new v2 grant preserves the supplied epoch. |
| Break sequencing | Sharing denial attempts HANDLE/Batch invalidation before retrying the reservation under all caching profiles. Queued destructive CREATE stages its required downgrades without overlapping ACK obligations or entering physical mutation before invalidation. |
| Metadata and locks | Attribute/time and per-open position updates bypass data-cache invalidation. Metadata-only QUERY_INFO does not consume cached stream data; data-open size queries retain coordination. An optional nonmutating lock-conflict preflight permits immediate rejection; atomic lock acquisition remains authoritative. |
| Directory notifications | A successful delete disposition completes matching outstanding directory notifications with DELETE_PENDING across sessions. A per-open sticky deletion marker is distinct from current shared disposition. The disposition check and waiter publication share a gate, closing the registration race. |
| Security notifications | Successful selected security-component SETs publish one explicit process-memory metadata event to matching local subscriptions, respecting their first filter, subtree, current relative path and bounded FIFO. Zero-component requests publish no event. Native watchers remain active for native changes. |
| Boundary behavior | Known unsupported information classes select NOT_SUPPORTED; undefined classes retain INVALID_INFO_CLASS. Invalid LOCK flag combinations fail before ownership changes. A fully present ushort-sized dialect array is accepted without the former 64-entry cap; truncated arrays still fail. |
| ARCHIVE updates | Successful nonzero writes, EOF changes including ADS, and new-child parent updates select the recommended ARCHIVE behavior using acquired handle identity. Other DOS attributes remain intact. |
| Directory rename | [IFileNamespaceStore](../../src/Smb.FileSystem/IFileNamespaceStore.cs) separates SMB's strict descendant check from generic backend relocation. [LocalNamespace](../../src/Smb.FileSystem/Local/LocalNamespace.cs) rechecks all acquired descendants atomically before mutation, including arrivals during a lease-break wait. The destination parent's acquired identity and sharing reservation remain pinned across the operation. |
| Named-stream rename | Existing stream data objects and stable stream identity move within the acquired base file. Collision, live/nonempty target, same-name and default-promotion cases preserve handles, bytes, locks, sharing and disposition. [LocalStreamTable](../../src/Smb.FileSystem/Local/LocalStreamTable.cs) shares families across backend aliases and pins identity while stream data survives. |
| Compound routing | Required identifier/dependency errors avoid unrelated cache admission. Unknown command framing is validated before predecessor-status propagation. Related component order, signatures, IDs and terminal outcomes remain checked. |
| Replay | Introducing a lease into an existing classic replay is rejected without consuming the original claim. Ordinary cross-session replay remains distinct from explicit durable reconnect and persistent/CA recovery. |

Restricted remains the default. No directory lease, persistent-handle, CA,
clustering or restart-recovery capability is enabled. All caching still requires
the explicit coherent-backend deployment assertion; it is not an OS fence.

## Primary mapping and selected compatibility policies

- [MS-SMB2 lease-v2 processing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fc4f8879-f295-4995-b71e-21f309d8d7c8)
  and [lease-v1 processing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/24cfce29-5d80-4651-ba5f-a2661c666b41)
  govern common lease lookup, promotion, response format and epoch. An incoming
  v2 request does not convert a common v1 lease's lifetime into v2.
- [Lease-break processing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/c367fad4-c00f-4778-913d-c0560ead1360)
  governs targets, ACK obligations, epochs and unavailable durable members.
  Recommended epoch increments are selected for successive notifications;
  historical unchanged-epoch behavior is documented separately.
- [QUERY_INFO](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d64e0451-64a2-425a-848e-52a7dddab7b9),
  [LOCK](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/670c7eda-e683-4923-9477-414303959613)
  and [NEGOTIATE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e14db7ff-763a-4263-8b10-0c3944f52fc5)
  distinguish known unsupported values, invalid flag combinations and complete
  bounded wire arrays. These changes retain authentication and message validation.
- [MS-FSA directory disposition](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/386d9ec5-e0f6-4853-b175-c05be01419e0)
  and [notification registration](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/e9e427f6-16b6-49ff-8782-6b564bef7726)
  distinguish pending waiters from the disposition-setting open's sticky marker.
- [SET_SECURITY](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/2e97fa70-e1f5-410b-ba87-f1ffda39a8ed)
  describes metadata-change posting. Emitting a security notification for every
  successful selected-component SET, including identical descriptors, is the
  chosen source-compatible policy. This does not implement a USN journal.
- [Stream rename](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/78a9210c-d708-4793-86e7-3c7f9c51d17f)
  requires rejection of a nonempty or open named target. Default promotion has
  separate target lookup semantics and preserves prior unnamed-stream handles.
  [Streamname](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/5953f072-b28c-4fbf-ae50-09b0173317b9)
  and [streamtype](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/0b4fa453-52fd-4b4a-96eb-4e6a149776e6)
  define their invalid-character checks.

The selected lease/byte-lock grant strategy can retain coordinated shared caching
while physical range access remains blocked. Every physical READ/WRITE and lock
acquisition still checks authoritative ownership. This is an object-store
interoperability policy, not a claim to reproduce every MS-FSA acquisition rule.

## Test-first evidence and fixture corrections

Each behavioral repair follows an observed existing or new RED, then GREEN and
affected regressions. New evidence is allocated externally at runtime and records
source snapshots, exact arguments, original output, status and artifact identity.
No maintained build/test depends on those captures or upstream clones. Original
archives, failing adaptations and intermediate regression results are preserved.

The cache batch observes all 44 assigned original REDs and adds 166 TCP cases.
Its integrated final-source full run is 3,681 total, 3,625 passing and 56 failing:
exactly 44 baseline names resolved, with no new failing names or source drift.
The notification/boundary batch repairs its eight notify and fifteen inventory
cases and adds fourteen TCP/lifecycle probes. The namespace batch repairs thirty
assigned cases and adds 67 TCP cases. These isolated/focused results do not
substitute for final merged-source published-mode validation.

Preserved fixture corrections are explicit:

- A destructive CREATE that revoked the previous Batch grant cannot later
  count that old cache as an existing level-II grant. The corrected workflow
  proves no truncation before ACK, exact truncation afterward and the actual
  remaining grant's invalidation.
- Cross-version CREATE response format follows the incoming context. Tests
  separately prove that the common lease's original version and epoch survive.
- Successive queued notifications check recommended epoch increments and exact
  RH-to-R and R-to-NONE safety, rather than imposing historical Windows timing.
- Older unsupported-query fixtures now use the selected exact NOT_SUPPORTED
  result for known classes, retaining access, sizing, data and close/reopen checks.
- Two durable RH adaptations incorrectly demanded loss despite HANDLE caching.
  Their corrected workflows verify retained locks, bytes, identity and close.
- Three ordinary replay adaptations assumed the persistent/CA recovery branch.
  They now reject cross-session CREATE replay, explicitly reconnect, then verify
  same-session replay with the original action and usable data. Persistent/CA
  behavior remains unsupported and is not counted as implemented.
- Batch replay response reconstruction retains the established Open grant;
  altered replay request fields cannot relax its original sharing promise.
- Stream replacement originally expected success over a nonempty named target.
  The corrected test verifies rejection and preservation, explicitly empties and
  closes the destination, then proves successful rename and data preservation.
- Enumeration-only fixtures stop requesting incidental DELETE access on the
  destination parent. Their enumeration/identity assertions are retained.
- The adapted Go directory rename first verifies SMB's denial with a live child
  and intact acquired bytes, then closes the child and completes the original
  successful rename/list/reopen/read workflow. Generic backend relocation tests
  retain their separate live-child contract.

No skip, expected-failure conversion, registration removal or automatic retry
turns an unsupported or broken workflow into a passing test.

## Final integration and profile reconciliation

The settled merged harness passes **3,897/3,897**, including every original
failure name, all 940 earlier baseline cases and all 371 recovery additions.
The campaign adds 382 registrations: cache TCP 191, namespace TCP 79,
notification/boundary TCP 14 and inheritance/name TCP 98. Inner descriptor
partitions and individual SMB operations are not counted as registrations.
[Every original failing name and its current disposition](remaining-failure-results.txt)
is recorded separately. Published Linux JIT and Native AOT each reproduce
**3,897/3,897**, with all 26 driver stages passing, 53 identical source manifests
and 430 verified published-artifact hashes. Both actual LocalFileStore TCP
workloads, both host selftests and all repeated stress/expiry selections pass.
See [platform validation](platform-validation.md). The source/test inputs remain
unchanged; documentation outside the captured input set is reconciled separately.

The last production admission fix adds READ_EA to one named metadata-only CREATE
predicate. It applies only to nondestructive CREATE without a sharing conflict.
READ_DATA, WRITE_DATA, APPEND_DATA, EXECUTE, WRITE_EA, physical EA SET and namespace
mutation retain cache coordination. The exact original stat compound is unchanged.
Twenty-five TCP cases prove metadata-only access cannot read/write data, leaves
bytes/timestamps and the original cache intact, and requires correct breaks and
ACKs before subsequent data access, destructive CREATE or EA mutation. Five
metadata CREATEs failed before the fix; all twenty-five pass afterward.

READ_EA exemption is the selected server metadata policy, not a Windows native
MUST: the native IRP_MJ_CREATE table guarantees a narrower exemption. Two older
stat-table fixtures required a break for READ_EA alone while the exact compound
required no break for the same metadata rights. They now use one consistent
policy while retaining all twelve access-mask partitions and exact break counts.
No implementation branch special-cases a test name, compound shape or exact mask.

The new notification-after-rename probe originally kept an acquired child during
directory rename, contradicting the corrected descendant contract. Its stronger
workflow now proves denial with unchanged acquired bytes, complete descriptor,
name and identity; closes the child; renames the directory while retaining the
same watched FileId; reopens/renames the child; and checks the exact new relative
security event, name-filter isolation, cancel/rearm and close cleanup frames.
This correction passes against unchanged notification/namespace production.

Two original backend-convention assertions also needed explicit reconciliation:

- The basic descriptor profile records inherited ACE origin independently of
  descriptor auto-inheritance controls. The original source table's conditional
  marker-zero convention was not implemented. Its ordinary registration now
  verifies the exact inherited marker and complete ACL bytes through all sixteen
  parent by sixteen explicit-child control combinations. Another 96 TCP cases
  check controls and propagation, exact deny/allow ordering and masks, data access,
  fixed handle grants, rejected descriptor updates, rename/identity and cleanup.
- The literal `.+,;=[].` contains none of MS-FSCC's excluded filename characters.
  Its old Samba legacy-error expectation is not imposed as a global DOS/8.3
  restriction. The same ordinary case and two added dialect rows instead verify
  exact create/open actions, bytes, EOF/name/identity, closed-handle rejection,
  exact enumeration, wrong-name/wildcard controls, sentinel preservation and
  deletion under the declared host-name profile.

These are stronger supported-profile workflows with the original source and
failures archived, not production fixes for the original backend conventions.
No full Windows ACL algorithm, dynamic subtree rewrite or legacy short-name
emulation is claimed.

The coordinator's local review found a stream-type validation ordering defect.
Twelve additional TCP cases observed nine wrong statuses before the fix. Invalid
slash, backslash or NUL in a type now returns INVALID_PARAMETER before valid-type
comparison; a valid different type still returns OBJECT_TYPE_MISMATCH. Failed
rename preserves old handles, bytes and absent target, then a valid retry moves
the same stream. All 79 namespace TCP cases pass. The separately delegated broad
audit was blocked by automated screening and did not execute; it is not reported
as an independent review pass.

## Independent client checks

After the final platform gate, a bounded native Samba 4.19.5 selection against
the published Native AOT host passes **27/27 processes**: eighteen signed/default
and nine required-encryption probes across SMB300/302/311. These verify exact
roundtrip bytes, network-interface query, real multichannel oplock exchanges,
durable-v1 reconnect/position/lock retention and durable-v2 reconnect. Both hosts
stop normally without forced termination. Tool and fixture inputs are read-only;
all new commands, results and temporary shares are in the new external allocation.

These are the same bounded selections used previously, not all Samba suites or
new harness registrations. The previous campaign's three older leased-v2
filename-status expectations were not part of this selection and are not claimed
fixed; current maintained tests retain the primary-spec negative status and
failed-then-valid recovery checks. No client authentication or verification was
disabled to obtain a pass.

## Limits retained by the new stream contract

Named-stream data and promoted logical unnamed streams are process-memory state.
Promotion does not overwrite the previous native unnamed extent: old native
handles remain pinned to it while new SMB default opens see the moved stream.
This requires the existing exclusive-server-access deployment contract and is
not host ADS persistence or coherence with external filesystem access.

Native unnamed-source to named-stream rename remains NOT_SUPPORTED. Third-party
backends must implement the namespace contract to provide the same atomic SMB
descendant check. Native Windows JIT/AOT execution remains outstanding; Linux
execution or cross-compilation cannot certify it.
