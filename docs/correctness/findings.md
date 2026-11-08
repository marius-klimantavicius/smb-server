# Finding disposition

This durable summary retains the original static review's F01–F16 and A01–A05
contracts. The unmodified original review and detailed phase evidence are held
externally. Historical repairs below have Linux functional evidence, subject to
the [unapproved test-first qualifications](acceptance.md). The expanded source
passes 2,917/3,144 in each Linux mode, retaining the same 227 failures; the
platform requirement still needs native Windows
execution. See [platform validation](platform-validation.md).

| ID | Remedy and remaining qualification |
|---|---|
| F01 | Shared delete-pending and nonrecursive fallible final deletion; Windows lifecycle validation required. |
| F02 | Collision-safe session IDs and shared-session lifecycle; multichannel opt-in, SMB300/302 scope. |
| F03 | Common object/stream lease/oplock coordinator before mutation; historical P6 order qualification. |
| F04 | Result-based compound inheritance and explicit async continuation; separate final frames remain a documented SHOULD deviation. |
| F05 | Cancel/grant winner with cancellation-registration disposal outside callback locks. |
| F06 | Pending publication, sender commitment and one final/abandonment; physical ownership survives response cancellation. |
| F07 | Granted/consumed credit ranges and operation-size charges. |
| F08 | Tree teardown closes owned opens, pending work and watchers before removal. |
| F09 | Handle-based stable object/stream identity and rename coordination; Windows implementation and native execution required. |
| F10 | Complete WRITE/channel validation and backend durability intentions; unbuffered remains advisory. |
| F11 | READ MinimumCount, class-specific short buffers and pipe remainders; historical P5 order qualification. |
| F12 | Allocation acts through an optional backend API or returns an honest unsupported/error result; local allocation unsupported. |
| F13 | Bounded resumable enumeration, restart/reopen/pattern/EOF/cleanup; historical P5 order qualification. |
| F14 | Per-open notifications, initial filter/subtree, FIFO buffering, overflow/error rescan; OS events best effort. |
| F15 | Mandatory channel sequence, LOCK replay and same-open SMB300/302 durable reconnect; historical order qualifications, persistent/CA deferred. |
| F16 | Transactional CREATE acquisition/publication/rollback with one cleanup owner; historical P2/P6/P7c order qualifications. |
| A01 | Fixed fields, offsets, lengths and compound alignment for the assigned structural surface; no all-parser certification. |
| A02 | Opt-in COPYCHUNK uses common lock/lifetime/cache coordination; historical COPY cancellation order qualification. |
| A03 | CANCEL/control progresses during blocked ordinary I/O; ignored backend cancellation can delay physical shutdown and still mutate. |
| A04 | Explicit metadata/stream/EA persistence and host behavior; no full NTFS promise. |
| A05 | Sealed feature/backend gates align advertisement, accepted contexts and grants; native platform validation remains required. |

The [adapted upstream campaign](upstream-tests.md) added 86 scenarios from pinned
Samba, SMBLibrary and Microsoft FileServer conformance tests. The original
production baseline passed 66 and failed 20; focused repairs now pass all 86 and
the complete 940-test harness under published Linux JIT and Native AOT. These additions refine the original
finding families rather than treating their historical closure as exhaustive:

| ID | Confirmed defect and disposition |
|---|---|
| U01 / A01, F16 | Repaired CREATE semantic validation before destructive backend admission: disposition/options/attributes/type combinations. |
| U02 / A01, F09 | Repaired rename minimum record padding and nonzero root rejection before mutation. |
| U03 / F05 | Repaired same-owner exclusive acquisition conflicts and conflicts between elements of one lock request; rollback preserves earlier grants. |
| U04 / F05 | Repaired invalid unlock flags and ordered multi-unlock partial effects, including waiter wakeup after successful prefix. |
| U05 / F05 | Repaired WRITE admission under the caller's own shared byte-range lock. |
| U06 / F13 | Repaired SMB `*.*` and DOS wildcard matching across local cursors/listing APIs; dot names obey the same expression. |

Each group has preserved valid RED and GREEN evidence. Older rename requests
were padded to the required minimum, and three replay fixtures changed illegal
exclusive stacking to legal shared stacking after their failures were captured;
behavioral assertions were retained. No registered case was skipped. Source
selection differences and the related-compound SHOULD policy are explicitly
documented. Published delivery results and remaining Windows execution limits
are recorded in [platform validation](platform-validation.md).

The repair plan references Microsoft MS-SMB2 revision 88.0 (2026-09-28) and
MS-FSCC revision 60.0 (2025-11-21), as recorded during historical work. Scope and
future test-first requirements remain in the [active plan](../correctness-repair-plan.txt).

## Broader protocol/auth campaign

The second campaign adds 2,068 source-derived registrations and 136 focused repair
regressions to the previous 940. Both final Linux modes pass 2,917/3,144, with the
same 227 failing names; all other 24 platform stages pass. This supersedes the
first campaign's all-green count as the current harness result.

The [campaign index](upstream-tests.md) links immutable source/function mappings,
observed RED/GREEN, fixture/oracle corrections and each repair handoff. Confirmed
repairs include auth negotiation/SPNEGO/session keys and failed-reauth signing;
encryption/compression boundaries; CREATE validation, sharing and pre-mutation
authorization; descriptor identity/access and partial updates; local metadata and
stream generations; lock/IOCTL/info validation; replay delivery; and cache-wait
identity revalidation/level-II invalidation. Optional rejection policies and
source-specific choices are not represented as implemented features.

The remaining failures are **211 Samba continuation, 15 inventory compatibility,
and one legacy OS2 filename policy**. The continuation includes two bounded cache
sequences and eight notify event/cleanup reproducers whose required outcomes are
unresolved, as well as conservative cache/durable choices, host rename policy,
unsupported stream rename and other recorded source conventions. Exact names and
first failing phases remain in [the continuation](upstream-samba-continuation.md)
and the final capture. Later assertions blocked by an earlier failure are not
claimed executed. Native Windows and broader security/persistence limitations
remain explicit. Completion of test-port work does not close these findings or
the historical M1/M2 acceptance qualifications.
