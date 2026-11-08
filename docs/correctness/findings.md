# Finding disposition

This durable summary retains the original static review's F01–F16 and A01–A05
contracts. The unmodified original review and detailed phase evidence are held
externally. Historical repairs below have Linux functional evidence, subject to
the [unapproved test-first qualifications](acceptance.md). Current source passes
fresh Linux JIT/AOT delivery; the platform requirement still needs native Windows
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

The repair plan references Microsoft MS-SMB2 revision 88.0 (2026-09-28) and
MS-FSCC revision 60.0 (2025-11-21), as recorded during historical work. Scope and
future test-first requirements remain in the [active plan](../correctness-repair-plan.txt).
