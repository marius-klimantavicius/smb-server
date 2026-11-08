# CREATE authorization repair handoff

This allocation repairs ordinary CREATE admission in the existing local descriptor
profile. It preserves the completed descriptor identity/partial-SET/ACE repairs,
authentication, cache coordination and file semantics. No SambaMore owner file,
foreign server implementation, runtime dependency, license gate, staged content
or commit was introduced. The additional cases are ordinary public signed wire
requests in `UpstreamCreateAuthorizationTests.cs`, registered under the campaign
registration lock. They do not call an access checker as their oracle.

All new transient evidence is under the campaign's `create-authorization-repair/`
allocation. Capture names below are relative to that allocation. Maintained
builds and tests require neither the campaign files nor network access. The
external `handoff-manifest.json` records exact arguments, results, source/archive
SHA-256s, loaded assembly paths/MVIDs/hashes, and the changes owned here.

## Repairs and authority

1. Existing-file and existing-base-stream authorization now occurs before
   truncation, stream reset or attribute replacement. The existing desired mask
   and additional explicit bits accompanying MAXIMUM_ALLOWED are checked. An
   overwrite also checks WRITE_DATA; supersede checks DELETE. These implicit
   admission requirements do not enlarge a client's requested handle grant.
   Old granted handles retain their rights.
2. A missing base object requires the immediate parent's ADD_FILE, or
   ADD_SUBDIRECTORY for a directory, before any object is created. Inheritance
   is separate. Creating a named stream on an existing base checks that base;
   creating its missing base checks the parent. OPEN_IF distinguishes its
   existing-object and new-object branches. Missing-parent and read-only backend
   rejection still occur without creating an orphan.
3. New base objects receive the initial requested grant. Their inherited DACL
   governs fresh opens; it cannot retrospectively veto the successful creation
   after the backend has already published the child. This preserves inherited
   denial for subsequent admission without orphaning an initially denied handle.
4. The guarded acquisition validates the current object/stream identity before
   authorization or mutation. A changed identity produces internal STATUS_RETRY;
   the dispatcher drops the old share/cache/lease reservations and repeats
   admission. The replacement's sharing and cache domain are established before
   destructive acquisition. No client retry or expected-failure conversion is
   used by the regression.

[MS-FSA new-file creation 2.1.5.1.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/498a5eeb-afc9-445f-99ed-a7e4b73c648b)
requires the parent add right before constructing the file/link and grants the
initial requested access before initializing its descriptor. The profile has
no restore privilege or earlier parent grant to bypass this check.
[MS-FSA existing-file access 2.1.5.1.2.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/82b364ce-6d7b-422f-8d88-4db32eea809a)
requires checking the object's descriptor and rejecting ungranted explicit bits.
[Microsoft's CREATE access guidance](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/checking-for-other-special-cases--on-irp-mj-create)
and [NtCreateFile disposition semantics](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile)
establish the additional overwrite/supersede access requirements. Independent
expected statuses, masks and preservation assertions are literal wire values.

## Acquisition contract and compatibility

`IAuthorizedCreateStore` is an optional backend capability. It takes synchronous
existing-object/parent authorization predicates and an identity validator.
The backend must invoke them against one coherent namespace/descriptor state,
check cancellation immediately before mutation and revalidate after waits.
An identity mismatch returns RETRY with no mutation. LocalFileStore implements
this under the existing `LocalObjects.Gate`, which already covers SET_SECURITY,
rename, retirement and local acquisition. The actual descriptor comes from the
injected/default descriptor store through the existing stable base-identity
lookup; host ACLs are not substituted for it.

The dispatcher keeps the existing admission/lifecycle structure. Authorization
runs after cache waits; failures leave no new published open and release the
existing provisional reservations. No byte restoration, truncate-then-rollback
or waived descriptor/backend check is involved. A previously requested cache
break may already have completed before denial; this change does not restore
revoked caching promises.

A legacy descriptor-aware backend retains nonmutating OPEN and an existing
ordinary OPEN_IF, including its acquired handle and descriptor semantics. For
mutation, nondestructive probes report ACCESS_DENIED for a failed object/parent
check; an allowed check returns NOT_SUPPORTED until that backend implements the
atomic capability. Separate asynchronous GetSecurity/Create calls cannot safely
provide this guarantee. All probe handles are disposed on rejection. This is
an explicit compatibility restriction for descriptor-aware custom backends,
not a claim that their authorized mutations now work. The public legacy case
checks both denials, the capability rejection, ordinary opens and byte/orphan
preservation.

GetSecurity NOT_SUPPORTED keeps the existing no-descriptor backend behavior;
other descriptor errors propagate. A custom backend with selective or changing
descriptor support must implement the guarded contract, rather than using
NOT_SUPPORTED as a transient policy-read failure. Wrappers must forward the
capability to provide their underlying store's guarded descriptor semantics.
No new descriptor enforcement is claimed for wrappers which omit that support.
The in-memory test fixture explicitly has no descriptors and keeps one controlled
acquisition; the descriptor barrier and replay-preparation fixtures forward the
new capability. Their assertions and fault/barrier behavior were retained.

Server-coordinated namespace changes are covered. Concurrent uncoordinated host
mutation, multiple independent servers, persistent object generations and native
Windows execution remain the existing deployment/platform limits. This patch
adds no all-ancestor traversal, privilege/token redesign, host ACL mapping,
dynamic inheritance propagation or richer ACE support.

## Immutable RED and GREEN evidence

| Capture | Result and qualification |
|---|---|
| `current-red-build` | Maintained build failed at the active owner's `UpstreamSambaMoreCacheTests.cs:175`, CS1503, ulong argument where uint was required. No owner file was edited. |
| `frozen-red-build`, `current-findings-red` | Current unchanged production plus the prior complete pinned test tree: build succeeds, the two registered descriptor findings fail 0/2. |
| `independent-red-build`, `independent-red` | Same unchanged production, complete pinned tests plus the first 23 CREATE cases: 1/23, with 22 real failures. `independent-red-source` is the authoritative compiled source map/archive. |
| `candidate-frozen-build`, `candidate-independent`, `candidate-findings`, `candidate-security` | First repair: 23/23 CREATE, 2/2 findings and prior source security 76/76. |
| `candidate2-build` | Retained fixture compile error: OrdinaryRequest has no MessageId property. Corrected to use the keyed request entry. |
| `candidate3-independent` | 29/30; cancellation fixture omitted the caching execution profile and consequently had no ordinary request entry. Fixed the fixture, preserving the failed log. |
| `candidate3-regression-4` | P7 225/227. The replay fixture's old CreateAsync barrier was consumed by nondestructive legacy probes. Forwarding guarded acquisition preserves its one-acquisition preparation barrier and original assertions. |
| `maintained-final-attempt-build`, `maintained-create` | The owner's compile correction permits the complete maintained source to build with zero warnings/errors and no source drift during build; CREATE 33/33. |
| `identity-prior-build`, `identity-prior-red` | Retrospective controlled replacement probe on the immediately preceding production: 0/1, old granted READ observes EOF after a rejected overwrite. The test adapter uses that production's earlier capability signature; scheduling and assertions are unchanged. |
| `identity-build`, `identity-create` | Complete maintained source: zero warnings/errors, no build source drift; all 34 CREATE cases pass, including identity replacement, policy changes during waits and public CANCEL before acquisition. `identity-source` exactly matches the build's source map. |
| `identity-regression-0..13` | P1 37/37, P2 64/64, P5 174/174, P6 88/88, P7 227/227, P8 125/125, Go 83/83, Microsoft 297/297, descriptor 25/25, repair 7/7, cache/auth repair 27/27, original findings 2/2 and ordinary CREATE 29/29. Current source security is 78/80; see below. |

The original two descriptor-repair RED logs and final manifest remain immutable
in the earlier allocation. No test was skipped, weakened, retried into a pass or
converted to expected failure. Later captures are new names following actual
implementation or fixture corrections. The abandoned initial `original-source`
tar capture accidentally included build artifacts and was interrupted; it is
retained as incomplete evidence and is not an authoritative source snapshot.

Early builds used a complete external pinned test tree while the active owner's
maintained sources did not compile; no test exclusion was added. The original
`current-red-source` working copy was extended after the first build; the later
`independent-red-source` archive records that extended compiled tree. Ordinary
capture wrappers hash the shared checkout even for external builds, so the
separate compiled-tree maps/archives are authoritative for those runs.
`maintained-final-source` was captured after its build and three active owner
test files had already changed; its differences are recorded in the manifest.
The final `identity-source` has no such mismatch and contains the full maintained
compilable test tree.

The fixtures establish signed authenticated sessions before public dispatch.
These are public SMB packet checks, not external-client authentication or TCP
interoperability. The selected older regression suites also include their
existing TCP cases. Host hardlinks establish an alias prerequisite; controlled
backend barriers only force wire-request scheduling. No manager-only result is
used to establish repaired authorization behavior.

## Remaining scope and parent gate

The active owner expanded the source security selection from 76 to 80 cases.
All 76 names from the earlier passing source selection still pass in the final
80-case capture. Two newly added ordinary rows remain failing:

- `upstream.samba.more.security.inheritance-control-table`: inherited ACE marker
  is 16 where the source control-partition oracle expects 0. Control-flag
  normalization and auto-inheritance were already outside the descriptor repair.
  The exact source expectation still needs independent applicability review.
- `upstream.samba.more.security.readonly-maximum.False`: a MAXIMUM_ALLOWED open
  of a DOS-read-only file returns ACCESS_DENIED instead of returning a grant
  without WRITE_DATA/APPEND_DATA. The corresponding directory row passes. This
  requires additional backend-access/grant filtering beyond these two repairs.

These are real retained failures, not passing capability exclusions. No active
SambaMore source file was edited to remove them. They prevent claiming the
expanded source security selection is entirely green. The parent owns final
settled-source full Linux JIT/Native AOT/TCP integration and the unavailable native
Windows gate after the test/docs owner finishes. This allocation's final result
is the focused maintained-source JIT evidence above.

## Reproduction

Use fresh external build/output paths; no campaign location is required:

```sh
dotnet build tests/Smb.Tests/Smb.Tests.csproj -c Release --artifacts-path "$build"
dotnet "$build/bin/Smb.Tests/release/Smb.Tests.dll" --filter upstream.createauth.
dotnet "$build/bin/Smb.Tests/release/Smb.Tests.dll" --filter upstream.descriptorfinding.
dotnet "$build/bin/Smb.Tests/release/Smb.Tests.dll" --filter upstream.samba.more.security.
```
