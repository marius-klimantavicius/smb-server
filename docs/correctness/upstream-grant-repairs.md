# Read-only grants and inheritance-control repair

This allocation repairs the two independently applicable grant/control defects
found while investigating the new SambaMore rows. The read-only file row is
repaired. The inheritance-control workflow still fails its source-specific ACE
marker assertion; it is retained as an ordinary failure. No SambaMore test or
owner document was edited, and no marker was removed to make that workflow pass.

The owned delta is four production files, `UpstreamGrantRepairTests.cs`, its one
registration line, and this report. The original staged/unstaged work is retained;
there was no formatting, restore, staging, commit, added dependency or license
gate. Registration used the campaign's external `registration.lock`. Evidence is
in the campaign's new `readonly-inheritance-repair/` allocation. Ordinary builds
and tests need neither that location nor network access.

## Grant correction and independent authority

[MS-FSA existing-file access, 2.1.5.1.2.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/82b364ce-6d7b-422f-8d88-4db32eea809a)
distinguishes an explicit data-write request on a read-only data file from a
MAXIMUM_ALLOWED request: explicit unavailable bits fail; maximal access is
filtered. The final supported grant must also satisfy the additional explicit
bits accompanying MAXIMUM_ALLOWED. File WRITE_DATA, APPEND_DATA and DELETE_CHILD
are removed by the local read-only-file filter. The directory DOS bit retains
the existing grant behavior; a read-only backend is a separate restriction.

The dispatcher now intersects descriptor access with the share's specific
maximal mask and the backend's supported mask before publishing the handle.
Previously an Everyone full descriptor could enlarge a restricted share grant.
The backend read-only mask excludes data/EA/attribute writes, deletion and
security writes for both files and directories. Explicit unavailable rights are
rejected, including when accompanied by MAXIMUM_ALLOWED. Overwrite/supersede's
additional required access is still checked before mutation. Missing-object
parent authorization, cancellation, identity validation, sharing, cache admission
and backend errors retain their earlier contracts.

Local acquisition chooses its host access intent from the **final** grant.
Previously MAXIMUM_ALLOWED selected ReadWrite from the potential share grant,
so a read-only file failed before returning its permitted read grant. A
read-descriptor-only grant had the same problem. The existing `FileAccess.Read`
choice for a nonmutating OPEN or existing OPEN_IF now receives the final intent;
no host permission check is bypassed. [.NET FileAccess](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileaccess?view=net-10.0)
defines these host stream access modes. OPEN_IF of a missing object on a
read-only backend still fails without creating anything, and existing OPEN_IF
does not replace attributes or truncate data. Attribute clear changes future
grants; an old restricted handle does not gain rights.

`IAuthorizedCreateStore` adds a backward-compatible overload whose existing-object
predicate receives the supported specific mask and returns a nullable final
`FileAccessIntent`. Null denies. LocalFileStore invokes it inside the same
`LocalObjects.Gate` as identity validation, descriptor reads and acquisition.
DOS attribute changes now take that gate before the existing object mutation
gate. Grant selection is re-evaluated after acquisition waits, without carrying
a pre-wait descriptor/attribute snapshot. Existing parent and identity predicates
and the final cancellation check are retained.

The original overload remains callable. Its default adapter for the new overload
retains its previous authorization/acquisition behavior, but cannot provide an
underlying backend restriction mask or reduce an already supplied host intent.
Custom implementations/wrappers must forward/implement the new overload to obtain
these improved local grant semantics. No new read-only grant guarantee is claimed
for legacy wrappers that omit it. No-descriptor GetSecurity NOT_SUPPORTED behavior
and the prior conservative legacy mutation rejection are unchanged. Sharing/cache
reservations still use conservative potential intent; this repair does not redesign
MAXIMUM_ALLOWED sharing admission or broaden grants beyond share plus descriptor.

## Inheritance disposition and small control repair

Inspected the pinned Samba `attr.c` and `acls.c` at
`2816d12d5346c4e6258d8263f68eb653fd44fd5e`, including `torture_smb2_winattr2`,
`test_overwrite_read_only_file`, `test_mxac_not_granted`,
`test_inheritance_flags` and the separate dynamic-inheritance probe. The original
`test_inheritance_flags` table derives the child's INHERITED_ACE marker from the
parent's AUTO_INHERITED plus AUTO_INHERIT_REQ combination. It also initializes
only entries 0 through 14 of its 16-entry table; the local adaptation explicitly
constructs all 16 partitions. These source tables are compatibility evidence,
not automatic proof of a mandatory protocol rule.

[MS-DTYP SECURITY_DESCRIPTOR, 2.4.6](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d)
distinguishes DACL protection, computed-inheritance request and resulting
inherited state. When request and inherited bits are both supplied, the resulting
inherited bit remains and the request bit is consumed. The repair normalizes
these DACL control bits, retains PROTECTED/DEFAULTED, and preserves them through
partial updates. A newly inherited basic DACL retains the parent's normalized
auto-inherited state without inheriting the parent's protection bit.
[MS-FSA security query, 2.1.5.14](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/0a9f223c-b258-4f61-8b59-92f970341400)
requires reporting the stored DACL present/defaulted/protected/auto-inherited bits
for DACL queries. QUERY now does so and excludes them from zero-field queries.
The previous merge/query helpers discarded every DACL control except PRESENT.
That loss was independently reproducible and is corrected without a subtree engine.

The current local basic inheritance profile always records the origin of an
inherited ACE with INHERITED_ACE. That behavior remains unchanged.
[MS-DTYP ACE_HEADER](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586)
describes this origin marker separately from the descriptor controls;
[descriptor creation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/0f0c6ffc-f57d-47f8-a6c8-63889e874e24)
and [marker processing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/180e7c76-12de-4d1b-8dfd-44667140336b)
describe the richer inheritance algorithms. The inspected text does not establish
that this bounded profile must clear an actually inherited ACE's marker solely
because the parent's control combination is zero. Matching Samba's legacy marker
partition would require an explicit inheritance-profile decision. It is not
claimed here as a repaired mandatory defect or a passing exclusion. The source
row still fails at partition zero, expected marker 0, actual 16.

This control normalization is bookkeeping for ordinary SET and new-child basic
inheritance, not automatic propagation to existing children. PROTECTED describes
the object's own DACL; it does not prohibit its inheritable ACEs from reaching
new children. Existing OI/CI/NO_PROPAGATE behavior, INHERIT_ONLY enforcement,
explicit ACE order/markers and explicit unsupported richer-ACE rejection remain.
Creator substitution, object/callback enforcement, SACL privilege/audit semantics,
owner-assignment privileges and dynamic subtree propagation remain outside this
profile. A control bit alone is not evidence that those mechanisms exist.

## Public tests and immutable captures

`UpstreamGrantRepairTests.Cases()` registers 24 ordinary signed public-dispatch
workflows: four DOS-read-only file/directory OPEN/OPEN_IF rows; two read-only
backend rows; descriptor and share grant bounds; and sixteen independently
registered DACL-control partitions. They use literal wire masks/statuses, actual
LocalFileStore, CREATE, FILE_ALL_INFORMATION, security QUERY/SET, READ/WRITE,
attribute clear and CLOSE. There are no backend-only grant/access-check oracles.
The fixtures establish an authenticated signed session before dispatch; they do
not establish external-client authentication or TCP interoperability.

| Capture | Observation |
|---|---|
| `red-build`, `red-independent` | Build succeeds with no warnings/errors. Initial independent 6/24. Two directory rows additionally tried creating a child after native READONLY was set; Linux host mutation was denied. |
| `red2-build`, `red2-independent` | Child is seeded before the DOS bit, keeping the requested grant/open regression free of an extra directory mutation requirement. Production unchanged: 8/24, sixteen retained failures. |
| `red-source-security` | Full current source security selection 86/88; read-only file and inheritance marker fail exactly as reported. |
| `candidate-build`, `candidate-independent` | First grant/control repair: 24/24. |
| `candidate2-build`, `candidate2-independent` | Final production additionally coordinates DOS attribute changes. Tests use a valid group-only partial update and check that attribute clear cannot enlarge an existing handle. Clean build, 24/24. |
| `improved-red-build`, `improved-red-independent` | Retrospective complete `red2-source` with the final independent test file: clean build, 8/24. Same sixteen failures, without weakening final oracles. Authoritative compiled-tree snapshot is `improved-red-compiled-source`. |
| `candidate2-regression-0` | Current source security 87/88. Both read-only rows and all sixteen ordinary ACE-flag inheritance rows pass. The control-table marker row remains failing. |
| `candidate2-regression-1..9` | Descriptor 25/25, findings 2/2, CREATE authorization 34/34, Go 83/83, Microsoft 297/297, P1 37/37, P2 64/64, P5 174/174, P6 88/88. |
| `candidate2-p7`, `candidate2-cache-repair` | P7 227/227; cache/auth repair 27/27. |
| `candidate2-regression-11..12`, `14..16` | P8 125/125, prior repair 7/7, ordinary CREATE 29/29, protocol 27/27, state 30/30. |

Two command-selection mistakes are preserved: `candidate2-regression-10` used
`p7.` and `13` used `upstream.cacherepair.`; each returned exit 2 with no selected
tests. The correctly named later captures select the registered P7 and cache
cases, with no changes to test assertions or production. The first directory
fixture failure and all RED logs remain. No skipped/expected-failure mechanism,
test exclusion or failure-to-success retry was introduced.

The source owner expanded ordinary inheritance flags between the earlier
CREATE handoff and this allocation: eight case names were added, none removed.
`security-selection-drift.json` compares the earlier 78/80 with current 87/88;
the original 80-name selection is now 79/80. The two exact source failure methods
were reread after repair and are unchanged. No full source-security pass is claimed.

Every run retains expanded command arguments, before/after SHA-256 maps and git
diffs, runtime identity and loaded production assembly paths/MVIDs/SHA-256s.
`candidate2-source` matches the build's complete source map, with no source drift
during the build or selected runs. `handoff-manifest.json` identifies source
archives, compiled outputs and owned changes. The retrospective wrapper's ordinary
maps describe the shared checkout; its separate compiled-tree snapshot describes
the older production actually built. Active owner test changes between other
captures are preserved and distinguished from production changes.

## Remaining limits and parent gate

Native Windows execution is absent. Uncoordinated host mutation, multiple servers,
persistent object generations and legacy-wrapper limitations remain as documented
in the earlier descriptor/CREATE handoffs. Linux native READONLY directory host
permissions can also prevent actual child mutation, independently of the DOS
access-mask distinction; the initial fixture observed this and this allocation
does not claim a directory mutation repair. No entire-suite, final Native AOT or
settled-source TCP acceptance is claimed. The parent owns those gates after the
SambaMore test/docs owner and this implementation handoff both settle.

Choose a fresh external build path to reproduce the maintained focused cases:

```sh
dotnet build tests/Smb.Tests/Smb.Tests.csproj -c Release --artifacts-path "$build"
dotnet "$build/bin/Smb.Tests/release/Smb.Tests.dll" --filter upstream.grantwire.
dotnet "$build/bin/Smb.Tests/release/Smb.Tests.dll" --filter upstream.samba.more.security.
```

The second command selection currently has the one retained marker-policy failure;
its nonzero exit is real evidence, not an expected-failure conversion.
