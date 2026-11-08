# SET_SECURITY descriptor repair handoff

This allocation corrects the existing local descriptor implementation. It does
not replace authentication, introduce privileges/Kerberos, or claim general
Windows security conformance. Previous auth, cache, replay, namespace and file
repairs are retained. No `UpstreamSambaMore*.cs` or `UpstreamInventory*.cs` file
was edited. The independent public cases are in
`tests/Smb.Tests/UpstreamDescriptorRepairTests.cs`; registration was added under
the campaign's external `registration.lock`. The missing `RawSmb.Logoff` packet
builder was added to compile an active owner's new test without editing it.
No staging, commit, restore, broad formatting, runtime dependency, maintained
transient-path dependency or foreign server implementation was introduced.

All builds, original logs, primary-source downloads, source archives, SHA-256
maps and runtime identities are in the campaign's new `descriptor-repair/`
subdirectory. Existing evidence was not rewritten. This report uses relative
capture names; ordinary builds/tests need no campaign directory or network.

## Repairs and independent authority

| Defect | Observed public RED | Correction |
|---|---|---|
| Path-based storage | Fresh READ succeeds through a renamed path/hardlink after SET deny; a newly created object at a deleted name inherits the old deny. | GET/SET and new-child inheritance use the acquired **base** FileIdentity, with empty StreamId. Named streams and aliases share that descriptor. Directory rename does not invalidate closed descendants' descriptors. |
| Retirement | Alias unlink/replacement must preserve remaining objects' policy. | Native link counts distinguish unlinking one name from retiring the object. Final unlink/replacement removes descriptor and existing DOS/creation/stream metadata; surviving aliases retain it. Every genuinely new server-created object clears recycled identity/path entries before inheritance. |
| Injected legacy store | A preseeded path descriptor is enforced initially but lost after rename. A replaced path's old descriptor can attach to the replacement. | The supplied store remains authoritative. Legacy entries on existing objects migrate to identity keys on access; a rename destination is migrated before replacement, and the obsolete destination path key is removed after success. |
| Concurrent partial SET | A paused owner-only SET reads the old descriptor; another FileId applies a deny; the first SET then restores the old allowing DACL. | A keyed async gate covers the descriptor read/merge/write, scoped to store plus base identity across FileIds and streams. Local descriptor operations also share `LocalObjects.Gate` with rename, creation and deletion. |
| INHERIT_ONLY | Both a direct allow and a direct deny incorrectly affect file/directory admission. | Direct access evaluation skips these ACEs. Existing OI/CI/NO_PROPAGATE inheritance logic is retained; the source OI-only child-directory case now passes because its inherited template is ineffective on that directory. |
| Generic ACE masks | Query returns generic bits and fresh specific-right opens fail incorrectly. | Local SET maps basic ACE masks when attaching the descriptor. File/directory generic mappings use the same bit positions (READ_DATA/LIST_DIRECTORY, WRITE_DATA/ADD_FILE, EXECUTE/TRAVERSE). Ordered allow/deny evaluation is preserved. |
| Owner / OWNER RIGHTS | Empty DACL denies implicit owner control rights; S-1-3-4 does not match the owner or suppress implicit grants. | The owner receives READ_CONTROL/WRITE_DAC unless an effective OWNER RIGHTS ACE controls them. That SID matches the actual owner, not an unrelated caller. No implicit owner data access is added. |
| MAXIMUM_ALLOWED plus explicit bits | MAXIMUM_ALLOWED plus denied WRITE_DATA succeeds. | CREATE preserves the additional explicit mask; evaluation requires those bits as well as a nonempty maximal grant. |
| NULL DACL query | Successful NULL DACL SET/query loses DACL_PRESENT. | Merge and field filtering preserve that bit, including a zero DACL offset. A zero-field query still returns the bare descriptor. |
| Unsupported ACE enforcement | Object/callback deny ACEs followed by Everyone allow are accepted and ignored. Inheritable CREATOR_OWNER is accepted without creator substitution. | Local SET rejects unsupported DACL ACE types and inheritable CREATOR_OWNER/CREATOR_GROUP with NOT_SUPPORTED before changing policy. Basic allow/deny ACEs, their order and ordinary inheritance remain supported. Direct unsubstituted CREATOR_OWNER remains a placeholder, not the current owner SID. |

The object association follows [MS-FSA SET_SECURITY
2.1.5.17](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/2e97fa70-e1f5-410b-ba87-f1ffda39a8ed):
security belongs to `Open.File`, shared by its streams and links. Existing-file
admission follows [MS-FSA
2.1.5.1.2.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/82b364ce-6d7b-422f-8d88-4db32eea809a).
The new tests check fresh CREATE decisions and QUERY_INFO, while existing granted
handles remain usable. There is no retroactive grant revocation.

[MS-DTYP 2.5.3.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/4f1bbcbb-814a-4c70-a11e-2a5b8779a6f9)
provides ordered evaluation, the INHERIT_ONLY exclusion, implied owner control
rights and maximal-access processing. [The well-known SID
rules](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab)
distinguish OWNER RIGHTS from creator placeholders. This is the existing simple
SID-token model; owner assignment privileges and full token semantics are not
implemented by these repairs.

[MS-DTYP ACCESS_MASK](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b)
warns that generic bits already attached to an object are not mapped by its
access-check algorithm. Mapping therefore occurs at local descriptor attachment.
Microsoft's [file and directory mapping
table](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights)
and [file access constants](https://learn.microsoft.com/en-us/windows/win32/adsi/security-descriptors-on-files-and-registry-keys)
independently establish the specific masks. NOT_SUPPORTED for richer DACL forms
is an explicit bounded-profile rejection, not a claim that MS-DTYP forbids those
forms. Atomic CREATE SecD rejection from the prior allocation is unchanged.

[MS-FSA security query
2.1.5.14](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/0a9f223c-b258-4f61-8b59-92f970341400)
supports field isolation and READ_CONTROL requirements. The source's old blanket
valid-DACL rejection oracle was invalid: basic enforcement already existed.
Those historical logs remain. The corrected source's granted-handle, zero-field,
owner/group isolation and fresh-admission assertions were inspected independently
and pass. No test expectation was weakened, skipped or converted to a pass.

## Store compatibility and lifetime limits

`ISecurityDescriptorStore` signatures and the injected instance are preserved.
Local writes now use `"local-security:" + (identity with empty StreamId).Key`.
Implementations must accept opaque keys and implement TryGet/Set/Remove. They are
called synchronously under the local object gate. A pathname-only external write
after migration is not an update of the bound object's policy. The independent
injected-store test checks the original preseeded path policy, subsequent writes,
rename enforcement and new-object reuse through public operations.

Legacy migration is **lazy**, not a complete persistent-store conversion. The
interface cannot enumerate legacy entries or recover identities for old names
that were moved/deleted before their descriptors were bound. Deployments with
persistent legacy dictionaries must bind/migrate existing policies before
namespace mutation and coordinate external policy edits. A custom store that
requires every key to be an absolute pathname needs an adapter/update. It is not
silently replaced by an in-memory store, and blanket backward key compatibility
is not claimed.

Default descriptors are process/store memory, independently of the temporary
`LocalObjects` live-handle records. Closing the final ordinary handle does not
retire a still-linked descriptor. Successful final server deletion does. A new
server CREATE also clears any recycled native-ID state. No pin is retained per
stored descriptor and there is no on-disk NTFS ACL implementation.

The sequential host-rename probe establishes that the same acquired native
identity retains policy while a replacement path gets the default policy. It
**does not** establish safety for concurrent host mutation, external unlink plus
native-ID reuse, process restart, multiple independent stores/servers, or cache
coherence with direct host access. Linux device/inode IDs and Windows file IDs
alone do not establish persistent object generations. These remain deployment
and persistence limits; `exclusiveServerAccess` still requires caller-enforced
coordination. Native Windows link-count execution remains unavailable.

## Immutable capture results

The public fixture establishes a signed authenticated session before dispatching
SMB commands. Assertions use SET_INFO, QUERY_INFO, CREATE, READ/WRITE and CLOSE;
no descriptor manager or access-check API is a test oracle. Host hardlinks and
sequential host rename establish namespace prerequisites. Backend barriers only
force wire-request interleavings. This is direct public-dispatch coverage, not
external-client or TCP-authentication interoperability.

| Capture | Result / boundary |
|---|---|
| `original-build`, `original-security` | Clean build, source security 58/76. Eighteen original failures retained. |
| `independent-red-fixed-build`, `independent-original-red` | Original production, independent probes 0/23. The first build attempt lacked two required DomainName fixture fields; that compile failure is retained separately. |
| `candidate-buildable-build`, `candidate-independent`, `candidate-more-security` | First repaired production, 23/23 independent and 76/76 source security. |
| `candidate-regression-0..6` | P1 37/37, P2 64/64, P5 174/174, P6 88/88, Go 83/83, Microsoft 297/297, prior repairs 7/7. |
| `partial-original-red` | Controlled partial SET probe 0/1 before the merge gate. |
| `findings-original-red` | Two separate CREATE authorization findings, 0/2; details below. |
| `frozen-final-build`, `frozen-final-run-0..10` | Current production after merge repair with the complete pinned `partial-red-source` tests: 24/24 independent, 76/76 source security, the same regression totals, cache/auth repairs 27/27. The two findings remain 0/2. |
| `legacy-red-build`, `legacy-original-red` | Same production plus independent injected replacement probe, 0/1 before its correction. |
| `handoff-build`, `handoff-run-0..10` | Final production: independent 25/25, source security 76/76, P1 37/37, P2 64/64, P5 174/174, P6 88/88, Go 83/83, Microsoft 297/297, prior repair 7/7, cache/auth repair 27/27. Separate CREATE findings remain 0/2. |
| `ace-original-red`, `ace-handoff-green`, `ace-handoff-more-security` | Corrected richer-ACE envelope against original production 0/2; final production independent 25/25 and source security 76/76. Production bytes match the preceding handoff exactly. |

Final oracle review corrected the two richer-ACE envelopes from ACL revision 2
to revision 4 without changing the NOT_SUPPORTED assertion. The earlier revision
2 rows are retained as malformed-profile observations, not proof of valid file
ACL enforcement defects. [MS-DTYP ACL revision
rules](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/20233ed8-a6c6-4097-aafa-dd545ed24428)
restrict object ACEs to the richer directory-service profile. Neither those
object forms nor callback evaluation is supported by this file store. These are
explicit capability-rejection policies, not an assertion that files must
implement directory-service ACL semantics. The corrected probes use complete
raw envelopes and observe rejection before mutation; original production
acknowledges them successfully. Basic descriptor enforcement and the valid
inheritable creator-placeholder rejection have separate original RED evidence.

`candidate-build` and `candidate-build-settled` retain an active owner's missing
RawSmb.Logoff compile failure. `final-build` retains the later missing Share
namespace in `UpstreamSambaMoreAdditionalTests.cs:208`. No owner file was edited.
To validate without excluding tests or altering assertions, the later builds use
an external full source copy: every test from the complete successfully compiled
`partial-red-source.tar.gz`, the latest independent test file, and current
production. `frozen-final-source.sha256.json`, `legacy-red-source.sha256.json`
and `handoff-source.sha256.json` identify those exact sources. The final fixture
correction uses `ace-original-source` and `ace-handoff-source`, each with its own
SHA-256 map and tarball. Capture wrappers'
ordinary before/after maps still describe the shared checkout, **not** the
external compiled tree; the separate source maps and tarballs are authoritative
for those builds. The handoff manifest verifies production equality and notes
later shared test drift. No entire-suite acceptance is inferred from this copy.

## Remaining concrete security blockers

These are registered ordinary failing public tests, not expected-failure passes:

1. `upstream.descriptorfinding.denied-overwrite-preserves-bytes`: SET an Everyone
   WRITE_DATA deny, then send FILE_OVERWRITE with WRITE_DATA. CREATE returns
   ACCESS_DENIED, but READ through the old granted handle returns END_OF_FILE:
   backend truncation occurred before the descriptor access check. Existing-file
   authorization must precede destructive acquisition. This requires assessment
   of CREATE's admission/acquisition contract beyond identity storage and ACE
   evaluation; this allocation has not replaced that contract.
2. `upstream.descriptorfinding.parent-deny-add-file`: SET a directory DACL denying
   FILE_ADD_FILE (bit 2) without inheritable ACEs, then CREATE a missing child.
   CREATE succeeds. [MS-FSA new-file
   creation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/498a5eeb-afc9-445f-99ed-a7e4b73c648b)
   requires parent authorization. Child-descriptor inheritance alone does not
   implement that check. Parent traversal/add-subdirectory and creator default
   token policy need separate review, not a blanket ACL redesign in this patch.

Richer creator substitution, automatic propagation to existing children,
protected/auto-inherit control-flag preservation, SACL privilege/audit semantics,
owner-assignment privilege rules and claims/object ACE support are not claimed.
The explicit object/callback and inheritable creator rejection probes establish
only the stated local capability boundary. Existing basic OI/CI/NO_PROPAGATE and
direct CREATOR_OWNER behavior pass the current source cases. No full inheritance
or privilege implementation is inferred.

The parent still owns the final settled-source Linux JIT, Native AOT and actual
local TCP gates after both test owners finish. Native Windows is unexecuted.

## Reproduction

Choose fresh external output/artifact directories. The maintained test suite is
offline; none of the evidence paths is required:

```sh
dotnet build tests/Smb.Tests/Smb.Tests.csproj -c Release --artifacts-path "$build"
dotnet "$build/bin/Smb.Tests/release/Smb.Tests.dll" --filter upstream.descriptorwire.
dotnet "$build/bin/Smb.Tests/release/Smb.Tests.dll" --filter upstream.samba.more.security.
dotnet "$build/bin/Smb.Tests/release/Smb.Tests.dll" --filter upstream.descriptorfinding.
```

Each external capture retains the exact expanded argument array, full original
output, source/archive hashes and loaded assembly paths/MVIDs/SHA-256s. The
finding selection is expected to return a failing process exit status until its
production defects are repaired; it is not an expected-failure test mechanism.
