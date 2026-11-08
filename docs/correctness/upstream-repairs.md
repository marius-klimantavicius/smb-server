# Serial upstream correctness repairs

This allocation is the sole production owner after the authentication handoff.
Existing user formatting and staged/unstaged changes are retained. New evidence is
external under this campaign's `file-protocol-repair/`; no external artifact is a
source, build or test dependency. Every capture uses `scripts/platform_capture.py
--out <new-directory> -- <command>` and records command, source hashes, staged and
unstaged diffs, host, output, result and drift. Builds use unique external
`--artifacts-path` directories. Tests from other allocations may change between
builds; per-capture manifests identify them. No native Windows or final AOT gate
is claimed here.

| Finding | Repair and evidence |
|---|---|
| R01 IOCTL / status literal | InputOffset now declares the same buffer base as OutputOffset for empty returned input. BAD_NETWORK_NAME is 0xc00000cc. `red-go` fails both; `admission-go` passes both. |
| R02 CREATE admission | Negative EOF rejected before backend; missing read-only OPEN_IF denied; existing read-only OPEN_IF uses read-only OS access. Directory parent existence/collision order, invalid directory options, OPEN_BY_FILE_ID/RESERVE_OPFILTER and reserved access are checked before mutation. `red-go` and `red-samba` preserve RED, `admission-*` captures improvement. |
| R03 sharing / namespace | EXECUTE requires read sharing, stat-only opens are exempt independently of minimal host access. CREATE reacquires a changed missing-name/stable-identity scope, releasing before changing keys. Only vanished enumeration children are skipped; root/access/I/O errors remain failures. Original Go race logs remain in `go/`; this is not a claim that one passing stress run establishes absence of races. |
| R04 DOS metadata | Local CREATE applies requested attributes with mandatory ARCHIVE for data files; overwrite checks existing HIDDEN/SYSTEM before truncation. Windows uses native attributes; Linux maintains unsupported DOS flags per store by stable identity, with native file READONLY authoritative. Directory READONLY is retained as DOS metadata. Deletion retires metadata. `metadata-go`: 83/83; `metadata-samba`: 1021/1161 (140 RED), versus original 277 RED/1153. Test additions explain different totals. |
| R05 stream / position / locks | Stream metadata uses base attributes; invalid type/directory combinations reject early; eligible stream creation creates base; base retirement removes old stream names. Live stream handles retain their data object when names are detached. FilePositionInformation is open-scoped and appears in FileAllInformation. Zero-length lock overlaps follow strict-interior and {0,0} exception. `streams-samba` captures 1054/1177 with four additional lock shortcut failures exposed. |
| R06 Microsoft admission / client dialect | Fixed SET minima, signed offsets/range overflow, stale FLUSH, notify list access and normalized-name status. Server-wide client-GUID dialect registration is atomic across connections; negotiated connections retain the record until the last closes. SMB202 is exempt. `metadata-ms-red`: 191/250, 59 RED; subsequent evidence below. |

Primary applicability references:

- [MS-SMB2 IOCTL response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/f70eccb6-e1be-4db8-9c47-9ac86ef18dbb): output offset relation is mandatory; input-base choice is SHOULD.
- [MS-SMB2 CREATE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e8fb45c1-a03d-44ca-b7ae-47385cfd7997): directory combinations, collision precedence and unsupported options.
- [MS-FSA new file](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/498a5eeb-afc9-445f-99ed-a7e4b73c648b) and [existing file](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/41f3734a-5bba-4c3b-9d04-7baafc9b7bfe): automatic ARCHIVE, directory TEMPORARY rejection and overwrite HIDDEN/SYSTEM matching.
- [MS-FSA range conflicts](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/124bb289-eeef-4653-b9c6-4fb93dd07a21) and [FSCC position](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/e3ce4a39-327e-495c-99b6-6b61606b6f16): zero-length interval behavior and per-open position.
- [MS-SMB2 final authentication](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5ed93f06-a1d2-4837-8954-fa8b833c2654) and [connection loss](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/eb5bfe99-47fe-4e87-8e87-08a084dcefb6): GlobalClientTable dialect check and optional removal after last same-GUID non-SMB202 connection.

Linux DOS flags and named streams remain process/store memory, not persistent NTFS
metadata. Direct host mutation cannot supply portable DOS flags. Native Windows
behavior remains unexecuted. Original build attempt `red-build` failed because a
new isolated artifacts directory had no restore assets; `red-build-restored`
then built cleanly. This invocation error is not production RED evidence.

The external-scratch volume regression in `streams-regression` is an oracle error:
NativeHost.VolumeTotalBytes used Path.GetPathRoot(directory), selecting `/` instead
of the actual share mount. `findmnt` identifies the scratch mount as ext4 on
/dev/sdd1; `df -B4096` reports 480430792 blocks there versus 480305459 on `/`.
Production reports the share mount correctly. Original failure is retained;
fixture correction is not counted as a production repair.

## Continued repair groups

R07 covers mandatory negotiate validation (duplicate/empty contexts, hash overlap,
no common dialect, repeated negotiate disconnect), cipher-zero response context,
VALIDATE_NEGOTIATE_INFO disconnects, signed NEGOTIATE and signed initial
SESSION_SETUP rejection. SMB300/302 encryption capability now reflects the
client capability; requiring encryption does not manufacture client support.
Mixed recovery claims are processed in chain order: the first recovery context
selects the v1 conflict policy or v2 NAME_NOT_FOUND validation. Disabled profiles
retain their conservative rejection.
[MS-SMB2 negotiate](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/b39f253e-4963-40df-8dff-2f9040ebbeb1),
[signature validation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/85df1680-2ee7-4d25-a916-a982371ddc75),
[v2 reconnect](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/62ba68d0-8806-4aef-a229-eefb5827160f).
`handshake-ms` is 295/295. Two later Microsoft pathname additions exposed valid
RED in `integrated-current`: overlong component exception mapping and a separator
immediately before an explicit default-data suffix. These are repaired before
the final build.

R08 repairs XPRESS Plain LZ77 extended match lengths. The old encoder and decoder
agreed with each other but incorrectly used a full byte instead of paired
four-bit extensions. The independent Microsoft TCP decoder exposed malformed
outbound streams in `metadata-ms-red` and `negotiate-ms`. Encoding and decoding
now implement the nibble/byte/word/dword hierarchy, with bounds checks; malformed
compression and invalid decompressed protocol identifiers terminate the transport.
[MS-XCA processing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/b66751f2-be7b-4d20-a87c-5147c563ff2d)
and [MS-SMB2 decompression](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/eacbd2d4-4383-4ea3-b9d9-c8ba9f5c9ff4)
independently establish these requirements. `compression-ms` advances to 257/263;
its six remaining failures are other groups, not compression.

R09 repairs EA size reporting and invalid EA names/flags, actual granted access
in FileAllInformation, READ_DATA-or-EXECUTE READ admission, QUERY_INFO and security
query access checks, and COPYCHUNK versus COPYCHUNK_WRITE destination access.
Last-write suppression is per open, and local mutations serialize through a
shared object gate so a suppressed writer restores the immediately preceding
write time without racing another server writer. Linux creation times are retained
by stable identity within the store to avoid host fallback timestamps changing
when a directory changes. Explicit creation-time updates change that value;
retirement removes it. These remain store-memory metadata, not a persistent NTFS
birth-time promise. `repair-tests-ms` shows the suppression and creation-time
failures green. Short-buffer fixtures in P5 now request READ_ATTRIBUTES through
CREATE; the original 18 access failures remain in `stream-identity-regressions`.
`replay-claim-p5` is 174/174; volume verification uses the external scratch mount.

R10 reserves durable-v2 CreateGuid claims before cache admission and keeps them
until physical execution and actual final-response delivery (or abandonment) both
finish. A rejected replay cannot replace the original claim. Pending replay uses
the explicitly selected Samba sane FILE_NOT_AVAILABLE policy. This changes the
old coalesced-wait policy: `integrated-current` preserves its two old P7c failures;
the updated fixtures assert FILE_NOT_AVAILABLE while pending, then explicitly
check a successful new replay after original delivery, preserving original FileId,
backend acquisition counts and failure recovery. This is an explicit protocol
policy transition, not a retry masking a race. `replay-delivery-p7c` is 23/23.
The initial implementation's MID-only delivery callback was defective;
`replay-delivery-red` preserves the new independent public-wire failure. Delivery
now matches the original CREATE status/body, so an ECHO rejection sharing its MID
cannot commit it. `replay-delivery-green` passes all seven repair regressions.
The intermediate failed build `replay-delivery-green-build` is a namespace typo,
retained separately from behavioral evidence; the corrected build has zero
warnings/errors.

R11 repairs primary-stream DELETE sharing against live alternate streams, with
stat-only exemptions and symmetric existing-primary-DELETE checks. Existing
stream generations receive independent stable identities, and detached live
handles retain their own storage. SET_SECURITY now checks WRITE_DAC, WRITE_OWNER
or ACCESS_SYSTEM_SECURITY as appropriate before applying a descriptor.
`security-sharing-red` is 4/6: the independent base-delete and unauthorized-DACL
cases fail. `security-sharing-green` is 6/6 after repair.
[MS-FSA access checks](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/82b364ce-6d7b-422f-8d88-4db32eea809a)
requires primary/alternate-stream DELETE sharing. The same source confirms the
continuation fixture's initial DELETE-capable base plus deny-delete-sharing
stream is invalid before its intended later operation. Those original fixtures
are retained untouched while their owner is active.

R12 rejects unavailable TWrp snapshots before any live backend open. A versioning
store receives its historical namespace token; an ordinary local store returns
NAME_NOT_FOUND. Leading separators are retained by CREATE parsing so admission
can validate them. Stream separators/types, explicit directory data streams and
wildcard base names reject before mutation. Unflagged lease-v2 ParentLeaseKey is
ignored. These changes do not add optional stream rename or directory leasing.

## Additional independent regressions

`UpstreamRepairTests` adds signed public-dispatch/TCP cases for deterministic first
OPEN_IF publication, client GUID dialect lifecycle without PreviousSessionId,
live stream overwrite generation, base DELETE sharing, basic DACL enforcement,
unauthorized SET DACL and replay delivery identity. The namespace fixture pauses
only backend CREATE, then observes the second missing-identity lookup before
releasing the first creator. No client retry or seeded file masks the race.
`deterministic-red` runs the first three against the original captured server DLL
substituted into the new runner: 0/3; `repair-tests-green` is 3/3 with repaired
source. This is explicitly a mixed-binary diagnostic, with DLL provenance in
`deterministic-red-runtime-manifest.json`, not a whole-source build claim. No
workspace production file was reverted. Historical Go race logs remain valid;
the enumeration churn fix still has no deterministic local conversion hook, so
its historical RED plus complete Go suite is the evidence boundary.

## Remaining continuation findings and oracle issues

No remaining test is skipped or converted to an expected-failure pass. Exact
registered names and original assertion text remain in the run logs; final result
maps are appended below. Continued port additions can change totals between
captures without any production drift.

- Conservative cache grants and break-to-NONE differ from Samba's exact RH/RW/RWH
  and classic level-II targets. The continuation itself records these as source
  compatibility choices, not automatically MUST violations. Existing pre-ACK
  mutation barriers are preserved. These larger cache-policy changes remain
  unresolved, including pending/break/retention rows that stop at an earlier
  target-state assertion; later ACK/epoch assertions in those rows are unreached.
- Named-stream rename (six variants) remains honestly NOT_SUPPORTED. Supporting
  promotion to the unnamed stream needs coherent alias/identity/lock semantics;
  copying bytes and acknowledging success would be an incomplete repair.
- No-W durable lease retention and client-GUID reconnect differences remain
  visible. They require distinguishing current spec's lease-qualified client
  check from v1/v2 and source-policy choices; no one-off rejection is added.
- The continuation's DACL tests assume no enforcement and require NOT_SUPPORTED
  for every valid descriptor. `security-sharing-red` independently proves a
  basic Everyone deny descriptor is enforced on a fresh wire CREATE, while old
  granted handles retain their rights. Therefore those plain-descriptor rows
  are invalid rejection oracles. Unsupported ACE inheritance/enforcement facets
  require separate validation; not all DACL rows are declared fixture errors.
- `upstream.samba.session.reconnect-same-transport` signs a new SessionId=0
  handshake using its old key. MS-SMB2 3.3.5.2.4 requires USER_SESSION_DELETED
  when the signed request has no session. The new Microsoft signed-initial case
  establishes that independently. The source-owner fixture must clear the old
  key for the fresh handshake; production must not accept this malformed one.
- Two stream-lifecycle deny-delete fixtures create a DELETE-capable base before
  opening the deny-delete-sharing stream, which already conflicts under MS-FSA.
  The independent `upstream.repair.stream.base-delete-sharing` uses a valid setup
  and checks rejection plus successful open after stream close.
- The old OS2 filename policy row remains RED; no mandatory protocol rule for that
  legacy name policy has been established. Compound bad-read error propagation
  and bad-IOCTL validation order still require normative/SHOULD review.
- Multichannel break sender-failure was subsequently repaired by selecting a live
  bound channel for unsolicited notifications after the failed transport is
  excluded. Async request-final delivery policy is unchanged. The original
  `handshake-samba`/`integrated-current` REDs remain. The two-connection notify-limit
  timeout remains in older captures; later owner fixture edits must be identified
  by source hashes. Cross-session lease-complex timeouts were added later and
  remain captured reproducers. They are not reclassified as grant discretion or
  hidden by retries. Further safety repair requires validating their setup and
  precise failing phase.

The final settled Linux/AOT/TCP gate remains the parent allocation's responsibility;
this allocation's broad current JIT runs are integration evidence, not that gate.

R13 routes unsolicited cache notifications to a surviving bound channel after a
transport send failure. Each failed channel is marked unusable before selecting
another; no failed peer is retried. Cache mutation still waits for the delivered
break's ACK or normal timeout. Ordinary asynchronous final responses keep their
existing transport policy. This repairs the two controlled sender-failure REDs,
without treating the loss of one channel as loss of the whole session.

R14 rejects the unsupported CREATE SecD security-descriptor context before
acquisition. Eight new continuation cases were RED in `delivery-integrated`:
production ignored an explicit descriptor and created an unsecured object.
SET_SECURITY's supported basic descriptor storage/enforcement is separate from
this unimplemented atomic security-CREATE path. Rejecting the recognized optional
context is an honest capability boundary; no malformed or successful result is
silently treated as support.

Two additional continuation rejection expectations conflict with primary rules:
FileNormalizedNameInformation (class 48) is NOT_SUPPORTED when unimplemented,
not INVALID_INFO_CLASS; and a classic ACK after the break obligation timed out
must receive INVALID_DEVICE_STATE because the open is no longer Breaking
([MS-SMB2 3.3.5.22.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/90f21fc9-3094-4d29-842d-55e9aeaf1d05)).
Their unchanged test failures are retained and are not production defects.
The same-key epoch row also needs literal-spec versus source-policy review:
[lease-v2 processing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fc4f8879-f295-4995-b71e-21f309d8d7c8)
requires an epoch increment on successful promotion of a superset; the current
code treats an equal-state successful request as promotion. No epoch patch is
made solely to match Samba's exact unchanged-state expectation.

## Reproduction commands

`repair` below is the external `file-protocol-repair` capture directory supplied
by the campaign caller, not a repository dependency. Every capture's
`command.json` retains the fully expanded exact argument array. Representative
RED/GREEN commands (no retries, seeds, skips or expected-failure switches):

```sh
python3 scripts/platform_capture.py --out "$repair/red-go" -- dotnet "$repair/red-artifacts/bin/Smb.Tests/release/Smb.Tests.dll" --filter upstream.go.
python3 scripts/platform_capture.py --out "$repair/metadata-go" -- dotnet "$repair/metadata-artifacts/bin/Smb.Tests/release/Smb.Tests.dll" --filter upstream.go.
python3 scripts/platform_capture.py --out "$repair/metadata-ms-red" -- dotnet "$repair/metadata-artifacts/bin/Smb.Tests/release/Smb.Tests.dll" --filter upstream.microsoft.
python3 scripts/platform_capture.py --out "$repair/handshake-ms" -- env TMPDIR="$repair/tmp" dotnet "$repair/handshake-artifacts/bin/Smb.Tests/release/Smb.Tests.dll" --filter upstream.microsoft.
python3 scripts/platform_capture.py --out "$repair/security-sharing-red" -- env TMPDIR="$repair/tmp" dotnet "$repair/security-sharing-red-artifacts/bin/Smb.Tests/release/Smb.Tests.dll" --filter upstream.repair.
python3 scripts/platform_capture.py --out "$repair/replay-delivery-green" -- env TMPDIR="$repair/tmp" dotnet "$repair/replay-delivery-green-fixed-artifacts/bin/Smb.Tests/release/Smb.Tests.dll" --filter upstream.repair.
python3 scripts/platform_capture.py --out "$repair/security-create-build" -- dotnet build tests/Smb.Tests/Smb.Tests.csproj -c Release --artifacts-path "$repair/security-create-artifacts"
python3 scripts/platform_capture.py --out "$repair/delivery-security-integrated" -- env TMPDIR="$repair/tmp" dotnet "$repair/security-create-artifacts/bin/Smb.Tests/release/Smb.Tests.dll"
```

These are already captured directories and must not be overwritten. To rerun,
choose new output and artifacts directories; no existing evidence is mutable.
Initial diagnostic runs used the host default temporary root; later captures
explicitly set external TMPDIR. Fixture roots are disposable in both cases.
`security-create-build` compiles with zero warnings/errors and zero source drift.

## Final captured integration

`delivery-security-integrated` runs the complete captured harness with external
TMPDIR: **2469/2641**, 172 retained failures, no source or test drift during this
run. The associated `security-create-build` has zero warnings/errors and zero
drift. No final Native AOT or native Windows execution is claimed.

| Group | Pass / total | Remaining |
|---|---:|---:|
| Prior regression, including first adapted 86 | 940 / 940 | 0 |
| Go | 83 / 83 | 0 |
| Microsoft available families | 297 / 297 | 0 |
| Original Samba plus auth/session additions | 809 / 811 | 2 |
| Samba continuation available families | 333 / 503 | 170 |
| Independent repair regressions | 7 / 7 | 0 |

The two original-family Samba failures are OS2 filename policy and the signed
SessionId=0 reconnect fixture described above. The continuation's controlled
multichannel sender-failure group is now **8/8**, and unsupported SecD atomic
CREATE rejection is **8/8**. Current complex cross-session lease workflows still
time out; original statuses and stack traces are preserved. There is no claim
that all Samba adaptations pass or that all residual findings are mandatory
production defects.

`delivery-security-summary.json` records every final failing name/assertion.
`final-handoff-manifest.json` records changed production files relative to the
auth-handoff baseline, current hashes, tested build identities and remaining
qualification. The earlier `delivery-summary.json`/`handoff-manifest.json` are
intermediate evidence and are preserved. No formatting command, restore, stage,
commit or publication was performed. Other-owner UpstreamMicrosoft*/
UpstreamSambaMore* files were not modified by this allocation.
