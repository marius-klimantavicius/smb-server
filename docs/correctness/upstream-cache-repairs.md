# Cache, durable and admission repair handoff

Later [multichannel/durable repairs](multichannel-durable-reconnect.md) extend
compatible RH grants, shared-member routing and retained-member purge, repair
both bounded complex sequences and implement SMB311 recovery. This report's
earlier results and limitations remain historical evidence; the later report
records current fixture corrections and unresolved cache workflows.

This allocation extends the completed [file/protocol handoff](upstream-repairs.md).
It preserves the existing authentication, encryption, replay-delivery and
multichannel-send repairs. No staging, commit, restore, formatting, source-test
exclusion, new runtime dependency or Native Windows execution was performed.
The port owners' `UpstreamMicrosoft*`, `UpstreamSambaMore*` and
`UpstreamInventory*` files were not edited. `AuthPeer.Login` in
`UpstreamSambaAdvancedTests.cs` has one narrow fresh-session key correction.

All evidence below is in the externally configured campaign's new
`cache-durable-repair/` directory, alongside `file-protocol-repair/`. Ordinary
tests have no dependency on that location. Run names identify immutable capture
directories, each retaining its exact `command.json`, complete `output.log`,
loaded runtime/assembly identities and SHA-256s, checkout status/diffs, and
before/after source maps. Source archives and primary specifications are external.
The parent still owns the settled-source Linux JIT/AOT and local TCP gates.

## Observed repairs and policy decisions

| Group | Original failing phase | Change and applicability |
|---|---|---|
| Same-key CREATE while breaking | `pending-confirmed-red`: both lease versions returned PENDING but could not deliver a same-key CREATE response before the conflicting overwrite's ACK. Each probe timed out and released the ACK in `finally`. | CREATE held its per-object namespace gate while waiting for a cache break. The gate is now released during that wait, then reacquired with identity revalidation before backend acquisition. Share reservations remain held. If the pathname changed, old cache/lease/share reservations are retired and admission restarts against the new identity. |
| Replacement identity after wait | External original-production diagnostic: after owner rename and replacement creation, no break was delivered for the replacement lease. | The resumed overwrite must invalidate the replacement object's cache before truncating it. Both versioned probes now check original and replacement bytes before the second ACK, and EOF only after it. |
| Classic level-II self invalidation | `independent-red`: owner WRITE and LOCK each invalidated only the other FileId's level-II grant. | The requesting FileId's classic level-II grant is also invalidated. Lease-key self exemption and exclusive/batch-owner behavior remain separate. No ACK is required for the level-II notification. |
| Attribute-only CREATE | `independent-red`: READ_ATTRIBUTES, WRITE_ATTRIBUTES and combined SYNCHRONIZE/attribute access produced a break/PENDING. | The chosen coherent-backend policy exempts nondestructive opens containing only these rights. Destructive dispositions and DELETE_ON_CLOSE still coordinate caching. This is a bounded compatibility policy, not a claim that every unsolicited revocation is prohibited. READ_CONTROL is deliberately outside this mask. |
| Fresh session on existing transport | `session-original-red`: fresh SessionId=0 SESSION_SETUP was signed with the previous session's key and correctly failed USER_SESSION_DELETED. | The test peer clears its old key before a fresh login, while retaining it for reauthentication. Production signature verification is preserved. |
| TREE_CONNECT path inside fixed fields | `parser-original-red`: three signed requests reached share-name lookup and returned BAD_NETWORK_NAME. | The parser validates the nonempty path against the actual variable buffer before decoding it. The existing structural-error mapping returns INVALID_PARAMETER. |
| Giant negotiate context offset | `parser-original-red`: three unsigned 0xfffffff8 offsets became negative slice positions and were mapped to OBJECT_NAME_INVALID. | Bounds, dialect-array separation and 8-byte alignment are validated before converting the wire offset to an `int`. Context-header bounds use subtraction rather than overflowing addition. This is structural validation, not pathname validation. |
| Ill-formed UTF-16 namespace input | `parser-original-red`: two CREATEs succeeded via replacement decoding; two QUERY_DIRECTORY patterns were interpreted and returned no-match. `unicode-alias-red` independently opened an existing literal U+FFFD name from malformed request bytes. | Strict decoding is an **explicit fail-closed namespace policy** for CREATE, QUERY_DIRECTORY and TREE_CONNECT. A supplementary-character pair and a literal U+FFFD filename still round-trip. These original four rows are source compatibility candidates, **not proven mandatory INVALID_PARAMETER violations**. |
| Ordinary IOCTL missing FileId | `ioctl-original-red`: a fresh correctly sequenced request returned INVALID_DEVICE_REQUEST for its control code instead of locating the missing open. | Ordinary control codes now validate their FileId before control-code/profile dispatch; the five server/tree sentinel control codes remain exempt. |
| NTLM AUTHENTICATE field validation | `auth-buffer-original-red-selected`: 20/24, with LM/workstation fields at offset 10 or 72 establishing sessions. `auth-layout-original-red`: valid controls 2/2, malformed cases 0/4. | Nonempty fields must lie in Payload outside the applicable header, fit without overflow, and meet Unicode offset/length parity. Optional Version affects the bound; absent buffers ignore offsets and MaxLen. An announced MIC is validated against the existing supported Version/MIC layout. Nonempty LM response has its specified 24-byte shape. Unused encrypted-key fields are ignored when KEY_EXCH is absent. Only `NtlmAuthenticateMessage` changed in authentication production code. |

The namespace fix does not relax missing-name publication serialization. The
original first-OPEN_IF publication, replay identity and delivery regressions pass.
The retained physical cache scope still prevents incompatible grants during
backend work. No cache architecture replacement or blanket Samba exact-grant
policy was introduced.

## Independent authority and qualification

- [MS-SMB2 3.3.5.9.11](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fc4f8879-f295-4995-b71e-21f309d8d7c8)
  requires the existing state and BREAK_IN_PROGRESS when a lease is breaking.
  The new same-key probes reach that phase before releasing the overwrite ACK;
  they do not first require Samba's particular downgrade target.
- Microsoft's object-store [WRITE](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-write2)
  and [LOCK](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-lock-control2)
  rules invalidate classic level-II caching even for the requesting open.
  The [CREATE rules](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-create2)
  separately describe attribute-only opens. These inform the selected local
  coherent-store policy; they do not require implementing every Windows grant.
- [MS-SMB2 3.3.5.2.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/85df1680-2ee7-4d25-a916-a982371ddc75)
  requires USER_SESSION_DELETED when a signed initial request has no session.
  The reconnect fixture correction must not be implemented by accepting that
  malformed initial signature in production.
- [TREE_CONNECT syntax](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/832d2130-22e8-4afb-aafd-b30bb0901798)
  places the share path in Buffer.
  [NEGOTIATE syntax](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e14db7ff-763a-4263-8b10-0c3944f52fc5)
  places contexts after the dialect array with the specified alignment.
  Returning structural INVALID_PARAMETER is the maintained rejection policy;
  no broader claim about every malformed-request status is inferred.
- [MS-SMB2 2.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/6eaf6e75-9c23-4eda-be99-c9223c60b181)
  specifies Unicode 5 UTF-16. [Unicode 5 chapter 3](https://www.unicode.org/versions/Unicode5.0.0/ch03.pdf),
  D91, identifies isolated surrogates as ill-formed. **C10 permits replacement
  handling with U+FFFD**; it does not require SMB rejection. Strict parsing is
  chosen to prevent lossy namespace aliasing. Odd byte counts and invalid buffer
  locations are separate framing constraints. The PDF and extracted text are
  retained under `spec/`.
- [MS-SMB2 3.3.5.15](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/c348a671-7750-49f8-9e61-cc59fa1a5701)
  requires locating an ordinary IOCTL's open and returning FILE_CLOSED when it
  is absent. The independent probe uses an actual valid message sequence.
- [MS-NLMP AUTHENTICATE_MESSAGE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/033d32cc-88f9-4483-9bf2-b273055038ce)
  defines field references into Payload, ignored MaxLen fields, Unicode parity,
  and ignored unused encrypted-key fields. [LMv2_RESPONSE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/8659238f-f5a9-44ad-8ee7-f37d3a172e56)
  is 16+8 bytes. The
  [product notes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/a211d894-21bc-4b8b-86ba-b83d0c167b00)
  distinguish omitted Version/MIC layouts. A blanket 88-byte payload minimum is
  not used. Successful signed 64-byte-header controls and absent-field offsets
  are tested. This allocation does not extend the mechanism's existing MIC
  verification at byte 72 into support for compact MIC-at-64 authentication.

The short NT proof keeps the existing terminal LOGON_FAILURE priority before
semantic text-parity validation. The first AUTH green run retained a Go
short-proof status regression (82/83); the narrow correction preserves the
rejection and the exact old Go oracle. That failed run is not overwritten.

## Durable and cache findings that do not justify forced exact grants

The independent v1/v2 probes obtain actual Batch or RH durable grants through
CREATE, WRITE, acquire a real byte-range lock, set position to 4096, disconnect,
and reconnect. They verify lock ownership, position, exact bytes and one-shot
claim consumption. A foreign ClientGuid fails a leased claim, and the valid
claim remains usable. A classic Batch claim permits a different ClientGuid.
These controls passed before the cache changes.

[MS-SMB2 connection loss](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/eb5bfe99-47fe-4e87-8e87-08a084dcefb6)
qualifies durable lease retention by HANDLE caching, not WRITE caching.
[v1 reconnect](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ba7499c3-4679-4d07-a82a-c80d9c2c6905)
and [v2 reconnect](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/62ba68d0-8806-4aef-a229-eefb5827160f)
qualify the ClientGuid comparison by lease presence. Thus the two Samba
`lock-no-write-lease` rejection expectations are source retention policy, not
grounds to destroy a valid RH durable open or its locks. The implementation
remains bounded in-memory recovery; persistent/CA restoration is unavailable.

Exact RH/RW/RWH/level-II grants, retained-RH keep/purge, share-denial cache breaks,
and equal-state v2 epoch requests still differ from Samba. Existing break-to-NONE
policy remains. Source rows stopping at an earlier target/grant assertion do
not establish whether their later ACK/epoch/replay assertions would pass.
The independent probes cover ACK rejection without premature CREATE completion,
common-key promotion across signed sessions, epoch sharing, closing a member,
the last live member's break delivery, and no pre-ACK overwrite.

## Cross-session timeout and compound setup diagnostics

`complex-original-red` retains v1 reaching the RH-target assertion and v2 timing
out in the `Other` response collector. `candidate-full` retains both timeout
variants. The collector starts two `WaitForSendAsync` tasks with `WhenAny` and
leaves the losing task running; that task can consume a later response signal.

In the external `baseline-diagnostic/` source copy, only this collector's losing
wait is canceled and drained. Production hashes match `pending-red-build`
exactly. `baseline-diagnostic-cross-session-complex` reaches the RH-target
assertion in **both** versions, with no timeout. Neither source assertion is
weakened and no behavior retry is used. The maintained owner file is untouched.
Its corrected collector still needs integration by the port owner. Subsequent
source phases after the exact RH mismatch remain unreached.

The original `compound.bad-ioctl` also has an earlier setup problem: its two
ECHOs leave the chosen MID 101 outside the granted credit window. It returns
INVALID_PARAMETER before the command handler. Longer chains happen to issue
enough ECHOs first. The independent missing-open probe confirms and repairs the
distinct handler defect without accepting an invalid MessageId. The maintained
compound helper remains its owner's file.

`compound.bad-read` sends an unknown related command after EOF. The dispatcher
currently propagates the predecessor error before dispatching that unknown
command. [3.3.5.2.7.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/46dd4182-62d3-4e30-9fe5-e2ec124edca1)
recommends propagation for a subsequent FileId operation; this unknown command
has no defined FileId contract. Its precise malformed-command/error-validation
ordering remains a compatibility/SHOULD assessment, not a claimed mandatory
repair. The previously documented propagation policy is preserved.

## Other retained REDs and boundaries

- Named-stream rename remains NOT_SUPPORTED in six source rows. Promotion to
  the unnamed stream needs coherent object, alias and lock semantics; bytes
  were not copied to manufacture successful support.
- OS2 legacy filename policy remains RED. The corrected same-transport session
  replacement passes; no mandatory OS2 filename defect is inferred.
- Ten optional QUERY_INFO rejection statuses and two ARCHIVE reassertion rows
  remain explicit compatibility choices. The newest archive fixtures close and
  reopen before querying, respecting allowed deferred updates. The full ushort
  dialect-array offer versus the current 64-offer parser cap is another explicit
  bounded-profile/source compatibility difference.
- New LOCK flags 0 and FAIL_IMMEDIATELY-only source rows are retained. Processing
  undefined flag combinations is governed by the explicit SHOULD in
  [3.3.5.14.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/670c7eda-e683-4923-9477-414303959613).
  No claim that those rows prove a MUST violation or mandatory repair is made.
- AUTH buffer row `44-mic` still succeeds: it puts four workstation bytes at 72
  without a declared Version or announced MIC. The source client's assumed MIC
  layout is not established by the adapted request. The four other successful
  malformed layout probes are repaired without forcing an 88-byte minimum.
- Later port additions expose DACL namespace/INHERIT_ONLY/generic-mask/owner
  findings. In particular, the observed rename/hardlink denial bypasses must
  not be classified as cache-grant discretion. `candidate-summary.json` retains
  all 12 then-observed security names and assertions. This parser/cache
  allocation has not repaired or accepted those broader descriptor semantics;
  they remain security follow-up blockers for the parent.
- No Native Windows, final Native AOT, full dialect conformance or all-green
  campaign claim is made. Active test/inventory owners can add cases after a
  build; loaded assembly and captured-source identities delimit each result.

## Immutable runs and reproduction

`campaign` below denotes the externally supplied campaign path; it is not a
maintained filesystem dependency. All arguments are retained expanded in each
run's `command.json`. Choose **new** output/artifacts directories for a rerun.

```sh
repair="$campaign/cache-durable-repair"
python3 scripts/platform_capture.py --out "$repair/pending-red-build" -- dotnet build tests/Smb.Tests/Smb.Tests.csproj -c Release --artifacts-path "$repair/pending-red-artifacts"
python3 scripts/platform_capture.py --out "$repair/pending-confirmed-red" -- env TMPDIR="$repair/tmp" dotnet "$repair/pending-red-artifacts/bin/Smb.Tests/release/Smb.Tests.dll" --filter pending-member
python3 scripts/platform_capture.py --out "$repair/candidate-build" -- dotnet build tests/Smb.Tests/Smb.Tests.csproj -c Release --artifacts-path "$repair/candidate-artifacts"
python3 scripts/platform_capture.py --out "$repair/candidate-full" -- env TMPDIR="$repair/tmp" dotnet "$repair/candidate-artifacts/bin/Smb.Tests/release/Smb.Tests.dll"
python3 scripts/platform_capture.py --out "$repair/parser-original-red" -- env TMPDIR="$repair/tmp" dotnet "$repair/parser-red-artifacts/bin/Smb.Tests/release/Smb.Tests.dll" --filter upstream.inventory.
python3 scripts/platform_capture.py --out "$repair/auth-layout-original-red" -- env TMPDIR="$repair/tmp" dotnet "$repair/auth-layout-red-artifacts/bin/Smb.Tests/release/Smb.Tests.dll" --filter upstream.cache-repair.auth.layout
python3 scripts/platform_capture.py --out "$repair/focused-final-build" -- dotnet build tests/Smb.Tests/Smb.Tests.csproj -c Release --artifacts-path "$repair/focused-final-artifacts"
python3 scripts/platform_capture.py --out "$repair/focused-final-0" -- env TMPDIR="$repair/tmp" dotnet "$repair/focused-final-artifacts/bin/Smb.Tests/release/Smb.Tests.dll" --filter upstream.cache-repair.
```

Key source archives: `independent-red-source.tar.gz`, reconstructed and
hash-verified `pending-red-source.tar.gz`, `candidate-source.tar.gz`,
`parser-red-source.tar.gz`, `unicode-alias-red-source.tar.gz`,
`auth-layout-red-source.tar.gz`, `auth-buffer-green-tested-source.tar.gz`, and
`focused-final-source.tar.gz`. `tested-source-reconstruction.json` verifies the
tested AUTH-green snapshot. The earlier `parser-green-source.tar.gz` records a
later inventory-owner edit and is **not** the exact tested boundary-test source;
its exact earlier version is retained in `parser-red-source.tar.gz` and the
hash-verified later AUTH-green snapshot. No old evidence is rewritten.

The external baseline diagnostic's first capture wrapper failed because its
source copy was not a Git checkout. The corrected external wrapper reads
checkout diffs from the maintained checkout while hashing/executing the
external baseline. `baseline-diagnostic-build-fixed` then built cleanly.
`auth-buffer-original-red` selected an incorrect filter and ran no cases; the
separate `auth-buffer-original-red-selected` is the actual 24-case RED.
Neither invocation error counts as behavioral evidence.

| Captured build/run | Result and limitation |
|---|---|
| `current-build` | 0 warnings/errors, no source drift |
| `independent-red` | 8/15; level-II, attribute-only and same-key pending failures retained |
| `pending-confirmed-red` | 0/2; genuine same-key completion timeout before ACK |
| `candidate-independent` | 17/17 |
| `candidate-full` | 2574/2736: prior 940/940, Go 83/83, Microsoft 297/297, original Samba 810/811, More 407/556, prior repair 7/7, cache repair 17/17, then-registered inventory 13/25; zero source drift |
| `parser-original-red` | 56/78; ten parser/policy candidates plus twelve compatibility failures |
| `unicode-alias-red` | 1/3; valid Unicode control passes, two malformed aliases succeed |
| `parser-green-inventory` | 69/81; only the twelve compatibility rows remain in that captured assembly |
| `parser-green-independent` | 20/20 |
| `ioctl-original-red` | 0/1, missing FileId reaches control-code dispatch |
| `auth-layout-original-red` | 2/6, four malformed attempts succeed |
| `auth-green-0` | 27/27 independent cache/parser/auth probes |
| `auth-green-1` | 23/24 original AUTH buffer adaptations; unannounced-MIC-layout row retained |
| `auth-protection-0..5` | P3 64/64, P5 174/174, P6 88/88, P7 227/227, P8 125/125, Microsoft 297/297 |
| `auth-protection-6` | Samba session 40/41, OS2 policy only |
| `auth-protection-7` | 116/132, newest inventory at that capture; all failures retained |
| `auth-protection-8` | controlled multichannel cache/failover 8/8 |
| `focused-final-0` | independent cache/parser/auth probes 27/27 |
| `focused-final-1` | complete Go protection 83/83, including the restored short-proof rejection status |
| `focused-final-2` | complete Microsoft protection 297/297 |
| `focused-final-3` | inventory 116/132, 16 retained failures: query-status 10, ARCHIVE 2, undefined LOCK flags 2, maximum dialect-array cap 1, unannounced MIC-layout assumption 1 |
| `focused-final-4` | P7 recovery/channel/replay 227/227 |
| `focused-final-5` | original Samba authentication 31/31 |

`focused-final-*` and `handoff-manifest.json` contain the final focused counts,
exact production hashes, assembly hashes and remaining assertions. The latest
focused build has zero warnings/errors and no source drift. No later full
JIT/AOT/TCP acceptance gate was run while source owners remained active.

The AUTH buffer provenance is the first-party server-side
`internal/ntlm.TestAuthenticateRejectsOutOfRangeSecurityBuffers` in the pinned
Hiro Go source, invoking `server.Authenticate`; it is not a client-only helper
test. The adaptation is still judged by its actual declared message layout.
The latest audit-owner run08 reports 113/132 before these last parser repairs;
those original results and selector-mapping corrections remain that owner's
evidence, distinct from `focused-final-3` above.

After the final focused build and runs, other owners changed
`UpstreamSambaMoreOplockTests.cs` and `UpstreamInventoryBoundaryTests.cs`.
The captured build/run source maps show no
drift during execution, and `focused-final-source.tar.gz` matches that tested
source. This is not a claim that the later shared checkout is settled or fully
tested. The requested inventory-audit Markdown file had not yet appeared in the
checkout at this handoff; the available test source and external run evidence
were inspected directly.
