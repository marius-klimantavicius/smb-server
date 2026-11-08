# Independent Go and Microsoft inventory audit

This audit concerns the pinned sources and public SMB/authentication facets, not
upstream implementation equivalence. Production was read-only for this allocation.
Existing staged/unstaged work was preserved; only owned inventory tests, their one
registration line, this report, precise Go/Microsoft report corrections, and
`scripts/validate-platform.py` were changed. No foreign implementation or runtime
dependency was imported. Ordinary execution is offline .NET 10/BCL on either host.
Native Windows execution and final settled Linux JIT/AOT/TCP gates remain pending.

## Census, method and selector reconciliation

The Go source census remains **147 test files and 1,401 Test functions**. The
external per-function audit covers all **1,491 inventory records**: those Test
functions plus the original benchmark/fuzz/setup/example/scenario/table records.
Of the 147 files, 146 contain these records; `smb/server/mem_vfs_test.go` is a
helper-only in-memory VFS fixture with no Test entry. It is inventoried as zero
executable cases and no public protocol assertion. A record contains its immutable
source link, symbol, source body hash, named runs,
ranges/tables, original mapping, audit disposition, rationale and new facet map.
Table records and repeated matrix prefixes are not passing tests.

The Microsoft source census remains **3,205 registered methods in 176 files**.
Every entry and its reachable helper/checker references were traversed separately
from the earlier inventory generator, balancing braces and parentheses after
recognizing C# strings/comments. The complete external per-method ledger records
body hashes, reachable helper names, normalized calls and audit dispositions.
The maintained Microsoft method table now links to that extraction's actual calls.

The earlier **2,694-selector count is a historical flawed regex extraction**. At
least **144 records are non-call fragments**, including checkpoint prose in I0001,
`\")` in I0002 and the `ClusterSizeInKB` property in I0202. Finding the same text in a
source file did not make those protocol inputs. The current maintained ledger
removes those pseudo-input rows and replaces the old selector links with **2,224
normalized adapter/client member-call signatures**. This definition includes
configuration, assertions and other genuine source-only calls; it excludes the
old regex's malformed string fragments and does not use precisely the same helper
call definition. The numerical difference is not simply 144 removed protocol
cases. Neither number is a conformance count or proof of complete graph coverage.

Namespace qualification, whitespace and temporary output-variable names are
normalized. Literal arguments and enum casts are preserved. Repeated calls through
different generated prefixes share a row; identical operation names with different
arguments do not automatically collapse. In particular, matching a registered
local name was rejected as proof of identical input/result. All earlier execution
counts and failed evidence remain historical evidence of their captured sources.

External evidence is the campaign's new `inventory-audit/` subtree. Important
artifacts are `go-per-function-audit-final.json`, `microsoft-per-method-dispositions.json`,
`microsoft-reachable-method-audit.json`, `microsoft-lexical-selectors.json`,
`microsoft-noncall-selector-objections.json`, `selector-summary.json`, the original
reports before correction, build/run captures, fixture versions and artifact/source
manifests. These are audit outputs, never build/runtime dependencies.

## Corrections established from bodies and local assertions

- Go macOS `TestLockRequestDecoderRejectsTruncation` declares two elements but
  supplies one. Neither enumeration/name/auth tests nor the old READ/WRITE parser
  matrix test this LOCK boundary. The inventory now has real signed TCP rejection,
  unchanged prior lock, no partially acquired first element, and successful retry.
- Go Hiro's `TestAuthenticateRejectsOutOfRangeSecurityBuffers` and
  `TestAuthenticateRejectsInvalidKeyExchangeLength` call **server.Authenticate**.
  Their former client-only classification was wrong. All six authenticate buffer
  fields and the source header/MIC/overrun/wrap partitions are now public tests.
  The separate `TestAuthenticateRejectsBeforeNegotiate` calls **Client.Authenticate**
  and remains an initiator API test. Server authenticate without a challenge is
  separately exercised through an initial type-3 packet from another exchange.
- Hiro `x/wire` request decoders are not excluded just because their repository is
  a client. Independently meaningful receiving-server offsets/counts/truncations,
  malformed names, negotiation contexts and LOCK flags are adapted. RDMA-only
  success remains unavailable. Channel-info bytes that the applicable Channel=0
  contract ignores are not turned into invented errors. Zero-length buffer offset
  rules remain field-specific; a strict helper decoder does not override them.
- A source decoder rejecting fabricated **responses** is not a malformed request
  to send to a server. Its positive ordinary response fields map to existing Go
  directory layouts, Microsoft metadata/CLOSE, P5 bounds and real IOCTL responses.
  Synthetic upstream timestamps, addresses, AsyncIds and unknown response tags
  cannot be imposed on a live host. In particular, the first CREATE response
  context cannot be forced to have synthetic `Next=88`; the request-chain padding
  rule is independently exercised before a recognized security context.
- `TestEncodeSessionlessEchoResponseKeepsZeroSession` has an independent public
  facet. A live authenticated connection now receives an unsigned SessionId=0
  ECHO response, followed by successful signed ECHO on its retained session.
- Go `TestHandleCap` is not exactly the provisional CREATE race. A signed TCP
  capacity/reject/close/retry test now demonstrates its public facet without
  fabricating an internal handle table. `TestQueryInfoRespectsOutputBufferLength`
  now has its actual dynamic full-volume-length minus two boundary, rather than
  only fixed-size analogies. `TestPathTraversal` is a real CREATE error scenario,
  not merely a private normalizer: all three source shapes preserve outside bytes.
- Stopped-listener and Go goroutine/Shutdown API assertions are not exactly
  `p2.counts.connection-loss-sessions`. The false exact references are withdrawn;
  those implementation/host lifecycle assertions are excluded from new ports.
- Microsoft `InvalidCreateRequestStructureSize` sets **58**. The earlier cited
  parser matrix did not issue that CREATE. New signed TCP cases cover 0/56/58,
  no mutation and a valid retry.
- Microsoft `DurableHandleV1_Reconnect_WithoutFileIdPersistent` concerns a missing
  **FileId.Persistent identifier half**, not persistent/CA handle support. New
  actual durable-v1 grants precede invalid claims and valid recovery. Separate
  v1+lease cases cover wrong/missing lease, no held lease, active original open,
  client GUID, owner and absent durable grant. Existing v2 cases were not exact
  substitutes. The declared durable profile offers SMB300/302, so these common
  v1 facets use SMB300; they do not claim the original SMB210 grant is supported.
- Linux DOS attributes are now per-store memory. The old automatic ARCHIVE
  exclusion based only on lack of DOS persistence is too broad. File WRITE and
  directory child CREATE after explicit archive clearing are tested through
  close/reopen. They remain source/SHOULD compatibility assertions; no restart
  persistence or mandatory NTFS behavior is inferred. Creation-time stability
  during those mutations is separately asserted.

Immutable sources are the five revisions in [the Go report](upstream-go-tests.md)
and Microsoft revision `29ddb4238a5443b7499e82934c90cc898861c5e7` in
[the Microsoft report](upstream-microsoft-tests.md). Those reports retain every
source symbol/permalink; the corrected per-method table uses actual call locations.

## Registered public facets

`UpstreamInventoryTests.Cases()` registers **140 cases** from the owned `UpstreamInventory*.cs` files
under `upstream.inventory.`. Filesystem/packet cases use signed TCP and the actual
LocalFileStore. NTLM cases use raw TCP; the existing NTLM client constructs valid
proofs, while mutations and expected rejection are independent. This is not an
additional independent NTLM cryptographic known-answer implementation. Durable
cases honestly start with established signed direct-session fixtures, then obtain
actual grants and disconnect through the dispatcher; no retained record or private
open lifecycle is manufactured. Backend observations only corroborate wire effects.

| Local suffix / partition | Exact pinned source symbols / recovered facet |
|---|---|
| `lock.truncated-*` (7), `lock.two-wire-elements` | [macOS lock_test.go `TestLockRequestDecoder`, `TestLockRequestDecoderRejectsTruncation`](https://github.com/macos-fuse-t/go-smb2/blob/277a9300411249a881a05f7a910f5a83ae3395f2/internal/smb2/lock_test.go#L8): counts 1/2/65535 and lengths 0/23/24/47/48/71, atomic incomplete-array rejection, literal ranges 100+20 and 200+30 |
| `lock.invalid-flags-0/5/16` | [Hiro `TestLockRequestDecoderRejectsInvalidElements`](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/wire/request_test.go): exact flag combinations, retained prior lock and release/retry |
| `create.no-response-contexts`, `.padded-unknown-before-security-context`, `.context-length-outside-frame` | [macOS create_context_test.go](https://github.com/macos-fuse-t/go-smb2/blob/277a9300411249a881a05f7a910f5a83ae3395f2/internal/smb2/create_context_test.go), [portable `TestCreateContextsParser`](https://github.com/fiddyschmitt/portable-smb-server/blob/107bb541fbb1c5e848c1b4ebb28f22117c17d523/internal/smb/aapl_test.go): zero response offsets/length, 84-byte first record padded to Next=88 before recognized SecD, outer length past frame rejects before mutation |
| `bounds.*-overflow` (9), `bounds.*-below-*` (27) | [Hiro `TestRequestDecodersRejectOverflowingBufferBounds`, `TestRequestDecodersRejectVariableBufferOffsetsBelowFixedFields`](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/wire/request_test.go): SESSION_SETUP/TREE_CONNECT/CREATE name/context/WRITE/IOCTL/QUERY_DIRECTORY/QUERY_INFO/SET_INFO; offsets 0/header/fixed-end-minus-one and overflowing counts |
| `bounds.truncated-fixed-*` (8) | Same request decoder source: **320 byte cuts** over TREE_CONNECT/CREATE/READ/WRITE/IOCTL/QUERY_INFO/SET_INFO/QUERY_DIRECTORY; eight executable cases, not 320 extra registered cases |
| `negotiate.context-overlap-*` (9), `.truncated-max-dialects`, `.valid-max-dialects` | Hiro `TestNegotiateRequestDecoderRejectsContextListOverlappingFixedOrDialects`, `TestNegotiateRequestDecoderRejectsOutOfBoundsSMB311Contexts`, `TestNegotiateRequestDecoderMaxDialectCount`: 1/3/4 dialect context offsets, uint32 boundary, 65535-dialect count and one-byte truncation. Maximum valid count deliberately offers supported SMB302 without claiming SMB311 success without preauth. |
| `names.create-unpaired-*`, `.directory-unpaired-*` (4) | Hiro `TestRequestNamesRejectMalformedUTF16`: exact `D800 0078` and `DC00 0078`, separate from odd byte counts; strict source policy qualification below |
| `auth.keyexchange-length-*` (3), `.buffer-*` (24), `.type3-before-challenge` | [Hiro server acceptor tests](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/internal/ntlm/ntlm_test.go#L956): key lengths 0/15/17; LM/NT/domain/user/workstation/key security buffers at 10/72/end-minus-one/uint32-wrap; reject without establishing a session and fresh valid exchange on same transport |
| `auth.sessionless-echo-with-live-session` | [macOS `TestEncodeSessionlessEchoResponseKeepsZeroSession`](https://github.com/macos-fuse-t/go-smb2/blob/277a9300411249a881a05f7a910f5a83ae3395f2/server/conn_test.go#L10): exact response SessionId/signing facets with a live session |
| `create.structure-size-*` (3), `.handle-cap-close-retry` | Microsoft [SMB2Basic `InvalidCreateRequestStructureSize`](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/Basic/SMB2Basic.cs) and portable `TestHandleCap`; actual public malformed packet/capacity behavior |
| `durable-v1.missing-persistent-*` (2), `.missing-persistent`, `.wrong-lease`, `.missing-lease`, `.no-held-lease`, `.active`, `.client-guid`, `.owner`, `.not-durable` (8) | Microsoft [DurableHandle.cs `DurableHandleV1_Reconnect_WithoutFileIdPersistent` and `_ObjectNameNotFound` helper partitions](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/DurableHandle/DurableHandle.cs#L431); v1 Batch controls and v1+lease cases remain distinct |
| `metadata.archive-on-modification-*`, `.creation-stable-on-modification-*` (4) | Microsoft [Algorithm_Noting_FileModified.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/CommonAlgorithm/Algorithm_Noting_FileModified.cs): file WRITE/directory child CREATE plus close/reopen, source allows deferred updates |
| `query.unsupported-*` (10) | Microsoft FSA/FSAModel query classes: Access(8), Mode(16), Alignment(17), AlternateName(21), Compression(28), ObjectId(29), Completion(30), ValidDataLength(39), HardLink(46), SFIOReserve(54). Tests assert recognized-but-unimplemented NOT_SUPPORTED as a **SHOULD compatibility** distinction, not success for those optional records. |
| `query.volume-two-bytes-short`, `names.escape-0/1/2` | portable `TestQueryInfoRespectsOutputBufferLength`, `TestPathTraversal`; exact dynamic-volume truncation/prefix and three outside-root path forms, without requiring the source’s private API |

The two Go `TestSecurityDescriptor` integration functions were also separated from
private SID/ACL codecs: `security.query-3/4/7` checks the requested owner/group and
non-null self-relative descriptor; `security.query-set-dacl-roundtrip` performs
public QUERY/SET/QUERY. Neither KDC nor Windows DACL SUT control is needed for
those ordinary supported operations. All four pass in the focused capture.

`auth.no-version-64-byte-header` and
`auth.workstation-offset72-without-mic` are positive header-layout controls.
The 24 negative authenticate-buffer cases announce a MIC when testing its area.
Their original unannounced-MIC variant is retained in the evidence archive.

## Expectations, corrections and remaining distinctions

The strict-surrogate input is ill-formed UTF-16 under Unicode 5.0 D91. However,
[Unicode 5.0 C10, page 73](https://www.unicode.org/versions/Unicode5.0.0/ch03.pdf)
permits replacement-marker handling. [MS-SMB2 message syntax](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/6eaf6e75-9c23-4eda-be99-c9223c60b181)
requires Unicode5/UTF-16 text but does not establish universal server
INVALID_PARAMETER rejection for every malformed surrogate. The four unchanged
strict-rejection tests are pinned-source compatibility candidates. They are not
proven mandatory defects from C10. Strict rejection may be selected as an explicit
namespace policy. Odd UTF16 **byte parity**, offset and buffer bounds are separate.

Undefined LOCK flag combinations 0/16 have a SHOULD INVALID_PARAMETER rule in
MS-SMB2 3.3.5.14.2; their source-policy failures are not universal MUST findings.
The supported parser's 64-dialect cap differs from the source helper's full uint16
cardinality. Its max-count failure is retained as source compatibility, without
blindly demanding an unlimited/resource-unbounded parser. Known optional query
classes and automatic ARCHIVE updates likewise remain SHOULD distinctions.

A malformed NTLM source test requires error, without prescribing one NTSTATUS.
The new buffer matrix therefore requires an error-severity final result; proof/MIC
failure and syntax failure are both legitimate. Four source-overlap inputs were
accepted on the initial build: LM or workstation fields at offset 10/72 with a
valid NT proof. Offset10 is inside the mandatory header. The original offset72
workstation case did **not** announce Version or MIC and was valid payload layout;
its initial failure is not a production defect. The corrected MIC-area partition
actually announces a MIC. Separate positive controls prove the 64-byte mandatory
header and offset72-without-MIC remain usable. These are parser-envelope rules,
**not** password or MIC bypass evidence. The production owner's separate MS-NLMP
layout repair is linked in [the cache repair report](upstream-cache-repairs.md).
Zero-length offsets retain their distinct semantics.

Retained fixture/oracle corrections:

- `run-01`: default fixture CREATE lacked READ/WRITE_ATTRIBUTES and directory
  CREATE used OPEN. Metadata cases now request their access and create directory
  state publicly. MxAc response support was assumed incorrectly: the padded-chain
  test now routes to recognized SecD rejection, without claiming optional MxAc.
- `run-03`: malformed established reauthentication was followed by an invalid
  assumption that its old session must survive. The case now uses an initial
  unsigned setup on a fresh negotiated transport, followed by real valid login.
- `run-03`: an invented LOGON_FAILURE oracle for malformed key-exchange buffers
  conflicted with legitimate syntax INVALID_PARAMETER. The malformed-token oracle
  was corrected with that rationale; original failures/source are retained.
- `run-08` preserves the original NTLM offset72 failure. `fixture-09-auth.cs`
  retains the old fixture: its Version/MIC fields were unannounced, so an 88-byte
  minimum was not justified. The MIC-area partition now uses an announced MIC;
  separate valid 64-byte/offset72 controls prevent a blanket88 regression. No
  source-policy expectation was changed merely to match implementation output.
- `run-06`: the new v1 claim matrix assumed durable grants under SMB210. The
  declared profile offers durable handles only on SMB300/302. The fixture now
  uses SMB300; no promise of SMB210 durable support was fabricated.
- Archive/creation stability assertions include close/reopen, matching the source
  helper's allowance for deferred updates. The stronger archive-clear prerequisite
  distinguishes automatic update from a default archive bit already being set.

There are no skips, expected-failure conversions or retry loops turning RED into
success. A failed prerequisite leaves its later assertions unreached. A later
production-owner repair does not erase a captured RED or make earlier source
hashes evidence for the new build. This audit does not certify entire generated
state graphs, all Go client APIs, or whole-dialect/native Windows conformance.

## Portable capture runner

`--keep-going` is optional; omitting it retains fail-fast execution. Every executed
stage records exit code and `pass`/`fail`; unavailable dependency stages record
`blocked`, `exit: null` and `blocked_by`. Commands, logs and before/after source
manifests are retained even for blocked stages. Artifact hashes and final status
are produced after failure. Any failure or blocked stage yields final `fail` and a
nonzero process exit. Successful later gates never transform an earlier failure.

Publishes perform their own restore/build, so they can independently succeed after
solution rebuild failure. Harness, stress and host gates depend on their own
successful publish, not on another harness being green. A failed tests publish
blocks only its executable gates; the independently published host can still run
selftest/localtest. A failed SDK launch blocks dependent work instead of executing
missing binaries. RID selection remains native Windows/Linux x64/arm64; no crossbuild
is called native evidence.

The existing portable-tool checks pass **12/12**. External synthetic checks cover
success, a RED JIT harness followed by native/host/TCP gates, failed native-tests
publish, failed restore with independent publish, unavailable SDK, and default
fail-fast. The Windows command/dependency branches were simulated; this is script
logic validation, not native Windows .NET/AOT execution. The first synthetic check
had an unmocked platform subprocess and is retained alongside the corrected run.

After source owners settle, the parent can run on each **native host**:

```sh
python3 scripts/validate-platform.py --out "$new_capture" --keep-going --stress-rounds 3
```

With an already provisioned scratch directory, append `--temp-root "$scratch"`.
Focused inventory reproduction (choose new output/artifact directories):

```sh
python3 scripts/platform_capture.py --out "$capture/build" -- dotnet build tests/Smb.Tests/Smb.Tests.csproj -c Release --artifacts-path "$artifacts"
python3 scripts/platform_capture.py --out "$capture/run" -- dotnet "$artifacts/bin/Smb.Tests/release/Smb.Tests.dll" --filter upstream.inventory.
```

The final full platform gates were deliberately not run during active production
work. The following file/operation census is an audit routing map. It states the
public versus private boundary for every inventoried group; it does not turn a
family-level mapping into an assertion that every state sequence passed.

## Complete source-file routing census

All 147 Go test files are represented below. Counts include table/driver records; the Test-function census remains 1,401. Each linked file’s individual symbols and subcase domains remain in the corrected Go report, and each record has an independent disposition in the external per-function ledger.

| Pinned Go source file | Records | Audit routes |
|---|---:|---|
| [macos-fuse-t/go-smb2/fs_impl_lock_unix_test.go](https://github.com/macos-fuse-t/go-smb2/blob/277a9300411249a881a05f7a910f5a83ae3395f2/fs_impl_lock_unix_test.go) | 2 | internal-api-or-primitive: 2 |
| [macos-fuse-t/go-smb2/fs_impl_test.go](https://github.com/macos-fuse-t/go-smb2/blob/277a9300411249a881a05f7a910f5a83ae3395f2/fs_impl_test.go) | 2 | retained-qualified-adapted-here: 1, retained-qualified-unsupported-feature: 1 |
| [macos-fuse-t/go-smb2/internal/crypto/ccm/ccm_test.go](https://github.com/macos-fuse-t/go-smb2/blob/277a9300411249a881a05f7a910f5a83ae3395f2/internal/crypto/ccm/ccm_test.go) | 1 | internal-api-or-primitive: 1 |
| [macos-fuse-t/go-smb2/internal/crypto/cmac/cmac_test.go](https://github.com/macos-fuse-t/go-smb2/blob/277a9300411249a881a05f7a910f5a83ae3395f2/internal/crypto/cmac/cmac_test.go) | 1 | internal-api-or-primitive: 1 |
| [macos-fuse-t/go-smb2/internal/ntlm/ntlm_test.go](https://github.com/macos-fuse-t/go-smb2/blob/277a9300411249a881a05f7a910f5a83ae3395f2/internal/ntlm/ntlm_test.go) | 8 | retained-qualified-adapted-here: 4, internal-api-or-primitive: 3, public-auth-acceptor: 1 |
| [macos-fuse-t/go-smb2/internal/smb2/create_context_test.go](https://github.com/macos-fuse-t/go-smb2/blob/277a9300411249a881a05f7a910f5a83ae3395f2/internal/smb2/create_context_test.go) | 3 | response-shape: 1, public-facet-ported: 2 |
| [macos-fuse-t/go-smb2/internal/smb2/lock_test.go](https://github.com/macos-fuse-t/go-smb2/blob/277a9300411249a881a05f7a910f5a83ae3395f2/internal/smb2/lock_test.go) | 2 | public-facet-ported: 2 |
| [macos-fuse-t/go-smb2/internal/smb2/packet_test.go](https://github.com/macos-fuse-t/go-smb2/blob/277a9300411249a881a05f7a910f5a83ae3395f2/internal/smb2/packet_test.go) | 1 | public-existing: 1 |
| [macos-fuse-t/go-smb2/internal/smb2/posix_test.go](https://github.com/macos-fuse-t/go-smb2/blob/277a9300411249a881a05f7a910f5a83ae3395f2/internal/smb2/posix_test.go) | 1 | retained-qualified-unsupported-feature: 1 |
| [macos-fuse-t/go-smb2/internal/spnego/spnego_test.go](https://github.com/macos-fuse-t/go-smb2/blob/277a9300411249a881a05f7a910f5a83ae3395f2/internal/spnego/spnego_test.go) | 6 | parameter-table: 3, retained-qualified-adapted-here: 3 |
| [macos-fuse-t/go-smb2/server/close_test.go](https://github.com/macos-fuse-t/go-smb2/blob/277a9300411249a881a05f7a910f5a83ae3395f2/server/close_test.go) | 3 | retained-qualified-adapted-here: 2, retained-qualified-unsupported-feature: 1 |
| [macos-fuse-t/go-smb2/server/conn_test.go](https://github.com/macos-fuse-t/go-smb2/blob/277a9300411249a881a05f7a910f5a83ae3395f2/server/conn_test.go) | 1 | public-facet-ported: 1 |
| [macos-fuse-t/go-smb2/server/delete_disposition_test.go](https://github.com/macos-fuse-t/go-smb2/blob/277a9300411249a881a05f7a910f5a83ae3395f2/server/delete_disposition_test.go) | 3 | retained-qualified-unsupported-feature: 2, existing-invariant-qualified: 1 |
| [macos-fuse-t/go-smb2/server/file_attributes_test.go](https://github.com/macos-fuse-t/go-smb2/blob/277a9300411249a881a05f7a910f5a83ae3395f2/server/file_attributes_test.go) | 2 | internal-api-or-primitive: 2 |
| [macos-fuse-t/go-smb2/server/info_fs_test.go](https://github.com/macos-fuse-t/go-smb2/blob/277a9300411249a881a05f7a910f5a83ae3395f2/server/info_fs_test.go) | 3 | retained-qualified-unsupported-feature: 1, response-shape: 1, retained-qualified-adapted-here: 1 |
| [macos-fuse-t/go-smb2/server/kdf_test.go](https://github.com/macos-fuse-t/go-smb2/blob/277a9300411249a881a05f7a910f5a83ae3395f2/server/kdf_test.go) | 1 | internal-api-or-primitive: 1 |
| [macos-fuse-t/go-smb2/server/locking_test.go](https://github.com/macos-fuse-t/go-smb2/blob/277a9300411249a881a05f7a910f5a83ae3395f2/server/locking_test.go) | 4 | existing-invariant-qualified: 4 |
| [macos-fuse-t/go-smb2/server/log_test.go](https://github.com/macos-fuse-t/go-smb2/blob/277a9300411249a881a05f7a910f5a83ae3395f2/server/log_test.go) | 1 | internal-api-or-primitive: 1 |
| [macos-fuse-t/go-smb2/server/posix_test.go](https://github.com/macos-fuse-t/go-smb2/blob/277a9300411249a881a05f7a910f5a83ae3395f2/server/posix_test.go) | 3 | retained-qualified-unsupported-feature: 3 |
| [macos-fuse-t/go-smb2/server/sign_test.go](https://github.com/macos-fuse-t/go-smb2/blob/277a9300411249a881a05f7a910f5a83ae3395f2/server/sign_test.go) | 1 | retained-qualified-adapted-here: 1 |
| [sonroyaalmerol/go-smb-server/smb/encryption/bench_test.go](https://github.com/sonroyaalmerol/go-smb-server/blob/d07dc723a2926177b4bc20c806d95cb2c3b1c70a/smb/encryption/bench_test.go) | 3 | internal-driver: 3 |
| [sonroyaalmerol/go-smb-server/smb/encryption/ccm_test.go](https://github.com/sonroyaalmerol/go-smb-server/blob/d07dc723a2926177b4bc20c806d95cb2c3b1c70a/smb/encryption/ccm_test.go) | 3 | internal-api-or-primitive: 1, retained-qualified-adapted-here: 2 |
| [sonroyaalmerol/go-smb-server/smb/kerberos/kerberos_test.go](https://github.com/sonroyaalmerol/go-smb-server/blob/d07dc723a2926177b4bc20c806d95cb2c3b1c70a/smb/kerberos/kerberos_test.go) | 9 | retained-qualified-external/platform-blocker: 9 |
| [sonroyaalmerol/go-smb-server/smb/ntlmssp/server_test.go](https://github.com/sonroyaalmerol/go-smb-server/blob/d07dc723a2926177b4bc20c806d95cb2c3b1c70a/smb/ntlmssp/server_test.go) | 3 | retained-qualified-adapted-here: 3 |
| [sonroyaalmerol/go-smb-server/smb/server/e2e_test.go](https://github.com/sonroyaalmerol/go-smb-server/blob/d07dc723a2926177b4bc20c806d95cb2c3b1c70a/smb/server/e2e_test.go) | 6 | existing-invariant-qualified: 5, retained-qualified-adapted-here: 1 |
| [sonroyaalmerol/go-smb-server/smb/server/integration_test.go](https://github.com/sonroyaalmerol/go-smb-server/blob/d07dc723a2926177b4bc20c806d95cb2c3b1c70a/smb/server/integration_test.go) | 2 | retained-qualified-adapted-here: 2 |
| [sonroyaalmerol/go-smb-server/smb/server/kerberos_e2e_test.go](https://github.com/sonroyaalmerol/go-smb-server/blob/d07dc723a2926177b4bc20c806d95cb2c3b1c70a/smb/server/kerberos_e2e_test.go) | 2 | retained-qualified-external/platform-blocker: 2 |
| [sonroyaalmerol/go-smb-server/smb/server/leak_test.go](https://github.com/sonroyaalmerol/go-smb-server/blob/d07dc723a2926177b4bc20c806d95cb2c3b1c70a/smb/server/leak_test.go) | 3 | retained-qualified-adapted-here: 1, internal-lifecycle: 1, internal-transport: 1 |
| [sonroyaalmerol/go-smb-server/smb/signing/bench_test.go](https://github.com/sonroyaalmerol/go-smb-server/blob/d07dc723a2926177b4bc20c806d95cb2c3b1c70a/smb/signing/bench_test.go) | 3 | internal-driver: 3 |
| [sonroyaalmerol/go-smb-server/smb/signing/signing_test.go](https://github.com/sonroyaalmerol/go-smb-server/blob/d07dc723a2926177b4bc20c806d95cb2c3b1c70a/smb/signing/signing_test.go) | 4 | internal-api-or-primitive: 3, retained-qualified-adapted-here: 1 |
| [sonroyaalmerol/go-smb-server/smb/wire/bench_test.go](https://github.com/sonroyaalmerol/go-smb-server/blob/d07dc723a2926177b4bc20c806d95cb2c3b1c70a/smb/wire/bench_test.go) | 5 | internal-driver: 5 |
| [sonroyaalmerol/go-smb-server/smb/wire/wire_test.go](https://github.com/sonroyaalmerol/go-smb-server/blob/d07dc723a2926177b4bc20c806d95cb2c3b1c70a/smb/wire/wire_test.go) | 8 | internal-api-or-primitive: 7, retained-qualified-adapted-here: 1 |
| [fiddyschmitt/portable-smb-server/internal/httpvfs/anyfs_test.go](https://github.com/fiddyschmitt/portable-smb-server/blob/107bb541fbb1c5e848c1b4ebb28f22117c17d523/internal/httpvfs/anyfs_test.go) | 3 | internal-api-or-primitive: 3 |
| [fiddyschmitt/portable-smb-server/internal/httpvfs/httpvfs_test.go](https://github.com/fiddyschmitt/portable-smb-server/blob/107bb541fbb1c5e848c1b4ebb28f22117c17d523/internal/httpvfs/httpvfs_test.go) | 6 | internal-api-or-primitive: 5, existing-invariant-qualified: 1 |
| [fiddyschmitt/portable-smb-server/internal/localfs/localfs_test.go](https://github.com/fiddyschmitt/portable-smb-server/blob/107bb541fbb1c5e848c1b4ebb28f22117c17d523/internal/localfs/localfs_test.go) | 5 | internal-api-or-primitive: 1, retained-qualified-adapted-here: 2, existing-invariant-qualified: 1, retained-qualified-normative-mismatch: 1 |
| [fiddyschmitt/portable-smb-server/internal/md4/md4_test.go](https://github.com/fiddyschmitt/portable-smb-server/blob/107bb541fbb1c5e848c1b4ebb28f22117c17d523/internal/md4/md4_test.go) | 2 | internal-api-or-primitive: 2 |
| [fiddyschmitt/portable-smb-server/internal/openapi/openapi_test.go](https://github.com/fiddyschmitt/portable-smb-server/blob/107bb541fbb1c5e848c1b4ebb28f22117c17d523/internal/openapi/openapi_test.go) | 2 | internal-api-or-primitive: 2 |
| [fiddyschmitt/portable-smb-server/internal/smb/aapl_test.go](https://github.com/fiddyschmitt/portable-smb-server/blob/107bb541fbb1c5e848c1b4ebb28f22117c17d523/internal/smb/aapl_test.go) | 3 | retained-qualified-unsupported-feature: 2, public-facet-ported: 1 |
| [fiddyschmitt/portable-smb-server/internal/smb/crypto_test.go](https://github.com/fiddyschmitt/portable-smb-server/blob/107bb541fbb1c5e848c1b4ebb28f22117c17d523/internal/smb/crypto_test.go) | 4 | internal-api-or-primitive: 2, internal-driver: 2 |
| [fiddyschmitt/portable-smb-server/internal/smb/lookup_test.go](https://github.com/fiddyschmitt/portable-smb-server/blob/107bb541fbb1c5e848c1b4ebb28f22117c17d523/internal/smb/lookup_test.go) | 1 | internal-api-or-primitive: 1 |
| [fiddyschmitt/portable-smb-server/internal/smb/readonly_test.go](https://github.com/fiddyschmitt/portable-smb-server/blob/107bb541fbb1c5e848c1b4ebb28f22117c17d523/internal/smb/readonly_test.go) | 1 | retained-qualified-adapted-here: 1 |
| [fiddyschmitt/portable-smb-server/internal/smb/server_test.go](https://github.com/fiddyschmitt/portable-smb-server/blob/107bb541fbb1c5e848c1b4ebb28f22117c17d523/internal/smb/server_test.go) | 1 | retained-qualified-normative-mismatch: 1 |
| [fiddyschmitt/portable-smb-server/internal/smb/smb_test.go](https://github.com/fiddyschmitt/portable-smb-server/blob/107bb541fbb1c5e848c1b4ebb28f22117c17d523/internal/smb/smb_test.go) | 24 | existing-invariant-qualified: 4, retained-qualified-adapted-here: 8, internal-api-or-primitive: 4, retained-qualified-normative-mismatch: 2, public-existing: 2, public-facet-ported: 3, internal-lifecycle: 1 |
| [fiddyschmitt/portable-smb-server/test/bench_loopback_test.go](https://github.com/fiddyschmitt/portable-smb-server/blob/107bb541fbb1c5e848c1b4ebb28f22117c17d523/test/bench_loopback_test.go) | 1 | retained-qualified-adapted-here: 1 |
| [fiddyschmitt/portable-smb-server/test/e2e_test.go](https://github.com/fiddyschmitt/portable-smb-server/blob/107bb541fbb1c5e848c1b4ebb28f22117c17d523/test/e2e_test.go) | 10 | internal-driver: 1, retained-qualified-adapted-here: 7, retained-qualified-unsupported-feature: 1, existing-invariant-qualified: 1 |
| [fiddyschmitt/portable-smb-server/test/rig/build_test.go](https://github.com/fiddyschmitt/portable-smb-server/blob/107bb541fbb1c5e848c1b4ebb28f22117c17d523/test/rig/build_test.go) | 3 | parameter-table: 2, internal-driver: 1 |
| [fiddyschmitt/portable-smb-server/test/rig/matrix_test.go](https://github.com/fiddyschmitt/portable-smb-server/blob/107bb541fbb1c5e848c1b4ebb28f22117c17d523/test/rig/matrix_test.go) | 32 | retained-qualified-external/platform-blocker: 1, parameter-table: 1, retained-qualified-adapted-here: 23, existing-invariant-qualified: 3, internal-api-or-primitive: 3, retained-qualified-unsupported-feature: 1 |
| [fiddyschmitt/portable-smb-server/test/rig/multiclient_test.go](https://github.com/fiddyschmitt/portable-smb-server/blob/107bb541fbb1c5e848c1b4ebb28f22117c17d523/test/rig/multiclient_test.go) | 1 | retained-qualified-adapted-here: 1 |
| [fiddyschmitt/portable-smb-server/test/rig/stress_test.go](https://github.com/fiddyschmitt/portable-smb-server/blob/107bb541fbb1c5e848c1b4ebb28f22117c17d523/test/rig/stress_test.go) | 1 | retained-qualified-external/platform-blocker: 1 |
| [fiddyschmitt/portable-smb-server/test/stress_e2e_test.go](https://github.com/fiddyschmitt/portable-smb-server/blob/107bb541fbb1c5e848c1b4ebb28f22117c17d523/test/stress_e2e_test.go) | 2 | retained-qualified-adapted-here: 2 |
| [fiddyschmitt/portable-smb-server/test/vfs_e2e_test.go](https://github.com/fiddyschmitt/portable-smb-server/blob/107bb541fbb1c5e848c1b4ebb28f22117c17d523/test/vfs_e2e_test.go) | 3 | internal-api-or-primitive: 3 |
| [CloudSoda/go-smb2/client_test.go](https://github.com/CloudSoda/go-smb2/blob/95be04a983b8770c7255d547aa02ee384e9882c7/client_test.go) | 3 | retained-qualified-client-only-semantics: 3 |
| [CloudSoda/go-smb2/conn_bench_test.go](https://github.com/CloudSoda/go-smb2/blob/95be04a983b8770c7255d547aa02ee384e9882c7/conn_bench_test.go) | 2 | internal-driver: 2 |
| [CloudSoda/go-smb2/conn_test.go](https://github.com/CloudSoda/go-smb2/blob/95be04a983b8770c7255d547aa02ee384e9882c7/conn_test.go) | 2 | retained-qualified-client-only-semantics: 1, retained-qualified-adapted-here: 1 |
| [CloudSoda/go-smb2/credit_books_test.go](https://github.com/CloudSoda/go-smb2/blob/95be04a983b8770c7255d547aa02ee384e9882c7/credit_books_test.go) | 2 | retained-qualified-client-only-semantics: 2 |
| [CloudSoda/go-smb2/credit_refund_test.go](https://github.com/CloudSoda/go-smb2/blob/95be04a983b8770c7255d547aa02ee384e9882c7/credit_refund_test.go) | 4 | retained-qualified-client-only-semantics: 4 |
| [CloudSoda/go-smb2/errors_test.go](https://github.com/CloudSoda/go-smb2/blob/95be04a983b8770c7255d547aa02ee384e9882c7/errors_test.go) | 1 | retained-qualified-client-only-semantics: 1 |
| [CloudSoda/go-smb2/example_test.go](https://github.com/CloudSoda/go-smb2/blob/95be04a983b8770c7255d547aa02ee384e9882c7/example_test.go) | 1 | internal-driver: 1 |
| [CloudSoda/go-smb2/filepath_test.go](https://github.com/CloudSoda/go-smb2/blob/95be04a983b8770c7255d547aa02ee384e9882c7/filepath_test.go) | 2 | retained-qualified-client-only-semantics: 2 |
| [CloudSoda/go-smb2/fscc_test.go](https://github.com/CloudSoda/go-smb2/blob/95be04a983b8770c7255d547aa02ee384e9882c7/fscc_test.go) | 1 | retained-qualified-client-only-semantics: 1 |
| [CloudSoda/go-smb2/internal/crypto/ccm/ccm_test.go](https://github.com/CloudSoda/go-smb2/blob/95be04a983b8770c7255d547aa02ee384e9882c7/internal/crypto/ccm/ccm_test.go) | 1 | retained-qualified-client-only-semantics: 1 |
| [CloudSoda/go-smb2/internal/crypto/cmac/cmac_test.go](https://github.com/CloudSoda/go-smb2/blob/95be04a983b8770c7255d547aa02ee384e9882c7/internal/crypto/cmac/cmac_test.go) | 1 | retained-qualified-client-only-semantics: 1 |
| [CloudSoda/go-smb2/internal/msrpc/msrpc_test.go](https://github.com/CloudSoda/go-smb2/blob/95be04a983b8770c7255d547aa02ee384e9882c7/internal/msrpc/msrpc_test.go) | 13 | retained-qualified-client-only-semantics: 13 |
| [CloudSoda/go-smb2/internal/ntlm/ntlm_test.go](https://github.com/CloudSoda/go-smb2/blob/95be04a983b8770c7255d547aa02ee384e9882c7/internal/ntlm/ntlm_test.go) | 8 | retained-qualified-adapted-here: 4, retained-qualified-client-only-semantics: 3, public-auth-acceptor: 1 |
| [CloudSoda/go-smb2/internal/smb2/fscc_test.go](https://github.com/CloudSoda/go-smb2/blob/95be04a983b8770c7255d547aa02ee384e9882c7/internal/smb2/fscc_test.go) | 4 | retained-qualified-client-only-semantics: 4 |
| [CloudSoda/go-smb2/internal/spnego/spnego_test.go](https://github.com/CloudSoda/go-smb2/blob/95be04a983b8770c7255d547aa02ee384e9882c7/internal/spnego/spnego_test.go) | 6 | parameter-table: 3, retained-qualified-adapted-here: 3 |
| [CloudSoda/go-smb2/internal/srvsvc/srvsvc_test.go](https://github.com/CloudSoda/go-smb2/blob/95be04a983b8770c7255d547aa02ee384e9882c7/internal/srvsvc/srvsvc_test.go) | 19 | retained-qualified-client-only-semantics: 19 |
| [CloudSoda/go-smb2/internal/utf16le/utf16le_test.go](https://github.com/CloudSoda/go-smb2/blob/95be04a983b8770c7255d547aa02ee384e9882c7/internal/utf16le/utf16le_test.go) | 4 | retained-qualified-client-only-semantics: 4 |
| [CloudSoda/go-smb2/kdf_test.go](https://github.com/CloudSoda/go-smb2/blob/95be04a983b8770c7255d547aa02ee384e9882c7/kdf_test.go) | 1 | retained-qualified-client-only-semantics: 1 |
| [CloudSoda/go-smb2/logoff_test.go](https://github.com/CloudSoda/go-smb2/blob/95be04a983b8770c7255d547aa02ee384e9882c7/logoff_test.go) | 2 | retained-qualified-client-only-semantics: 2 |
| [CloudSoda/go-smb2/path_test.go](https://github.com/CloudSoda/go-smb2/blob/95be04a983b8770c7255d547aa02ee384e9882c7/path_test.go) | 6 | parameter-table: 3, retained-qualified-client-only-semantics: 3 |
| [CloudSoda/go-smb2/readdirplus_test.go](https://github.com/CloudSoda/go-smb2/blob/95be04a983b8770c7255d547aa02ee384e9882c7/readdirplus_test.go) | 2 | retained-qualified-client-only-semantics: 2 |
| [CloudSoda/go-smb2/shares_test.go](https://github.com/CloudSoda/go-smb2/blob/95be04a983b8770c7255d547aa02ee384e9882c7/shares_test.go) | 1 | retained-qualified-client-only-semantics: 1 |
| [CloudSoda/go-smb2/sign_test.go](https://github.com/CloudSoda/go-smb2/blob/95be04a983b8770c7255d547aa02ee384e9882c7/sign_test.go) | 1 | retained-qualified-adapted-here: 1 |
| [CloudSoda/go-smb2/smb2_fs_test.go](https://github.com/CloudSoda/go-smb2/blob/95be04a983b8770c7255d547aa02ee384e9882c7/smb2_fs_test.go) | 2 | retained-qualified-client-only-semantics: 2 |
| [CloudSoda/go-smb2/smb2_test.go](https://github.com/CloudSoda/go-smb2/blob/95be04a983b8770c7255d547aa02ee384e9882c7/smb2_test.go) | 20 | internal-driver: 1, retained-qualified-client-only-semantics: 10, existing-invariant-qualified: 1, retained-qualified-adapted-here: 4, retained-qualified-unsupported-feature: 3, public-facet-ported: 1 |
| [hirochachacha/go-smb2/auth/credentials_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/auth/credentials_test.go) | 6 | retained-qualified-client-only-semantics: 6 |
| [hirochachacha/go-smb2/auth/initiator_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/auth/initiator_test.go) | 10 | retained-qualified-client-only-semantics: 9, internal-driver: 1 |
| [hirochachacha/go-smb2/auth/kerberos_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/auth/kerberos_test.go) | 8 | retained-qualified-client-only-semantics: 8 |
| [hirochachacha/go-smb2/client/client_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/client/client_test.go) | 48 | client-api-or-unavailable-facet: 48 |
| [hirochachacha/go-smb2/client/file_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/client/file_test.go) | 17 | client-api-or-unavailable-facet: 17 |
| [hirochachacha/go-smb2/client/fs_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/client/fs_test.go) | 11 | client-api-or-unavailable-facet: 10, internal-driver: 1 |
| [hirochachacha/go-smb2/client/operations_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/client/operations_test.go) | 17 | client-api-or-unavailable-facet: 17 |
| [hirochachacha/go-smb2/client/referrals_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/client/referrals_test.go) | 43 | client-api-or-unavailable-facet: 42, internal-driver: 1 |
| [hirochachacha/go-smb2/client/session_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/client/session_test.go) | 11 | client-api-or-unavailable-facet: 11 |
| [hirochachacha/go-smb2/dfs/client_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/dfs/client_test.go) | 3 | client-api-or-unavailable-facet: 3 |
| [hirochachacha/go-smb2/dialer_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/dialer_test.go) | 9 | retained-qualified-client-only-semantics: 9 |
| [hirochachacha/go-smb2/file_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/file_test.go) | 134 | retained-qualified-client-only-semantics: 134 |
| [hirochachacha/go-smb2/fs_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/fs_test.go) | 7 | retained-qualified-client-only-semantics: 7 |
| [hirochachacha/go-smb2/internal/crypto/ccm/benchmark_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/internal/crypto/ccm/benchmark_test.go) | 1 | internal-driver: 1 |
| [hirochachacha/go-smb2/internal/crypto/ccm/ccm_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/internal/crypto/ccm/ccm_test.go) | 6 | retained-qualified-client-only-semantics: 6 |
| [hirochachacha/go-smb2/internal/crypto/cmac/benchmark_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/internal/crypto/cmac/benchmark_test.go) | 1 | internal-driver: 1 |
| [hirochachacha/go-smb2/internal/crypto/cmac/cmac_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/internal/crypto/cmac/cmac_test.go) | 1 | retained-qualified-client-only-semantics: 1 |
| [hirochachacha/go-smb2/internal/dfsc/dfsc_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/internal/dfsc/dfsc_test.go) | 29 | client-api-or-unavailable-facet: 29 |
| [hirochachacha/go-smb2/internal/directory/directory_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/internal/directory/directory_test.go) | 3 | client-api-or-unavailable-facet: 3 |
| [hirochachacha/go-smb2/internal/erref/ntstatus_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/internal/erref/ntstatus_test.go) | 1 | retained-qualified-client-only-semantics: 1 |
| [hirochachacha/go-smb2/internal/msrpc/msrpc_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/internal/msrpc/msrpc_test.go) | 26 | retained-qualified-client-only-semantics: 26 |
| [hirochachacha/go-smb2/internal/ntlm/ntlm_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/internal/ntlm/ntlm_test.go) | 38 | retained-qualified-adapted-here: 4, retained-qualified-client-only-semantics: 28, public-auth-acceptor: 1, client-initiator: 1, parameter-table: 1, public-facet-ported: 3 |
| [hirochachacha/go-smb2/internal/path/fs_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/internal/path/fs_test.go) | 3 | client-api-or-unavailable-facet: 3 |
| [hirochachacha/go-smb2/internal/path/path_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/internal/path/path_test.go) | 20 | parameter-table: 3, client-api-or-unavailable-facet: 17 |
| [hirochachacha/go-smb2/internal/path/symlink_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/internal/path/symlink_test.go) | 4 | client-api-or-unavailable-facet: 4 |
| [hirochachacha/go-smb2/internal/spnego/spnego_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/internal/spnego/spnego_test.go) | 7 | parameter-table: 3, retained-qualified-adapted-here: 3, retained-qualified-client-only-semantics: 1 |
| [hirochachacha/go-smb2/internal/utf16le/utf16le_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/internal/utf16le/utf16le_test.go) | 4 | retained-qualified-client-only-semantics: 2, internal-driver: 2 |
| [hirochachacha/go-smb2/notify/notify_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/notify/notify_test.go) | 3 | retained-qualified-client-only-semantics: 3 |
| [hirochachacha/go-smb2/security/ace_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/security/ace_test.go) | 2 | client-api-or-unavailable-facet: 2 |
| [hirochachacha/go-smb2/security/sddl_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/security/sddl_test.go) | 22 | internal-driver: 1, client-api-or-unavailable-facet: 21 |
| [hirochachacha/go-smb2/security/security_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/security/security_test.go) | 13 | client-api-or-unavailable-facet: 13 |
| [hirochachacha/go-smb2/security/sid_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/security/sid_test.go) | 6 | client-api-or-unavailable-facet: 6 |
| [hirochachacha/go-smb2/session_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/session_test.go) | 27 | retained-qualified-client-only-semantics: 27 |
| [hirochachacha/go-smb2/share_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/share_test.go) | 100 | retained-qualified-client-only-semantics: 100 |
| [hirochachacha/go-smb2/smb2_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/smb2_test.go) | 56 | internal-driver: 8, retained-qualified-adapted-here: 18, existing-invariant-qualified: 6, retained-qualified-unsupported-feature: 4, retained-qualified-client-only-semantics: 18, public-facet-ported: 1, retained-qualified-external/platform-blocker: 1 |
| [hirochachacha/go-smb2/transport_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/transport_test.go) | 4 | retained-qualified-client-only-semantics: 4 |
| [hirochachacha/go-smb2/user/client_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/user/client_test.go) | 7 | client-api-or-unavailable-facet: 7 |
| [hirochachacha/go-smb2/x/protocol/aapl_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/protocol/aapl_test.go) | 1 | client-protocol-engine: 1 |
| [hirochachacha/go-smb2/x/protocol/channel_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/protocol/channel_test.go) | 15 | client-protocol-engine: 15 |
| [hirochachacha/go-smb2/x/protocol/compound_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/protocol/compound_test.go) | 5 | client-protocol-engine: 5 |
| [hirochachacha/go-smb2/x/protocol/compression_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/protocol/compression_test.go) | 10 | client-protocol-engine: 10 |
| [hirochachacha/go-smb2/x/protocol/conn_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/protocol/conn_test.go) | 86 | client-protocol-engine: 86 |
| [hirochachacha/go-smb2/x/protocol/credit_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/protocol/credit_test.go) | 34 | client-protocol-engine: 34 |
| [hirochachacha/go-smb2/x/protocol/dialer_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/protocol/dialer_test.go) | 6 | client-protocol-engine: 6 |
| [hirochachacha/go-smb2/x/protocol/encrypted_io_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/protocol/encrypted_io_test.go) | 2 | internal-driver: 2 |
| [hirochachacha/go-smb2/x/protocol/errors_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/protocol/errors_test.go) | 6 | client-protocol-engine: 6 |
| [hirochachacha/go-smb2/x/protocol/kdf_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/protocol/kdf_test.go) | 1 | client-protocol-engine: 1 |
| [hirochachacha/go-smb2/x/protocol/nonce_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/protocol/nonce_test.go) | 3 | client-protocol-engine: 3 |
| [hirochachacha/go-smb2/x/protocol/payload_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/protocol/payload_test.go) | 4 | client-protocol-engine: 4 |
| [hirochachacha/go-smb2/x/protocol/request_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/protocol/request_test.go) | 23 | client-protocol-engine: 23 |
| [hirochachacha/go-smb2/x/protocol/response_decode_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/protocol/response_decode_test.go) | 4 | client-protocol-engine: 4 |
| [hirochachacha/go-smb2/x/protocol/response_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/protocol/response_test.go) | 7 | client-protocol-engine: 7 |
| [hirochachacha/go-smb2/x/protocol/response_validation_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/protocol/response_validation_test.go) | 14 | client-protocol-engine: 14 |
| [hirochachacha/go-smb2/x/protocol/session_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/protocol/session_test.go) | 36 | client-protocol-engine: 36 |
| [hirochachacha/go-smb2/x/protocol/signer_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/protocol/signer_test.go) | 10 | client-protocol-engine: 10 |
| [hirochachacha/go-smb2/x/protocol/signing_bench_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/protocol/signing_bench_test.go) | 2 | internal-driver: 2 |
| [hirochachacha/go-smb2/x/protocol/spnego_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/protocol/spnego_test.go) | 5 | client-protocol-engine: 5 |
| [hirochachacha/go-smb2/x/protocol/symlink_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/protocol/symlink_test.go) | 9 | client-protocol-engine: 9 |
| [hirochachacha/go-smb2/x/protocol/transport_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/protocol/transport_test.go) | 24 | client-protocol-engine: 24 |
| [hirochachacha/go-smb2/x/protocol/tree_conn_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/protocol/tree_conn_test.go) | 17 | client-protocol-engine: 17 |
| [hirochachacha/go-smb2/x/wire/cmd_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/wire/cmd_test.go) | 1 | retained-qualified-client-only-semantics: 1 |
| [hirochachacha/go-smb2/x/wire/const_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/wire/const_test.go) | 2 | retained-qualified-client-only-semantics: 2 |
| [hirochachacha/go-smb2/x/wire/dtyp_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/wire/dtyp_test.go) | 11 | retained-qualified-client-only-semantics: 11 |
| [hirochachacha/go-smb2/x/wire/fscc_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/wire/fscc_test.go) | 54 | response-rule-not-decoder-port: 54 |
| [hirochachacha/go-smb2/x/wire/fuzz_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/wire/fuzz_test.go) | 6 | internal-driver: 2, retained-qualified-client-only-semantics: 4 |
| [hirochachacha/go-smb2/x/wire/guid_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/wire/guid_test.go) | 1 | retained-qualified-client-only-semantics: 1 |
| [hirochachacha/go-smb2/x/wire/packet_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/wire/packet_test.go) | 8 | retained-qualified-client-only-semantics: 8 |
| [hirochachacha/go-smb2/x/wire/request_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/wire/request_test.go) | 22 | public-request-group: 10, source-strictness: 1, public-facet-ported: 8, helper-width-versus-wire-width: 1, source-partial: 1, unsupported-rdma: 1 |
| [hirochachacha/go-smb2/x/wire/response_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/wire/response_test.go) | 35 | response-rule-not-decoder-port: 35 |
| [hirochachacha/go-smb2/x/wire/smb2_test.go](https://github.com/hirochachacha/go-smb2/blob/7f69f65878329522ceb556435bdeb3cde6552656/x/wire/smb2_test.go) | 5 | retained-qualified-client-only-semantics: 4, source-partial: 1 |

| [sonroyaalmerol/go-smb-server/smb/server/mem_vfs_test.go](https://github.com/sonroyaalmerol/go-smb-server/blob/d07dc723a2926177b4bc20c806d95cb2c3b1c70a/smb/server/mem_vfs_test.go) | 0 | helper-only in-memory VFS fixture; no Test entry or independent public assertion |

All 176 inventoried Microsoft test files and every entry’s reachable helper/checker references are included. Source-only setup/assertion/event calls remain provenance, not ports. Common portable subfacets in optional-feature graphs use the operation routes below; the graph’s unavailable persistent/CA, application-fencing, resilient, directory-lease or SOFS requirement is not claimed passed. An unsupported graph does not exclude its independent ordinary file/packet/error facet.

| Pinned Microsoft source file | Entry methods | Distinct reachable call signatures |
|---|---:|---:|
| [Auth/TestSuite/Authentication/EncryptionAuthentication.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/Auth/TestSuite/Authentication/EncryptionAuthentication.cs) | 2 | 11 |
| [Auth/TestSuite/Authentication/KerberosAuthentication/KerberosAuthentication.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/Auth/TestSuite/Authentication/KerberosAuthentication/KerberosAuthentication.cs) | 18 | 16 |
| [Auth/TestSuite/Authentication/NtlmAuthentication/NtlmAuthentication.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/Auth/TestSuite/Authentication/NtlmAuthentication/NtlmAuthentication.cs) | 1 | 5 |
| [Auth/TestSuite/Authorization/CBACTest.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/Auth/TestSuite/Authorization/CBACTest.cs) | 11 | 0 |
| [Auth/TestSuite/Authorization/FilePermissionTest.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/Auth/TestSuite/Authorization/FilePermissionTest.cs) | 6 | 2 |
| [Auth/TestSuite/Authorization/FolderPermissionTest.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/Auth/TestSuite/Authorization/FolderPermissionTest.cs) | 6 | 2 |
| [Auth/TestSuite/Authorization/SharePermissionTest.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/Auth/TestSuite/Authorization/SharePermissionTest.cs) | 7 | 12 |
| [FSA/TestSuite/AlternateDataStream/AlternateDataStream_CreateStream.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/AlternateDataStream/AlternateDataStream_CreateStream.cs) | 2 | 0 |
| [FSA/TestSuite/AlternateDataStream/AlternateDataStream_DeleteStream.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/AlternateDataStream/AlternateDataStream_DeleteStream.cs) | 2 | 0 |
| [FSA/TestSuite/AlternateDataStream/AlternateDataStream_FSCTL_GET_COMPRESSION.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/AlternateDataStream/AlternateDataStream_FSCTL_GET_COMPRESSION.cs) | 2 | 8 |
| [FSA/TestSuite/AlternateDataStream/AlternateDataStream_FSCTL_GET_INTEGRITY_INFORMATION.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/AlternateDataStream/AlternateDataStream_FSCTL_GET_INTEGRITY_INFORMATION.cs) | 2 | 4 |
| [FSA/TestSuite/AlternateDataStream/AlternateDataStream_FSCTL_QUERY_ALLOCATED_RANGES.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/AlternateDataStream/AlternateDataStream_FSCTL_QUERY_ALLOCATED_RANGES.cs) | 2 | 4 |
| [FSA/TestSuite/AlternateDataStream/AlternateDataStream_FSCTL_SET_COMPRESSION.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/AlternateDataStream/AlternateDataStream_FSCTL_SET_COMPRESSION.cs) | 2 | 5 |
| [FSA/TestSuite/AlternateDataStream/AlternateDataStream_FSCTL_SET_ZERO_DATA.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/AlternateDataStream/AlternateDataStream_FSCTL_SET_ZERO_DATA.cs) | 2 | 3 |
| [FSA/TestSuite/AlternateDataStream/AlternateDataStream_FileInfo_Query_FileAccessInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/AlternateDataStream/AlternateDataStream_FileInfo_Query_FileAccessInformation.cs) | 2 | 2 |
| [FSA/TestSuite/AlternateDataStream/AlternateDataStream_FileInfo_Query_FileBasicInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/AlternateDataStream/AlternateDataStream_FileInfo_Query_FileBasicInformation.cs) | 2 | 2 |
| [FSA/TestSuite/AlternateDataStream/AlternateDataStream_FileInfo_Query_FileCompressionInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/AlternateDataStream/AlternateDataStream_FileInfo_Query_FileCompressionInformation.cs) | 2 | 8 |
| [FSA/TestSuite/AlternateDataStream/AlternateDataStream_FileInfo_Query_FileNetworkOpenInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/AlternateDataStream/AlternateDataStream_FileInfo_Query_FileNetworkOpenInformation.cs) | 2 | 2 |
| [FSA/TestSuite/AlternateDataStream/AlternateDataStream_FileInfo_Query_FileStandardInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/AlternateDataStream/AlternateDataStream_FileInfo_Query_FileStandardInformation.cs) | 2 | 3 |
| [FSA/TestSuite/AlternateDataStream/AlternateDataStream_FileInfo_Set_FileEaInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/AlternateDataStream/AlternateDataStream_FileInfo_Set_FileEaInformation.cs) | 2 | 2 |
| [FSA/TestSuite/AlternateDataStream/AlternateDataStream_FileInfo_Set_FileShortNameInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/AlternateDataStream/AlternateDataStream_FileInfo_Set_FileShortNameInformation.cs) | 2 | 4 |
| [FSA/TestSuite/AlternateDataStream/AlternateDataStream_FileInfo_Set_FileValidDataLengthInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/AlternateDataStream/AlternateDataStream_FileInfo_Set_FileValidDataLengthInformation.cs) | 2 | 2 |
| [FSA/TestSuite/AlternateDataStream/AlternateDataStream_ListStreams.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/AlternateDataStream/AlternateDataStream_ListStreams.cs) | 2 | 0 |
| [FSA/TestSuite/AlternateDataStream/AlternateDataStream_LockAndUnlock.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/AlternateDataStream/AlternateDataStream_LockAndUnlock.cs) | 2 | 4 |
| [FSA/TestSuite/AlternateDataStream/AlternateDataStream_RenameStream.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/AlternateDataStream/AlternateDataStream_RenameStream.cs) | 2 | 3 |
| [FSA/TestSuite/AlternateDataStream/AlternateDataStream_ShareAccess.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/AlternateDataStream/AlternateDataStream_ShareAccess.cs) | 3 | 7 |
| [FSA/TestSuite/AlternateDataStream/AlternateDataStream_WriteAndRead.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/AlternateDataStream/AlternateDataStream_WriteAndRead.cs) | 2 | 8 |
| [FSA/TestSuite/CommonAlgorithm/Algorithm_Noting_FileAccessed.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/CommonAlgorithm/Algorithm_Noting_FileAccessed.cs) | 2 | 6 |
| [FSA/TestSuite/CommonAlgorithm/Algorithm_Noting_FileModified.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/CommonAlgorithm/Algorithm_Noting_FileModified.cs) | 8 | 7 |
| [FSA/TestSuite/CreateFile/CreateFile_BackSlash.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/CreateFile/CreateFile_BackSlash.cs) | 3 | 7 |
| [FSA/TestSuite/CreateFile/CreateFile_FindAllFiles.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/CreateFile/CreateFile_FindAllFiles.cs) | 4 | 8 |
| [FSA/TestSuite/CreateFile/CreateFile_InvalidColon.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/CreateFile/CreateFile_InvalidColon.cs) | 2 | 4 |
| [FSA/TestSuite/CreateFile/CreateFile_InvalidStreamName.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/CreateFile/CreateFile_InvalidStreamName.cs) | 1 | 4 |
| [FSA/TestSuite/FileAccess/FileAccess_OpenExistingFile.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileAccess/FileAccess_OpenExistingFile.cs) | 2 | 7 |
| [FSA/TestSuite/FileAccess/FileAccess_OpenNamedPipe.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileAccess/FileAccess_OpenNamedPipe.cs) | 7 | 10 |
| [FSA/TestSuite/FileInformation/FileInfo_Query_FileAccessInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileInformation/FileInfo_Query_FileAccessInformation.cs) | 1 | 5 |
| [FSA/TestSuite/FileInformation/FileInfo_Query_FileAlignmentInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileInformation/FileInfo_Query_FileAlignmentInformation.cs) | 1 | 4 |
| [FSA/TestSuite/FileInformation/FileInfo_Query_FileAlternateNameInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileInformation/FileInfo_Query_FileAlternateNameInformation.cs) | 1 | 4 |
| [FSA/TestSuite/FileInformation/FileInfo_Query_FileAttributeTagInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileInformation/FileInfo_Query_FileAttributeTagInformation.cs) | 2 | 6 |
| [FSA/TestSuite/FileInformation/FileInfo_Query_FileBasicInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileInformation/FileInfo_Query_FileBasicInformation.cs) | 2 | 4 |
| [FSA/TestSuite/FileInformation/FileInfo_Query_FileBasicInformation_CreationTime.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileInformation/FileInfo_Query_FileBasicInformation_CreationTime.cs) | 8 | 7 |
| [FSA/TestSuite/FileInformation/FileInfo_Query_FileBothDirectoryInformation_CreationTime.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileInformation/FileInfo_Query_FileBothDirectoryInformation_CreationTime.cs) | 1 | 3 |
| [FSA/TestSuite/FileInformation/FileInfo_Query_FileCompressionInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileInformation/FileInfo_Query_FileCompressionInformation.cs) | 2 | 7 |
| [FSA/TestSuite/FileInformation/FileInfo_Query_FileEaInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileInformation/FileInfo_Query_FileEaInformation.cs) | 2 | 6 |
| [FSA/TestSuite/FileInformation/FileInfo_Query_FileFullDirectoryInformation_CreationTime.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileInformation/FileInfo_Query_FileFullDirectoryInformation_CreationTime.cs) | 1 | 1 |
| [FSA/TestSuite/FileInformation/FileInfo_Query_FileFullEaInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileInformation/FileInfo_Query_FileFullEaInformation.cs) | 2 | 6 |
| [FSA/TestSuite/FileInformation/FileInfo_Query_FileIdGlobalTxDirectoryInformation_CreationTime.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileInformation/FileInfo_Query_FileIdGlobalTxDirectoryInformation_CreationTime.cs) | 1 | 2 |
| [FSA/TestSuite/FileInformation/FileInfo_Query_FileIdInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileInformation/FileInfo_Query_FileIdInformation.cs) | 2 | 5 |
| [FSA/TestSuite/FileInformation/FileInfo_Query_FileInternalInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileInformation/FileInfo_Query_FileInternalInformation.cs) | 1 | 4 |
| [FSA/TestSuite/FileInformation/FileInfo_Query_FileModeInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileInformation/FileInfo_Query_FileModeInformation.cs) | 1 | 4 |
| [FSA/TestSuite/FileInformation/FileInfo_Query_FileNetworkOpenInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileInformation/FileInfo_Query_FileNetworkOpenInformation.cs) | 2 | 4 |
| [FSA/TestSuite/FileInformation/FileInfo_Query_FileNormalizedNameInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileInformation/FileInfo_Query_FileNormalizedNameInformation.cs) | 2 | 2 |
| [FSA/TestSuite/FileInformation/FileInfo_Query_FilePositionInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileInformation/FileInfo_Query_FilePositionInformation.cs) | 1 | 6 |
| [FSA/TestSuite/FileInformation/FileInfo_Set_FileBasicInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileInformation/FileInfo_Set_FileBasicInformation.cs) | 10 | 14 |
| [FSA/TestSuite/FileInformation/FileInfo_Set_FileBasicInformation_Timestamp_MinusOne.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileInformation/FileInfo_Set_FileBasicInformation_Timestamp_MinusOne.cs) | 8 | 6 |
| [FSA/TestSuite/FileInformation/FileInfo_Set_FileBasicInformation_Timestamp_MinusTwo.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileInformation/FileInfo_Set_FileBasicInformation_Timestamp_MinusTwo.cs) | 15 | 5 |
| [FSA/TestSuite/FileInformation/FileInfo_Set_FileBasicInformation_Timestamp_Zero.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileInformation/FileInfo_Set_FileBasicInformation_Timestamp_Zero.cs) | 8 | 2 |
| [FSA/TestSuite/FileInformation/FileInfo_Set_FileDispositionInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileInformation/FileInfo_Set_FileDispositionInformation.cs) | 4 | 6 |
| [FSA/TestSuite/FileInformation/FileInfo_Set_FileEaInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileInformation/FileInfo_Set_FileEaInformation.cs) | 2 | 3 |
| [FSA/TestSuite/FileInformation/FileInfo_Set_FileFullEaInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileInformation/FileInfo_Set_FileFullEaInformation.cs) | 2 | 5 |
| [FSA/TestSuite/FileInformation/FileInfo_Set_FileLinkInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileInformation/FileInfo_Set_FileLinkInformation.cs) | 2 | 9 |
| [FSA/TestSuite/FileInformation/FileInfo_Set_FileRenameInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileInformation/FileInfo_Set_FileRenameInformation.cs) | 3 | 8 |
| [FSA/TestSuite/FileInformation/FileInfo_Set_FileShortNameInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileInformation/FileInfo_Set_FileShortNameInformation.cs) | 2 | 5 |
| [FSA/TestSuite/FileInformation/FileInfo_Set_FileValidDataLengthInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/FileInformation/FileInfo_Set_FileValidDataLengthInformation.cs) | 2 | 5 |
| [FSA/TestSuite/QueryDirectory/QueryDirectoryTestCases.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/QueryDirectory/QueryDirectoryTestCases.cs) | 14 | 19 |
| [FSA/TestSuite/QueryDirectory/QueryDirectory_FileNameInExpression_FileBothDirectoryInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/QueryDirectory/QueryDirectory_FileNameInExpression_FileBothDirectoryInformation.cs) | 7 | 0 |
| [FSA/TestSuite/QueryDirectory/QueryDirectory_FileNameInExpression_FileDirectoryInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/QueryDirectory/QueryDirectory_FileNameInExpression_FileDirectoryInformation.cs) | 7 | 0 |
| [FSA/TestSuite/QueryDirectory/QueryDirectory_FileNameInExpression_FileFullDirectoryInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/QueryDirectory/QueryDirectory_FileNameInExpression_FileFullDirectoryInformation.cs) | 7 | 0 |
| [FSA/TestSuite/QueryDirectory/QueryDirectory_FileNameInExpression_FileIdBothDirectoryInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/QueryDirectory/QueryDirectory_FileNameInExpression_FileIdBothDirectoryInformation.cs) | 7 | 0 |
| [FSA/TestSuite/QueryDirectory/QueryDirectory_FileNameInExpression_FileIdFullDirectoryInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/QueryDirectory/QueryDirectory_FileNameInExpression_FileIdFullDirectoryInformation.cs) | 7 | 0 |
| [FSA/TestSuite/QueryDirectory/QueryDirectory_FileNameInExpression_FileNamesInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSA/TestSuite/QueryDirectory/QueryDirectory_FileNameInExpression_FileNamesInformation.cs) | 7 | 0 |
| [FSAModel/TestSuite/CloseFileTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSAModel/TestSuite/CloseFileTestCase.cs) | 1 | 4 |
| [FSAModel/TestSuite/CreateFileTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSAModel/TestSuite/CreateFileTestCase.cs) | 25 | 29 |
| [FSAModel/TestSuite/FlushCachedDataTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSAModel/TestSuite/FlushCachedDataTestCase.cs) | 1 | 4 |
| [FSAModel/TestSuite/QueryDirectoryTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSAModel/TestSuite/QueryDirectoryTestCase.cs) | 20 | 31 |
| [FSAModel/TestSuite/QueryFileInformationTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSAModel/TestSuite/QueryFileInformationTestCase.cs) | 44 | 47 |
| [FSAModel/TestSuite/ReadFileTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSAModel/TestSuite/ReadFileTestCase.cs) | 3 | 10 |
| [FSAModel/TestSuite/SetFileAllocOrObjIdInformationTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSAModel/TestSuite/SetFileAllocOrObjIdInformationTestCase.cs) | 6 | 8 |
| [FSAModel/TestSuite/SetFileBasicInformationTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSAModel/TestSuite/SetFileBasicInformationTestCase.cs) | 8 | 10 |
| [FSAModel/TestSuite/SetFileDispositionInformationTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSAModel/TestSuite/SetFileDispositionInformationTestCase.cs) | 2 | 4 |
| [FSAModel/TestSuite/SetFileEndOfFileInformationTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSAModel/TestSuite/SetFileEndOfFileInformationTestCase.cs) | 4 | 6 |
| [FSAModel/TestSuite/SetFileFullEaInformationTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSAModel/TestSuite/SetFileFullEaInformationTestCase.cs) | 4 | 6 |
| [FSAModel/TestSuite/SetFileLinkInformationTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSAModel/TestSuite/SetFileLinkInformationTestCase.cs) | 4 | 7 |
| [FSAModel/TestSuite/SetFileModeInformationTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSAModel/TestSuite/SetFileModeInformationTestCase.cs) | 4 | 6 |
| [FSAModel/TestSuite/SetFilePositionInformationTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSAModel/TestSuite/SetFilePositionInformationTestCase.cs) | 6 | 8 |
| [FSAModel/TestSuite/SetFileRenameInformationTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSAModel/TestSuite/SetFileRenameInformationTestCase.cs) | 9 | 12 |
| [FSAModel/TestSuite/SetFileShortNameInformationTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSAModel/TestSuite/SetFileShortNameInformationTestCase.cs) | 5 | 8 |
| [FSAModel/TestSuite/SetFileStreamRenameInformationTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSAModel/TestSuite/SetFileStreamRenameInformationTestCase.cs) | 35 | 57 |
| [FSAModel/TestSuite/SetFileValidDataLengthInformationTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSAModel/TestSuite/SetFileValidDataLengthInformationTestCase.cs) | 2 | 5 |
| [FSAModel/TestSuite/WriteFileTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/FSAModel/TestSuite/WriteFileTestCase.cs) | 1 | 6 |
| [SMB2/TestSuite/AppInstanceId/AppInstanceIdBasic.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/AppInstanceId/AppInstanceIdBasic.cs) | 4 | 15 |
| [SMB2/TestSuite/AppInstanceId/AppInstanceIdWithEncryption.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/AppInstanceId/AppInstanceIdWithEncryption.cs) | 3 | 8 |
| [SMB2/TestSuite/AppInstanceId/AppInstanceIdWithLeasing.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/AppInstanceId/AppInstanceIdWithLeasing.cs) | 2 | 14 |
| [SMB2/TestSuite/AppInstanceId/AppInstanceIdWithLock.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/AppInstanceId/AppInstanceIdWithLock.cs) | 1 | 18 |
| [SMB2/TestSuite/AppInstanceId/AppInstanceVersion.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/AppInstanceId/AppInstanceVersion.cs) | 7 | 14 |
| [SMB2/TestSuite/Basic/MultiCredit.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/Basic/MultiCredit.cs) | 1 | 11 |
| [SMB2/TestSuite/Basic/SMB2Basic.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/Basic/SMB2Basic.cs) | 32 | 80 |
| [SMB2/TestSuite/Compound/Compound.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/Compound/Compound.cs) | 4 | 10 |
| [SMB2/TestSuite/Compression/CompressionTest.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/Compression/CompressionTest.cs) | 17 | 14 |
| [SMB2/TestSuite/Compression/CompressionTestForChained.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/Compression/CompressionTestForChained.cs) | 15 | 0 |
| [SMB2/TestSuite/Compression/CompressionTestForUnchained.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/Compression/CompressionTestForUnchained.cs) | 2 | 2 |
| [SMB2/TestSuite/CreateClose/CreateClose.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/CreateClose/CreateClose.cs) | 10 | 7 |
| [SMB2/TestSuite/DurableHandle/DurableHandle.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/DurableHandle/DurableHandle.cs) | 17 | 18 |
| [SMB2/TestSuite/DurableHandle/DurableHandleV2.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/DurableHandle/DurableHandleV2.cs) | 21 | 33 |
| [SMB2/TestSuite/Encryption/Encryption.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/Encryption/Encryption.cs) | 7 | 12 |
| [SMB2/TestSuite/HVRS/MS-FSA_Clarification.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/HVRS/MS-FSA_Clarification.cs) | 5 | 27 |
| [SMB2/TestSuite/HVRS/MS-SMB2_Clarification.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/HVRS/MS-SMB2_Clarification.cs) | 3 | 12 |
| [SMB2/TestSuite/IOCTL/CopyOffload.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/IOCTL/CopyOffload.cs) | 2 | 21 |
| [SMB2/TestSuite/IOCTL/EnumerateSnapshots.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/IOCTL/EnumerateSnapshots.cs) | 1 | 10 |
| [SMB2/TestSuite/IOCTL/NetworkInterfaceInfo.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/IOCTL/NetworkInterfaceInfo.cs) | 4 | 13 |
| [SMB2/TestSuite/IOCTL/SetGetIntegrityInformation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/IOCTL/SetGetIntegrityInformation.cs) | 1 | 10 |
| [SMB2/TestSuite/IOCTL/ValidateNegotiateInfo.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/IOCTL/ValidateNegotiateInfo.cs) | 8 | 7 |
| [SMB2/TestSuite/Leasing/DirectoryLeasing.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/Leasing/DirectoryLeasing.cs) | 9 | 14 |
| [SMB2/TestSuite/Leasing/DirectoryLeasingExtendedTest.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/Leasing/DirectoryLeasingExtendedTest.cs) | 9 | 19 |
| [SMB2/TestSuite/Leasing/FileLeasing.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/Leasing/FileLeasing.cs) | 5 | 18 |
| [SMB2/TestSuite/MultipleChannel/MultipleChannelBasic.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/MultipleChannel/MultipleChannelBasic.cs) | 7 | 18 |
| [SMB2/TestSuite/MultipleChannel/MultipleChannelWithEncryption.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/MultipleChannel/MultipleChannelWithEncryption.cs) | 3 | 6 |
| [SMB2/TestSuite/MultipleChannel/MultipleChannelWithLeasing.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/MultipleChannel/MultipleChannelWithLeasing.cs) | 1 | 7 |
| [SMB2/TestSuite/MultipleChannel/MultipleChannelWithLock.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/MultipleChannel/MultipleChannelWithLock.cs) | 2 | 12 |
| [SMB2/TestSuite/Negotiate/Negotiation.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/Negotiate/Negotiation.cs) | 35 | 13 |
| [SMB2/TestSuite/OpLock/OpLock.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/OpLock/OpLock.cs) | 2 | 14 |
| [SMB2/TestSuite/Replay/Replay.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/Replay/Replay.cs) | 2 | 14 |
| [SMB2/TestSuite/Replay/ReplayIsReplayEligible.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/Replay/ReplayIsReplayEligible.cs) | 18 | 44 |
| [SMB2/TestSuite/ResilientHandle/ResilientHandle.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/ResilientHandle/ResilientHandle.cs) | 4 | 16 |
| [SMB2/TestSuite/ResilientHandle/ResilientOpenScavengerTimer.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/ResilientHandle/ResilientOpenScavengerTimer.cs) | 2 | 8 |
| [SMB2/TestSuite/SessionMgmt/SessionMgmt.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/SessionMgmt/SessionMgmt.cs) | 5 | 15 |
| [SMB2/TestSuite/Signing/Signing.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/Signing/Signing.cs) | 10 | 18 |
| [SMB2/TestSuite/TreeMgmt/TreeMgmt.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2/TestSuite/TreeMgmt/TreeMgmt.cs) | 5 | 18 |
| [SMB2Model/TestSuite/AppInstanceIdTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/AppInstanceIdTestCase.cs) | 70 | 35 |
| [SMB2Model/TestSuite/BreakReadHandleLeaseV1TestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/BreakReadHandleLeaseV1TestCase.cs) | 80 | 60 |
| [SMB2Model/TestSuite/BreakReadHandleLeaseV2TestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/BreakReadHandleLeaseV2TestCase.cs) | 38 | 44 |
| [SMB2Model/TestSuite/BreakReadLeaseV1TestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/BreakReadLeaseV1TestCase.cs) | 50 | 30 |
| [SMB2Model/TestSuite/BreakReadLeaseV2TestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/BreakReadLeaseV2TestCase.cs) | 16 | 24 |
| [SMB2Model/TestSuite/BreakReadWriteHandleLeaseV1TestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/BreakReadWriteHandleLeaseV1TestCase.cs) | 102 | 57 |
| [SMB2Model/TestSuite/BreakReadWriteHandleLeaseV2TestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/BreakReadWriteHandleLeaseV2TestCase.cs) | 65 | 43 |
| [SMB2Model/TestSuite/BreakReadWriteLeaseV1TestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/BreakReadWriteLeaseV1TestCase.cs) | 43 | 32 |
| [SMB2Model/TestSuite/BreakReadWriteLeaseV2TestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/BreakReadWriteLeaseV2TestCase.cs) | 18 | 24 |
| [SMB2Model/TestSuite/ConflictTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/ConflictTestCase.cs) | 29 | 30 |
| [SMB2Model/TestSuite/CreateCloseTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/CreateCloseTestCase.cs) | 25 | 20 |
| [SMB2Model/TestSuite/CreditMgmtTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/CreditMgmtTestCase.cs) | 52 | 30 |
| [SMB2Model/TestSuite/DurableHandleV1PreparedWithBatchOplockReconnectTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/DurableHandleV1PreparedWithBatchOplockReconnectTestCase.cs) | 35 | 10 |
| [SMB2Model/TestSuite/DurableHandleV1PreparedWithLeaseV1ReconnectTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/DurableHandleV1PreparedWithLeaseV1ReconnectTestCase.cs) | 29 | 11 |
| [SMB2Model/TestSuite/DurableHandleV2PreparedWithBatchOplockReconnectTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/DurableHandleV2PreparedWithBatchOplockReconnectTestCase.cs) | 26 | 11 |
| [SMB2Model/TestSuite/DurableHandleV2PreparedWithLeaseV1ReconnectTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/DurableHandleV2PreparedWithLeaseV1ReconnectTestCase.cs) | 26 | 11 |
| [SMB2Model/TestSuite/DurableHandleV2PreparedWithLeaseV2ReconnectTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/DurableHandleV2PreparedWithLeaseV2ReconnectTestCase.cs) | 20 | 10 |
| [SMB2Model/TestSuite/EncryptionTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/EncryptionTestCase.cs) | 128 | 18 |
| [SMB2Model/TestSuite/LeaseOplockTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/LeaseOplockTestCase.cs) | 12 | 8 |
| [SMB2Model/TestSuite/NegotiateTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/NegotiateTestCase.cs) | 92 | 18 |
| [SMB2Model/TestSuite/OplockLeaseTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/OplockLeaseTestCase.cs) | 12 | 8 |
| [SMB2Model/TestSuite/OplockOnShareWithForceLevel2AndSOFSTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/OplockOnShareWithForceLevel2AndSOFSTestCase.cs) | 114 | 16 |
| [SMB2Model/TestSuite/OplockOnShareWithForceLevel2WithoutSOFSTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/OplockOnShareWithForceLevel2WithoutSOFSTestCase.cs) | 112 | 16 |
| [SMB2Model/TestSuite/OplockOnShareWithoutForceLevel2OrSOFSTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/OplockOnShareWithoutForceLevel2OrSOFSTestCase.cs) | 51 | 16 |
| [SMB2Model/TestSuite/OplockOnShareWithoutForceLevel2WithSOFSTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/OplockOnShareWithoutForceLevel2WithSOFSTestCase.cs) | 63 | 16 |
| [SMB2Model/TestSuite/PersistentHandleReconnectTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/PersistentHandleReconnectTestCase.cs) | 28 | 15 |
| [SMB2Model/TestSuite/ReplayCreateDurableHandleV1TestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/ReplayCreateDurableHandleV1TestCase.cs) | 63 | 126 |
| [SMB2Model/TestSuite/ReplayCreateDurableHandleV2PersistentTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/ReplayCreateDurableHandleV2PersistentTestCase.cs) | 118 | 239 |
| [SMB2Model/TestSuite/ReplayCreateDurableHandleV2TestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/ReplayCreateDurableHandleV2TestCase.cs) | 134 | 256 |
| [SMB2Model/TestSuite/ReplayCreateNormalHandleTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/ReplayCreateNormalHandleTestCase.cs) | 94 | 130 |
| [SMB2Model/TestSuite/ReplayCreateWithoutHandleTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/ReplayCreateWithoutHandleTestCase.cs) | 24 | 25 |
| [SMB2Model/TestSuite/ReplayFileOperationTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/ReplayFileOperationTestCase.cs) | 140 | 151 |
| [SMB2Model/TestSuite/RequestDurableHandleV1BatchOplockTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/RequestDurableHandleV1BatchOplockTestCase.cs) | 11 | 15 |
| [SMB2Model/TestSuite/RequestDurableHandleV1LeaseV1TestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/RequestDurableHandleV1LeaseV1TestCase.cs) | 10 | 17 |
| [SMB2Model/TestSuite/RequestDurableHandleV2BatchOplockTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/RequestDurableHandleV2BatchOplockTestCase.cs) | 6 | 12 |
| [SMB2Model/TestSuite/RequestDurableHandleV2LeaseV1TestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/RequestDurableHandleV2LeaseV1TestCase.cs) | 6 | 12 |
| [SMB2Model/TestSuite/RequestDurableHandleV2LeaseV2TestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/RequestDurableHandleV2LeaseV2TestCase.cs) | 6 | 10 |
| [SMB2Model/TestSuite/RequestPersistentHandleTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/RequestPersistentHandleTestCase.cs) | 8 | 13 |
| [SMB2Model/TestSuite/ResilientHandleBasicTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/ResilientHandleBasicTestCase.cs) | 44 | 18 |
| [SMB2Model/TestSuite/ResilientHandleDurableTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/ResilientHandleDurableTestCase.cs) | 44 | 18 |
| [SMB2Model/TestSuite/SessionMgmtBindSessionAfterDisconnectionScenarioTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/SessionMgmtBindSessionAfterDisconnectionScenarioTestCase.cs) | 12 | 13 |
| [SMB2Model/TestSuite/SessionMgmtBindSessionAfterLogOffScenarioTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/SessionMgmtBindSessionAfterLogOffScenarioTestCase.cs) | 70 | 13 |
| [SMB2Model/TestSuite/SessionMgmtBindSessionScenarioTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/SessionMgmtBindSessionScenarioTestCase.cs) | 33 | 12 |
| [SMB2Model/TestSuite/SessionMgmtNewSessionScenarioTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/SessionMgmtNewSessionScenarioTestCase.cs) | 80 | 18 |
| [SMB2Model/TestSuite/SessionMgmtReconnectSessionScenarioTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/SessionMgmtReconnectSessionScenarioTestCase.cs) | 24 | 14 |
| [SMB2Model/TestSuite/SigningTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/SigningTestCase.cs) | 95 | 29 |
| [SMB2Model/TestSuite/TreeMgmtTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/TreeMgmtTestCase.cs) | 13 | 9 |
| [SMB2Model/TestSuite/ValidateNegotiateInfoTestCase.cs](https://github.com/microsoft/WindowsProtocolTestSuites/blob/29ddb4238a5443b7499e82934c90cc898861c5e7/TestSuites/FileServer/src/SMB2Model/TestSuite/ValidateNegotiateInfoTestCase.cs) | 96 | 37 |

## Shared operation routes for current Microsoft call signatures

These routes concern the public operation facet. They do not claim that every source argument tuple or prerequisite graph is byte-identical to a local case. The current Microsoft ledger retains each literal normalized argument list, exact call permalink and entry-method/helper association, so different source-only configuration/feature dependencies stay visible. Numeric casts are preserved rather than guessed into wire constants.

| Member call | Signatures | Public facet / source-only disposition |
|---|---:|---|
| `Add` | 5 | Source fixture/configuration/assertion/result callback; not another public test. Operation performed by its reachable request helper is inventoried separately. |
| `AlternativeChannelSessionSetup` | 4 | Microsoft auth/signing/cipher/policy/session/binding cases, Go NTLM/MIC/integrity and inventory auth/header/buffer cases; no Guest-success/signing-disabled policy weakening. |
| `AssertAreEqual` | 72 | Source fixture/configuration/assertion/result callback; not another public test. Operation performed by its reachable request helper is inventoried separately. |
| `AssertIfNotSuccess` | 13 | Source fixture/configuration/assertion/result callback; not another public test. Operation performed by its reachable request helper is inventoried separately. |
| `BeforeSendingPacket` | 1 | Source fixture/configuration/assertion/result callback; not another public test. Operation performed by its reachable request helper is inventoried separately. |
| `ByteRangeLock` | 1 | Public lock ownership/ranges/I/O/cancel: upstream.protocol, Samba lock and inventory.lock. Undefined flag 0/16 rejection is source/SHOULD compatibility. |
| `ByteRangeUnlock` | 1 | Public lock ownership/ranges/I/O/cancel: upstream.protocol, Samba lock and inventory.lock. Undefined flag 0/16 rejection is source/SHOULD compatibility. |
| `Cancel` | 1 | Actual mutation-to-notify Microsoft native-filter cases; P4/state/continuation cancellation, close and subtree workflows. Native Windows creation/EA/security/stream watcher prerequisites remain explicit. |
| `ChangeNotify` | 17 | Actual mutation-to-notify Microsoft native-filter cases; P4/state/continuation cancellation, close and subtree workflows. Native Windows creation/EA/security/stream watcher prerequisites remain explicit. |
| `CheckIsR405Implemented` | 1 | Source fixture/configuration/assertion/result callback; not another public test. Operation performed by its reachable request helper is inventoried separately. |
| `CheckIsR507Implemented` | 1 | Source fixture/configuration/assertion/result callback; not another public test. Operation performed by its reachable request helper is inventoried separately. |
| `Close` | 19 | Ordinary close/logoff/transport/echo/compound behavior: baseline wire, P3/state, Microsoft auth compound and inventory sessionless ECHO. Client response expectation callbacks are source-only bookkeeping. |
| `CloseOpen` | 1 | Ordinary close/logoff/transport/echo/compound behavior: baseline wire, P3/state, Microsoft auth compound and inventory sessionless ECHO. Client response expectation callbacks are source-only bookkeeping. |
| `CloseRequest` | 4 | CREATE/close/context/replay/disposition/metadata facets: upstream.create, Microsoft context/replay/close, P7 and inventory create/durable-v1. Actual grants required for recovery; no seeded records. Persistent/CA/application fencing success is not claimed. |
| `ComNegotiateRequest` | 5 | Actual negotiated dialect/context/credit/validation and TCP lifecycle: Microsoft negotiate/validate-negotiate/auth, Go auth, P3/P7 and inventory negotiate/bounds. Physical NIC failover, RDMA and stopped-listener internals remain distinct. |
| `ComposeRandomFileName` | 9 | Source fixture/configuration/assertion/result callback; not another public test. Operation performed by its reachable request helper is inventoried separately. |
| `ConflictRequest` | 29 | Supported file lease/oplock/lock mutation and ACK facets: P6 wire workflows, P7 channel/recovery and Samba continuation cache/lease/oplock cases. Directory leasing, SOFS/forced-Level-II and cross-node setup arms stay unavailable; private model cache state is not a protocol assertion. |
| `ConnectToServer` | 10 | Actual negotiated dialect/context/credit/validation and TCP lifecycle: Microsoft negotiate/validate-negotiate/auth, Go auth, P3/P7 and inventory negotiate/bounds. Physical NIC failover, RDMA and stopped-listener internals remain distinct. |
| `ConnectToServerOverTCP` | 1 | Actual negotiated dialect/context/credit/validation and TCP lifecycle: Microsoft negotiate/validate-negotiate/auth, Go auth, P3/P7 and inventory negotiate/bounds. Physical NIC failover, RDMA and stopped-listener internals remain distinct. |
| `Create` | 94 | CREATE/close/context/replay/disposition/metadata facets: upstream.create, Microsoft context/replay/close, P7 and inventory create/durable-v1. Actual grants required for recovery; no seeded records. Persistent/CA/application fencing success is not claimed. |
| `CreateFile` | 71 | CREATE/close/context/replay/disposition/metadata facets: upstream.create, Microsoft context/replay/close, P7 and inventory create/durable-v1. Actual grants required for recovery; no seeded records. Persistent/CA/application fencing success is not claimed. |
| `CreateNamedPipeAsync` | 1 | CREATE/close/context/replay/disposition/metadata facets: upstream.create, Microsoft context/replay/close, P7 and inventory create/durable-v1. Actual grants required for recovery; no seeded records. Persistent/CA/application fencing success is not claimed. |
| `CreateRequest` | 775 | CREATE/close/context/replay/disposition/metadata facets: upstream.create, Microsoft context/replay/close, P7 and inventory create/durable-v1. Actual grants required for recovery; no seeded records. Persistent/CA/application fencing success is not claimed. |
| `CreateResponse` | 1 | Source fixture/configuration/assertion/result callback; not another public test. Operation performed by its reachable request helper is inventoried separately. |
| `CreditOperationRequest` | 25 | P3 credit boundaries/undercharge/grants and upstream.protocol.credit retained-hole/overlap/actual multi-credit TCP. Invalid-sequence disconnect remains a SHOULD policy distinction. |
| `Disconnect` | 1 | Ordinary close/logoff/transport/echo/compound behavior: baseline wire, P3/state, Microsoft auth compound and inventory sessionless ECHO. Client response expectation callbacks are source-only bookkeeping. |
| `DuplicateExtentsToFile` | 1 | Exact optional control/namespace/record capability unavailable where declared. Ordinary stream/file data, CREATE/query framing, buffer validation and honest unsupported-error facets map separately to P5, Microsoft metadata/context and inventory bounds/query; no optional successful object-store side effect claimed. |
| `Echo` | 4 | Ordinary close/logoff/transport/echo/compound behavior: baseline wire, P3/state, Microsoft auth compound and inventory sessionless ECHO. Client response expectation callbacks are source-only bookkeeping. |
| `EnableSessionSigningAndEncryption` | 3 | Microsoft auth/signing/cipher/policy/session/binding cases, Go NTLM/MIC/integrity and inventory auth/header/buffer cases; no Guest-success/signing-disabled policy weakening. |
| `EnumerateSnapShots` | 2 | Exact optional control/namespace/record capability unavailable where declared. Ordinary stream/file data, CREATE/query framing, buffer validation and honest unsupported-error facets map separately to P5, Microsoft metadata/context and inventory bounds/query; no optional successful object-store side effect claimed. |
| `ExpectAsResponse` | 1 | Ordinary close/logoff/transport/echo/compound behavior: baseline wire, P3/state, Microsoft auth compound and inventory sessionless ECHO. Client response expectation callbacks are source-only bookkeeping. |
| `ExpectDisconnect` | 1 | Ordinary close/logoff/transport/echo/compound behavior: baseline wire, P3/state, Microsoft auth compound and inventory sessionless ECHO. Client response expectation callbacks are source-only bookkeeping. |
| `ExpectPreauthRequiredError` | 1 | Source configuration/expected-result/identity helper; actual reachable wire operation is inventoried separately. KDC, Windows identity and optional-capability discovery do not become portable protocol assertions. |
| `ExpectTgsResponse` | 1 | Source configuration/expected-result/identity helper; actual reachable wire operation is inventoried separately. KDC, Windows identity and optional-capability discovery do not become portable protocol assertions. |
| `FileLevelTrim` | 2 | Exact optional control/record/namespace side effect unavailable where declared. Common file data, stream identity, buffer/length validation and unsupported-error facets remain mapped to P5, Microsoft metadata/context and inventory bounds/query. |
| `FileOperationRequest` | 142 | Go/Microsoft/P5/Samba ordinary file/data/FSCC/EA/rename/delete/public buffer facets, inventory bounds/metadata/query/durable-v1. Optional controls and exact host-only FSA semantics remain explicitly qualified. |
| `FileOperationToBreakLeaseRequest` | 58 | Supported public file cache/ACK/mutation: P6, P7, Samba continuation cache/lease/oplock. Directory leasing, forced-Level-II/SOFS/cross-node prerequisites are not inferred supported. |
| `FileOperationToBreakLeaseResponse` | 1 | Source setup/result callback; public grant/data setup is inventoried at the reachable CREATE/request helper. No seed of private server graph state is ported. |
| `FileOperationVerifyEncryptionRequest` | 2 | Microsoft auth signing/cipher/policy/session/binding, Go NTLM/MIC/integrity, inventory auth. Guest-success/signing-disabled source branches remain unavailable under preserved host policy. |
| `Flush` | 4 | Go/Microsoft/P5/Samba ordinary file/data/FSCC/EA/rename/delete/public buffer facets, inventory bounds/metadata/query/durable-v1. Optional controls and exact host-only FSA semantics remain explicitly qualified. |
| `FlushCachedData` | 1 | Go/Microsoft/P5/Samba ordinary file/data/FSCC/EA/rename/delete/public buffer facets, inventory bounds/metadata/query/durable-v1. Optional controls and exact host-only FSA semantics remain explicitly qualified. |
| `FsCtlForEasyRequest` | 2 | Exact optional control/record/namespace behavior remains unavailable where declared. Generic wrapper arguments stay literal in current ledger. Ordinary data, stream identity, bounds, buffer sizes and rejection are mapped separately to P5/Microsoft/Samba/inventory; no optional successful host side effect inferred. |
| `FsCtlGetCompression` | 1 | Exact optional control/record/namespace behavior remains unavailable where declared. Generic wrapper arguments stay literal in current ledger. Ordinary data, stream identity, bounds, buffer sizes and rejection are mapped separately to P5/Microsoft/Samba/inventory; no optional successful host side effect inferred. |
| `FsCtlGetIntegrityInfo` | 1 | Exact optional control/record/namespace behavior remains unavailable where declared. Generic wrapper arguments stay literal in current ledger. Ordinary data, stream identity, bounds, buffer sizes and rejection are mapped separately to P5/Microsoft/Samba/inventory; no optional successful host side effect inferred. |
| `FsCtlQueryAllocatedRanges` | 1 | Exact optional control/record/namespace behavior remains unavailable where declared. Generic wrapper arguments stay literal in current ledger. Ordinary data, stream identity, bounds, buffer sizes and rejection are mapped separately to P5/Microsoft/Samba/inventory; no optional successful host side effect inferred. |
| `FsCtlReadFileUSNData` | 1 | Exact optional control/record/namespace behavior remains unavailable where declared. Generic wrapper arguments stay literal in current ledger. Ordinary data, stream identity, bounds, buffer sizes and rejection are mapped separately to P5/Microsoft/Samba/inventory; no optional successful host side effect inferred. |
| `FsCtlSetCompression` | 1 | Exact optional control/record/namespace behavior remains unavailable where declared. Generic wrapper arguments stay literal in current ledger. Ordinary data, stream identity, bounds, buffer sizes and rejection are mapped separately to P5/Microsoft/Samba/inventory; no optional successful host side effect inferred. |
| `FsCtlSetZeroData` | 1 | Exact optional control/record/namespace behavior remains unavailable where declared. Generic wrapper arguments stay literal in current ledger. Ordinary data, stream identity, bounds, buffer sizes and rejection are mapped separately to P5/Microsoft/Samba/inventory; no optional successful host side effect inferred. |
| `FsaInitial` | 1 | Source configuration/fixture/expected-result helper. Public operation in reachable request helper is inventoried separately. Windows/domain identity, private model state and capability-discovery output are not new portable tests. |
| `GetApResponseFromToken` | 1 | Source configuration/fixture/expected-result helper. Public operation in reachable request helper is inventoried separately. Windows/domain identity, private model state and capability-discovery output are not new portable tests. |
| `GetFileVolumSize` | 1 | Source configuration/fixture/expected-result helper. Public operation in reachable request helper is inventoried separately. Windows/domain identity, private model state and capability-discovery output are not new portable tests. |
| `GetGroupSid` | 1 | Source configuration/fixture/expected-result helper. Public operation in reachable request helper is inventoried separately. Windows/domain identity, private model state and capability-discovery output are not new portable tests. |
| `GetIfImplementQueryFileObjectIdInformation` | 1 | Source configuration/fixture/expected-result helper. Public operation in reachable request helper is inventoried separately. Windows/domain identity, private model state and capability-discovery output are not new portable tests. |
| `GetIfImplementQueryFileReparsePointInformation` | 1 | Source configuration/fixture/expected-result helper. Public operation in reachable request helper is inventoried separately. Windows/domain identity, private model state and capability-discovery output are not new portable tests. |
| `GetIfOpenFileVolumeIsReadOnly` | 1 | Source configuration/fixture/expected-result helper. Public operation in reachable request helper is inventoried separately. Windows/domain identity, private model state and capability-discovery output are not new portable tests. |
| `GetIfOpenHasManageVolumeAccess` | 1 | Source configuration/fixture/expected-result helper. Public operation in reachable request helper is inventoried separately. Windows/domain identity, private model state and capability-discovery output are not new portable tests. |
| `GetIfOpenListContains` | 1 | Source configuration/fixture/expected-result helper. Public operation in reachable request helper is inventoried separately. Windows/domain identity, private model state and capability-discovery output are not new portable tests. |
| `GetIfStreamRenameIsSupported` | 1 | Source configuration/fixture/expected-result helper. Public operation in reachable request helper is inventoried separately. Windows/domain identity, private model state and capability-discovery output are not new portable tests. |
| `GetIntegrityInfo` | 1 | Source configuration/fixture/expected-result helper. Public operation in reachable request helper is inventoried separately. Windows/domain identity, private model state and capability-discovery output are not new portable tests. |
| `GetIsLinkFound` | 1 | Source configuration/fixture/expected-result helper. Public operation in reachable request helper is inventoried separately. Windows/domain identity, private model state and capability-discovery output are not new portable tests. |
| `GetKrbErrorFromToken` | 1 | Source configuration/fixture/expected-result helper. Public operation in reachable request helper is inventoried separately. Windows/domain identity, private model state and capability-discovery output are not new portable tests. |
| `GetOSInfo` | 1 | Source configuration/fixture/expected-result helper. Public operation in reachable request helper is inventoried separately. Windows/domain identity, private model state and capability-discovery output are not new portable tests. |
| `GetSystemConfig` | 1 | Source configuration/fixture/expected-result helper. Public operation in reachable request helper is inventoried separately. Windows/domain identity, private model state and capability-discovery output are not new portable tests. |
| `GetUserSid` | 1 | Source configuration/fixture/expected-result helper. Public operation in reachable request helper is inventoried separately. Windows/domain identity, private model state and capability-discovery output are not new portable tests. |
| `GetWindowsIdentity` | 1 | Source configuration/fixture/expected-result helper. Public operation in reachable request helper is inventoried separately. Windows/domain identity, private model state and capability-discovery output are not new portable tests. |
| `IoCtlResiliencyRequest` | 9 | Exact optional control/record/namespace behavior remains unavailable where declared. Generic wrapper arguments stay literal in current ledger. Ordinary data, stream identity, bounds, buffer sizes and rejection are mapped separately to P5/Microsoft/Samba/inventory; no optional successful host side effect inferred. |
| `LeaseBreakAcknowledgment` | 4 | Supported file cache/ACK/mutation: P6/P7/Samba continuation. Directory leasing, forced-Level-II/SOFS and cross-node setup are unavailable dependencies. |
| `LeaseBreakAcknowledgmentRequest` | 4 | Supported file cache/ACK/mutation: P6/P7/Samba continuation. Directory leasing, forced-Level-II/SOFS and cross-node setup are unavailable dependencies. |
| `Lock` | 9 | Public range/ownership/I/O/cancel: upstream.protocol, Samba and inventory.lock; undefined flags0/16 rejection is source/SHOULD compatibility. |
| `LogOff` | 2 | Microsoft auth signing/cipher/policy/session/binding and Go/inventory auth; no Guest-success/signing-disabled policy weakening. |
| `LogOffRequest` | 2 | Microsoft auth signing/cipher/policy/session/binding and Go/inventory auth; no Guest-success/signing-disabled policy weakening. |
| `MultiProtocolNegotiate` | 2 | Microsoft negotiation/validate-negotiate/auth, P3/P7 and inventory negotiate, excluding actual RDMA/NIC/cluster execution. |
| `Negotiate` | 39 | Microsoft negotiation/validate-negotiate/auth, P3/P7 and inventory negotiate, excluding actual RDMA/NIC/cluster execution. |
| `NegotiateRequest` | 27 | Microsoft negotiation/validate-negotiate/auth, P3/P7 and inventory negotiate, excluding actual RDMA/NIC/cluster execution. |
| `NegotiateWithContexts` | 12 | Microsoft negotiation/validate-negotiate/auth, P3/P7 and inventory negotiate, excluding actual RDMA/NIC/cluster execution. |
| `OffloadRead` | 3 | Exact optional control/record/namespace behavior remains unavailable where declared. Generic wrapper arguments stay literal in current ledger. Ordinary data, stream identity, bounds, buffer sizes and rejection are mapped separately to P5/Microsoft/Samba/inventory; no optional successful host side effect inferred. |
| `OffloadWrite` | 3 | Exact optional control/record/namespace behavior remains unavailable where declared. Generic wrapper arguments stay literal in current ledger. Ordinary data, stream identity, bounds, buffer sizes and rejection are mapped separately to P5/Microsoft/Samba/inventory; no optional successful host side effect inferred. |
| `OpenRequest` | 74 | Ordinary data/FSCC/EA/rename/delete/public buffer facets: Go/Microsoft/P5/Samba and inventory bounds/query/metadata/durable-v1. Exact optional controls and host-only FSA success rules stay qualified. |
| `OplockAcknowledgement` | 1 | Supported file cache/ACK/mutation: P6/P7/Samba continuation. Directory leasing, forced-Level-II/SOFS and cross-node setup are unavailable dependencies. |
| `OplockBreakAcknowledgementRequest` | 7 | Supported file cache/ACK/mutation: P6/P7/Samba continuation. Directory leasing, forced-Level-II/SOFS and cross-node setup are unavailable dependencies. |
| `Preparation` | 1 | Source configuration/fixture/expected-result helper. Public operation in reachable request helper is inventoried separately. Windows/domain identity, private model state and capability-discovery output are not new portable tests. |
| `PrepareCreate` | 12 | Source configuration/fixture/expected-result helper. Public operation in reachable request helper is inventoried separately. Windows/domain identity, private model state and capability-discovery output are not new portable tests. |
| `PrepareFileOperation` | 8 | Source configuration/fixture/expected-result helper. Public operation in reachable request helper is inventoried separately. Windows/domain identity, private model state and capability-discovery output are not new portable tests. |
| `PrepareOpen` | 42 | Source configuration/fixture/expected-result helper. Public operation in reachable request helper is inventoried separately. Windows/domain identity, private model state and capability-discovery output are not new portable tests. |
| `QueryDirectory` | 7 | Ordinary data/FSCC/EA/rename/delete/public buffer facets: Go/Microsoft/P5/Samba and inventory bounds/query/metadata/durable-v1. Exact optional controls and host-only FSA success rules stay qualified. |
| `QueryDirectoryInfo` | 11 | Ordinary data/FSCC/EA/rename/delete/public buffer facets: Go/Microsoft/P5/Samba and inventory bounds/query/metadata/durable-v1. Exact optional controls and host-only FSA success rules stay qualified. |
| `QueryFSAttributes` | 1 | Ordinary data/FSCC/EA/rename/delete/public buffer facets: Go/Microsoft/P5/Samba and inventory bounds/query/metadata/durable-v1. Exact optional controls and host-only FSA success rules stay qualified. |
| `QueryFileAttributes` | 6 | Ordinary data/FSCC/EA/rename/delete/public buffer facets: Go/Microsoft/P5/Samba and inventory bounds/query/metadata/durable-v1. Exact optional controls and host-only FSA success rules stay qualified. |
| `QueryFileFsAttributeInformation` | 1 | Ordinary data/FSCC/EA/rename/delete/public buffer facets: Go/Microsoft/P5/Samba and inventory bounds/query/metadata/durable-v1. Exact optional controls and host-only FSA success rules stay qualified. |
| `QueryFileFullEaInformation` | 1 | Ordinary data/FSCC/EA/rename/delete/public buffer facets: Go/Microsoft/P5/Samba and inventory bounds/query/metadata/durable-v1. Exact optional controls and host-only FSA success rules stay qualified. |
| `QueryFileInfoPart1` | 44 | Ordinary data/FSCC/EA/rename/delete/public buffer facets: Go/Microsoft/P5/Samba and inventory bounds/query/metadata/durable-v1. Exact optional controls and host-only FSA success rules stay qualified. |
| `QueryFileInformation` | 15 | Ordinary data/FSCC/EA/rename/delete/public buffer facets: Go/Microsoft/P5/Samba and inventory bounds/query/metadata/durable-v1. Exact optional controls and host-only FSA success rules stay qualified. |
| `QueryFileNormalizedNameInformation` | 1 | Ordinary data/FSCC/EA/rename/delete/public buffer facets: Go/Microsoft/P5/Samba and inventory bounds/query/metadata/durable-v1. Exact optional controls and host-only FSA success rules stay qualified. |
| `QueryFileObjectIdInfo` | 10 | Exact optional control/record/namespace behavior remains unavailable where declared. Generic wrapper arguments stay literal in current ledger. Ordinary data, stream identity, bounds, buffer sizes and rejection are mapped separately to P5/Microsoft/Samba/inventory; no optional successful host side effect inferred. |
| `QueryFileQuotaInfo` | 1 | Exact optional control/record/namespace behavior remains unavailable where declared. Generic wrapper arguments stay literal in current ledger. Ordinary data, stream identity, bounds, buffer sizes and rejection are mapped separately to P5/Microsoft/Samba/inventory; no optional successful host side effect inferred. |
| `QueryFileReparsePointInformation` | 10 | Exact optional control/record/namespace behavior remains unavailable where declared. Generic wrapper arguments stay literal in current ledger. Ordinary data, stream identity, bounds, buffer sizes and rejection are mapped separately to P5/Microsoft/Samba/inventory; no optional successful host side effect inferred. |
| `QueryNetworkInterfaceInfo` | 3 | Ordinary data/FSCC/EA/rename/delete/public buffer facets: Go/Microsoft/P5/Samba and inventory bounds/query/metadata/durable-v1. Exact optional controls and host-only FSA success rules stay qualified. |
| `ReEstablishResilientOpenRequest` | 2 | Exact optional control/record/namespace behavior remains unavailable where declared. Generic wrapper arguments stay literal in current ledger. Ordinary data, stream identity, bounds, buffer sizes and rejection are mapped separately to P5/Microsoft/Samba/inventory; no optional successful host side effect inferred. |
| `Read` | 19 | Ordinary data/FSCC/EA/rename/delete/public buffer facets: Go/Microsoft/P5/Samba and inventory bounds/query/metadata/durable-v1. Exact optional controls and host-only FSA success rules stay qualified. |
| `ReadConfig` | 1 | Source configuration/fixture/expected-result helper. Public operation in reachable request helper is inventoried separately. Windows/domain identity, private model state and capability-discovery output are not new portable tests. |
| `ReadFile` | 6 | Ordinary data/FSCC/EA/rename/delete/public buffer facets: Go/Microsoft/P5/Samba and inventory bounds/query/metadata/durable-v1. Exact optional controls and host-only FSA success rules stay qualified. |
| `ReconnectOpenRequest` | 24 | Ordinary data/FSCC/EA/rename/delete/public buffer facets: Go/Microsoft/P5/Samba and inventory bounds/query/metadata/durable-v1. Exact optional controls and host-only FSA success rules stay qualified. |
| `ReconnectSessionSetup` | 3 | Microsoft auth signing/cipher/policy/session/binding and Go/inventory auth; no Guest-success/signing-disabled policy weakening. |
| `RequestLease` | 4 | Supported file cache/ACK/mutation: P6/P7/Samba continuation. Directory leasing, forced-Level-II/SOFS and cross-node setup are unavailable dependencies. |
| `RequestOplock` | 3 | Supported file cache/ACK/mutation: P6/P7/Samba continuation. Directory leasing, forced-Level-II/SOFS and cross-node setup are unavailable dependencies. |
| `RequestOplockAndOperateFileRequest` | 4 | Supported file cache/ACK/mutation: P6/P7/Samba continuation. Directory leasing, forced-Level-II/SOFS and cross-node setup are unavailable dependencies. |
| `ResiliencyRequest` | 6 | Exact optional control/record/namespace behavior remains unavailable where declared. Generic wrapper arguments stay literal in current ledger. Ordinary data, stream identity, bounds, buffer sizes and rejection are mapped separately to P5/Microsoft/Samba/inventory; no optional successful host side effect inferred. |
| `SendAndReceiveCompoundPacket` | 2 | Wire close/tree/logoff/echo/compound/transport lifecycle: P3/P7/state/Microsoft auth and inventory sessionless ECHO. Private harness response callbacks are not new tests. |
| `SendAsRequest` | 2 | Wire close/tree/logoff/echo/compound/transport lifecycle: P3/P7/state/Microsoft auth and inventory sessionless ECHO. Private harness response callbacks are not new tests. |
| `SendTgsRequest` | 1 | Wire close/tree/logoff/echo/compound/transport lifecycle: P3/P7/state/Microsoft auth and inventory sessionless ECHO. Private harness response callbacks are not new tests. |
| `SessionSetup` | 18 | Microsoft auth signing/cipher/policy/session/binding and Go/inventory auth; no Guest-success/signing-disabled policy weakening. |
| `SessionSetupRequest` | 28 | Microsoft auth signing/cipher/policy/session/binding and Go/inventory auth; no Guest-success/signing-disabled policy weakening. |
| `SetFileAllocOrObjIdInfo` | 6 | Allocation negative/short records: p5.allocation.length/value cases; object-ID creation is optional and unavailable. Allocation size is not EOF and object ID is not stable file identity. |
| `SetFileAttributes` | 14 | Public basic/EOF/EA/disposition/rename update and validation: Microsoft metadata/set/rename/delete, upstream.create, P5 and inventory bounds/metadata. Independent ChangeTime and NTFS-only automatic controls remain qualified. |
| `SetFileBasicInfo` | 8 | Public basic/EOF/EA/disposition/rename update and validation: Microsoft metadata/set/rename/delete, upstream.create, P5 and inventory bounds/metadata. Independent ChangeTime and NTFS-only automatic controls remain qualified. |
| `SetFileDispositionInfo` | 2 | Public basic/EOF/EA/disposition/rename update and validation: Microsoft metadata/set/rename/delete, upstream.create, P5 and inventory bounds/metadata. Independent ChangeTime and NTFS-only automatic controls remain qualified. |
| `SetFileEndOfFileInfo` | 4 | Public basic/EOF/EA/disposition/rename update and validation: Microsoft metadata/set/rename/delete, upstream.create, P5 and inventory bounds/metadata. Independent ChangeTime and NTFS-only automatic controls remain qualified. |
| `SetFileFullEaInfo` | 4 | Public basic/EOF/EA/disposition/rename update and validation: Microsoft metadata/set/rename/delete, upstream.create, P5 and inventory bounds/metadata. Independent ChangeTime and NTFS-only automatic controls remain qualified. |
| `SetFileFullEaInformation` | 1 | Public basic/EOF/EA/disposition/rename update and validation: Microsoft metadata/set/rename/delete, upstream.create, P5 and inventory bounds/metadata. Independent ChangeTime and NTFS-only automatic controls remain qualified. |
| `SetFileInformation` | 5 | Public basic/EOF/EA/disposition/rename update and validation: Microsoft metadata/set/rename/delete, upstream.create, P5 and inventory bounds/metadata. Independent ChangeTime and NTFS-only automatic controls remain qualified. |
| `SetFileLinkInfo` | 4 | Exact SET/FSCTL/stream-rename capability is unavailable; ordinary base rename/stream reads/identity and malformed buffers remain separately mapped. Current ledger preserves actual class/control arguments. |
| `SetFileLinkInformation` | 1 | Exact SET/FSCTL/stream-rename capability is unavailable; ordinary base rename/stream reads/identity and malformed buffers remain separately mapped. Current ledger preserves actual class/control arguments. |
| `SetFileModeInfo` | 4 | Exact SET/FSCTL/stream-rename capability is unavailable; ordinary base rename/stream reads/identity and malformed buffers remain separately mapped. Current ledger preserves actual class/control arguments. |
| `SetFilePositionInfo` | 8 | Microsoft short/negative position SET validation and P5 fixed QUERY bounds. FSA synchronous implicit-current-position success does not apply to SMB2 asynchronous opens. |
| `SetFileRenameInfo` | 11 | Public basic/EOF/EA/disposition/rename update and validation: Microsoft metadata/set/rename/delete, upstream.create, P5 and inventory bounds/metadata. Independent ChangeTime and NTFS-only automatic controls remain qualified. |
| `SetFileShortNameInfo` | 5 | Exact SET/FSCTL/stream-rename capability is unavailable; ordinary base rename/stream reads/identity and malformed buffers remain separately mapped. Current ledger preserves actual class/control arguments. |
| `SetFileValidDataLengthInfo` | 2 | Exact SET/FSCTL/stream-rename capability is unavailable; ordinary base rename/stream reads/identity and malformed buffers remain separately mapped. Current ledger preserves actual class/control arguments. |
| `SetIntegrityInfo` | 1 | Exact SET/FSCTL/stream-rename capability is unavailable; ordinary base rename/stream reads/identity and malformed buffers remain separately mapped. Current ledger preserves actual class/control arguments. |
| `SetSecurityDescriptor` | 1 | Public descriptor query/set and access: inventory.security and descriptor-owner repair tests. No domain/claims SUT-control or private ACL-representation pass claimed. |
| `SetSessionSigningAndEncryption` | 1 | Microsoft signed/encrypted auth policy, cipher and compound cases; source helper configuration is not an independent pass. Host signing/anonymous policy stays preserved. |
| `SetTreeEncryption` | 1 | Microsoft signed/encrypted auth policy, cipher and compound cases; source helper configuration is not an independent pass. Host signing/anonymous policy stays preserved. |
| `SetZeroData` | 1 | Exact SET/FSCTL/stream-rename capability is unavailable; ordinary base rename/stream reads/identity and malformed buffers remain separately mapped. Current ledger preserves actual class/control arguments. |
| `SetupConnection` | 75 | Source fixture/client API/configuration; its actual negotiated/dialect/auth operation facets are in Microsoft auth/negotiate and inventory.negotiate, not another server state test. |
| `StreamRename` | 54 | Exact SET/FSCTL/stream-rename capability is unavailable; ordinary base rename/stream reads/identity and malformed buffers remain separately mapped. Current ledger preserves actual class/control arguments. |
| `StreamRenameWithNewName` | 1 | Exact SET/FSCTL/stream-rename capability is unavailable; ordinary base rename/stream reads/identity and malformed buffers remain separately mapped. Current ledger preserves actual class/control arguments. |
| `TerminateConnection` | 1 | Actual TCP loss and established direct-fixture teardown: P7 channel/recovery and Microsoft retired-session binding; no cross-node/NIC-failure claim. |
| `ToString` | 1 | Source fixture/client API/configuration; its actual negotiated/dialect/auth operation facets are in Microsoft auth/negotiate and inventory.negotiate, not another server state test. |
| `TreeConnect` | 31 | Microsoft tree IDs/path and baseline signed tree disconnect lifecycle; unsupported administrative/SOFS/cluster extensions remain explicit. |
| `TreeConnectRequest` | 9 | Microsoft tree IDs/path and baseline signed tree disconnect lifecycle; unsupported administrative/SOFS/cluster extensions remain explicit. |
| `TreeDisconnect` | 12 | Microsoft tree IDs/path and baseline signed tree disconnect lifecycle; unsupported administrative/SOFS/cluster extensions remain explicit. |
| `TreeDisconnectRequest` | 3 | Microsoft tree IDs/path and baseline signed tree disconnect lifecycle; unsupported administrative/SOFS/cluster extensions remain explicit. |
| `ValidateNegotiateInfo` | 2 | Eight independent Microsoft validate-negotiate field/status/transport cases, preserving exact dialect/GUID/mode/capability partitions. |
| `ValidateNegotiateInfoRequest` | 6 | Eight independent Microsoft validate-negotiate field/status/transport cases, preserving exact dialect/GUID/mode/capability partitions. |
| `Write` | 34 | Actual Go/P5/Microsoft/Samba wire data/offset/EOF/readonly/share/lock/cache behaviors; inventory buffer truncation/overflow and metadata mutation. Source PCG/seek/client byte accounting is not copied. |
| `WriteFile` | 4 | Actual Go/P5/Microsoft/Samba wire data/offset/EOF/readonly/share/lock/cache behaviors; inventory buffer truncation/overflow and metadata mutation. Source PCG/seek/client byte accounting is not copied. |

## Focused captured result

`build-10` compiles the 140-case allocation; `run-10` is **125 PASS / 15 FAIL**.
The 15 retained source-policy failures are ten optional QUERY_INFO statuses,
two automatic ARCHIVE updates, two undefined LOCK flag combinations (0/16),
and the maximum dialect array versus the explicit 64-dialect cap. None is
silently skipped or converted to a pass. The corrected auth/header cases,
public descriptor query/set, eight v1+lease claim partitions, buffer/name/context
cases and all 320 fixed byte cuts pass on that captured source. Earlier public
boundary/NTLM failures remain RED in earlier captures; later owner changes are
identified by their source hashes, not attributed to this allocation.

This is a focused JIT selection. Final settled full JIT/NativeAOT/actual-TCP and
native Windows gates are the parent's responsibility. No such full gate was run
by this allocation during active production work.

All five owned inventory test sources match the `build-10` source manifest. The
shared Program registration subsequently changed under another owner; its old/new
hashes are retained in `shared-registration-after-build.json`. The focused result
is for the captured registration/build, not the later entire shared checkout.
