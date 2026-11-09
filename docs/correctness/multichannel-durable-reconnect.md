# Multichannel and in-memory durable reconnect

Subsequent [remaining-failure repairs](remaining-failure-repairs.md) resolve all
100 retained cases described by this historical delivery. Current integration
and published Linux JIT/AOT pass 3,897/3,897. Production changes and corrected
primary/profile oracles are distinguished in that later report; original source
conventions and results below remain historical evidence.

This feature delivery follows clean baseline `1def1af` and the second upstream
campaign. The baseline was reproduced before implementation: 3,144 tests,
2,917 passing and the identical 227 failing names from the preceding Linux
capture, with unchanged executable source. Earlier reports describe that
historical policy and remain evidence of their respective source versions.

The integrated implementation supports authenticated SMB 3.0/3.0.2/3.1.1
multichannel and in-memory durable reconnect. Durable v1 applies to SMB
2.0.2/2.1/3.0/3.0.2/3.1.1; durable v2 requires SMB3. `Restricted` remains the
default. Use the [explicit configuration examples](multichannel-durable-configuration.md).
Persistent handles, continuous availability, clustering and crash/restart
recovery remain separate unsupported features. Directory leases are not enabled.

## Implemented contracts and primary mapping

| Source and contract | Primary requirement / selected behavior |
|---|---|
| `Smb2Dispatcher.HandleSessionBindingCore`, `DeriveChannelSigningKey` | [3.3.5.5.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5ed93f06-a1d2-4837-8954-fa8b833c2654): a bound channel derives its signing key from its fresh authentication key and its own transcript. Session encryption keys remain established session keys. |
| `ResponseSegment.ResponsePreauthHash`, `AssembleResponse` | Hash the actual signed challenge bytes after flags, credits, signature and padding are assembled. The final authentication request completes the channel's derivation transcript; the final success response uses the resulting channel key. Initial session and binding transcripts remain distinct. |
| `VerifyInboundSignature`, response-local signing keys | [3.3.5.2.4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/85df1680-2ee7-4d25-a916-a982371ddc75) and [3.3.4.1.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d594481c-f6d5-4de5-8842-9099063d41e7): binding requests use the original session signing key; ordinary traffic uses the receiving channel key; non-success SESSION_SETUP uses the session signing key. Claimed signatures are checked even when signing is optional. |
| `SmbConnection.BindingGate`, `SmbSession.TryAttachChannel` | Serialize publication against connection retirement; prevent late admission after final loss or LOGOFF. Check dialect, client identity/GUID and usable encryption keys. Client MULTI_CHANNEL capability is ignored as required by [2.2.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e14db7ff-763a-4263-8b10-0c3944f52fc5). |
| `MaxChannelsPerSession` | Configurable capacity, default 32 including the original channel. Both early admission and competing final authentications enforce the bound atomically; exhaustion returns INSUFFICIENT_RESOURCES. This capacity is an implementation choice. |
| `OnConnectionClosedAsync`, session/channel lookup | [3.3.7.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/eb5bfe99-47fe-4e87-8e87-08a084dcefb6): cancel lost-channel requests, detach that channel, promote a survivor and retain its shared trees/opens. Final-channel loss evaluates durable eligibility and retires session/tree indexes. IDs remain session-scoped and credits connection-scoped. |
| `SendOplockBreakAsync`, `SendLeaseBreakAsync`, host transport | [3.3.4.6](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/2a09fc40-1615-42df-bda6-2865b8d6da95) and [3.3.4.7](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/c367fad4-c00f-4778-913d-c0560ead1360): unsolicited notifications follow SHOULD NOT sign; ACKs retain ordinary authentication. Retry failed sends on surviving channels. Encrypted lease notifications retain inner SessionId/TreeId zero and an explicit transport encryption owner. |
| `SmbConnectionHandler.EncodeOutbound`, response protection snapshot | Preserve protection of a corresponding terminal response after LOGOFF removes indexes. A response-local key/owner cannot authorize new requests or revive the session. The shared session nonce counter remains in use. |
| `Smb3KeyDerivation.Derive` | [3.3.5.5.3 step 11](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5ed93f06-a1d2-4837-8954-fa8b833c2654): AES256 cipher derivation uses FullSessionKey; signing/application derivation uses SessionKey. Distinct-input independent vectors expose truncation that NTLM's equal 16-byte inputs cannot. |
| Durable CREATE grant and reconnect | [V1 request](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/9adbc354-5fad-40e7-9a62-4a4b6c1ff8a0), [v2 request](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/33e6800a-adf5-4221-af27-7e089b9e81d1), [v1 reconnect](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ba7499c3-4679-4d07-a82a-c80d9c2c6905), [v2 reconnect](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/62ba68d0-8806-4aef-a229-eefb5827160f): pin eligible Batch/HANDLE-caching file opens; validate owner, share, CreateGuid where applicable, lease presence/key/version/name and flags without consuming a failed claim. |
| Reconnect identity and contexts | Lookup uses FileId.Persistent; the supplied Volatile portion is not an equality requirement. Allocate a new volatile ID only for successful publication. Legal cross-version contexts are accepted according to their actual predicates. Reconnect omits renewed DHnQ/DH2Q; v1 omission is a MAY choice. Retained lease state is returned. |
| PreviousSessionId and explicit teardown | [3.3.5.5.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5ed93f06-a1d2-4837-8954-fa8b833c2654) replaces a same-user previous session using connection-loss processing, preserving eligible opens for explicit reconnect. CLOSE, TREE_DISCONNECT, LOGOFF, expiry and server shutdown release the applicable handles. Wrong/self/foreign previous-session identities do not retire an unrelated owner. |
| Replay registry and reconnect deadline | [CREATE replay processing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/8c61e928-9242-44ed-96a0-98d1032d0d39): arbitrate pending and completed requests, preserve original action/identity and retire eligibility on applicable operations. Recheck expiry after suspended metadata preparation before claiming ownership. Retained locks and their replay sequence slots survive reconnect. |
| `FileCacheCoordinator`, CREATE/rename coordination | Retain compatible RH rights, break WRITE for compatible CREATE and HANDLE for conflicting reservations, route a common lease through a live member, accept only valid subset ACKs, and purge unreachable members before resumed I/O when HANDLE is removed. An unchanged lease request preserves epoch. Same-object rename reuses source coordination instead of breaking the requester's own key again. |

Cipher key width cannot change within a bound session in this implementation;
such admission returns NOT_SUPPORTED. Same-width CCM/GCM changes and distinct
negotiated signing algorithms are tested. No full dialect/security-conformance
claim follows from these bounded combinations.

Completed v2 CREATE identity can also be replayed within its live session when
the requested caching/durable grant was declined. That selected interoperability
extension returns the established open without fabricating a durable context;
it does not preserve an ineligible open on disconnect or create cross-session
persistent recovery.

The backend coherence requirement remains `exclusiveServerAccess: true` with
all access routed through this server. This is a deployment assertion, not OS
fencing or coordination with external writers. Eligible disconnect retains the
acquired backend handle, bytes, position, locks, sharing, delete state and
supported cache state in process memory. There is no JSON recovery activation.

Production entry points are the [dispatcher](../../src/Smb.Server/Smb2Dispatcher.cs),
[cache coordinator](../../src/Smb.Server/Caching/FileCacheCoordinator.cs),
[session](../../src/Smb.Server/State/SmbSession.cs),
[connection](../../src/Smb.Server/State/SmbConnection.cs),
[host transport](../../src/Smb.Host/SmbConnectionHandler.cs),
[key derivation](../../src/Smb.Crypto/Smb3KeyDerivation.cs),
[policy](../../src/Smb.Server/SmbFeaturePolicy.cs) and
[options](../../src/Smb.Server/SmbServerOptions.cs).

## Maintained wire and lifecycle acceptance

| Test selection | Cases | Coverage |
|---|---:|---|
| `channel-wire.` | 131 | Actual separate TCP NEGOTIATE/NTLM binding on 300/302/311; transcript corruption, signatures, owner/GUID/dialect rejection, credits/IDs, concurrent I/O, cross-channel rename/locks/CLOSE, capacity and teardown races, surviving notifications, signing and AES128/256 CCM/GCM. |
| `durable.tcp.` | 151 | Legal dialect/v1/v2/lease combinations, repeated reconnect, claims and failed-then-valid recovery, expiry/shutdown, explicit teardown, PreviousSessionId, offsets, locks/replay, pinned rename/delete and cache keep/purge. |
| `cache.sequence.tcp.` | 28 | Same-client cross-session membership, queued downgrade, invalid/subset ACK, retained-member recovery, purge before conflicting I/O and unchanged v2 epochs on 210/300/302/311. |
| `channel-composition.` | 60 | 36 dialect/protection/v1-v2/Batch-lease combinations plus 24 controlled claim/LOGOFF races. Loss of primary retains the same FileId on survivor; final loss is followed by new-session reconnect, replay/lock checks, rebind and cross-channel close. |
| `p7c.reconnect.deadline-during-preparation` | 1 | Virtual-clock deadline passes while metadata is suspended; no late reconnect publication without a scavenger. |
| New registrations | **371** | All execute as ordinary tests. Four initial composition registrations were expanded to sixty; the total is not inflated by counting inner operations. |

The peers independently construct SP800-108 with BCL HMACSHA256 and preauth with
BCL SHA512 over wire bytes. Channel/composition tests implement CMAC from AES-ECB
and check RFC4493 literal examples, and independently assemble GMAC/AEAD inputs.
They do not read server keys. NTLM credential generation uses the existing
fixture primitive; this is not an independent NTLM implementation. Metadata and
transport barriers control scheduling after real wire grants, without injecting
sessions, grants or retained records as acceptance setup.

Acceptance source: [channels and composition](../../tests/Smb.Tests/MultichannelWireTests.cs),
[durable reconnect](../../tests/Smb.Tests/DurableRecoveryTcpTests.cs),
[cache sequences](../../tests/Smb.Tests/CacheSequenceRecoveryTests.cs) and
[deadline/lifecycle regressions](../../tests/Smb.Tests/P7cTests.cs).

Focused settled regressions also pass P3 64/64, P6 88/88, P7 228/228, P8 125/125,
authentication 203/203 and final-protocol 17/17. Published Linux JIT and Native
AOT each execute 3,515 cases: 3,415 passing and 100 failing, with identical
failed names. One retained notify case differs only in its first timeout
diagnostic; the exact difference is listed with the failure names. All 371
additions pass in both modes.
The 26-stage settled capture has unchanged source manifests, 430 verified
artifact hashes, both actual local TCP workloads and all repeated stress/expiry
checks passing. Its two full-harness stages and aggregate result remain failed.
See [platform validation](platform-validation.md).

## RED/GREEN evidence and valid fixture corrections

New evidence was allocated externally at runtime. Each capture retains exact
argument arrays, original output/exit status, source hashes/diffs and identities.
No original archive or prior evidence was changed. Maintained tests run offline
without those captures or upstream clones.

| Batch | Observed relevant RED before behavior change | Settled GREEN |
|---|---|---|
| Channel transcript and admission | Initial 49 cases: 35 failures; enabling only the dialect gate still left 32 failures, including independently verified final signatures. Lifecycle 36 cases: 16 failures. | 131 channel cases. |
| Protection and notification boundaries | Separate key-width/capability, encrypted LOGOFF, terminal binding GSS and distinct FullSessionKey vectors failed. Plain unsolicited signing and encrypted lease-transform REDs preceded repairs; six encrypted-classic fixture signature diagnostics were excluded as invalid REDs. | Channel suite, authenticated ACK rejection and encrypted completion checks. |
| Durable contexts/session recovery | Existing durable 82 cases: 29 failures; replay 41 cases: 32 failures. New TCP grant/PreviousSessionId/context failures reproduced before production changes. Initial incorrect metadata-access and cross-session replay expectations were corrected and preserved separately. | 151 durable TCP cases and 138 original durable cases. |
| Cache keep/purge and replay | TCP cache 16 cases: 12 failures; declined-cache completed replay 3/3 failures. | Durable/cache suites and applicable retained source workflows. |
| Deadline and response retirement | Reconnect after metadata passed its deadline incorrectly; a separate controlled reconnect/LOGOFF race lost its response signature. Each failed independently before its fix. | Deadline test and all 24 composition race cases. |
| Shared lease coordination | Corrected 24-case TCP fixture: 15 failures; a later four-case purge test proved stale unreachable sharing reservations. | 28 cache TCP cases; both original bounded complex sequences pass. |
| Integration | Native capacity status failed on all three dialects; independent admission/publication race REDs preceded the selected status change. Same-name rename produced two breaks where exactly one foreign break was required. | Native capacity and 60 composition cases; exact single-break rename and complete compound finals. |

Original adapted fixtures sometimes imposed invalid wire or scheduling
assumptions. Their original results and source are preserved externally:

- STATUS_PENDING need not be signed. Peers still verify any present signature
  and require authenticated ordinary finals; AEAD-protected traffic is verified
  through its authenticated transform.
- Mixed compound synchronous and asynchronous components require following
  each matching MessageId/AsyncId final. The corrected collector verifies every
  component signature/status, exact single completion, pre-ACK nonmutation and
  final bytes/names. It does not treat an interim as success.
- Windows's standalone-rename timing preference is not a universal synchronous
  requirement under [3.3.4.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/c1692ece-7c6d-45c8-a0e3-6b53c0483030).
  Corrected tests withhold ACK and verify the complete permitted async exchange.
- A validly signed terminal binding GSS failure retires the session under
  3.3.5.5.3. The old Microsoft adaptation substituted a wrong-password final for
  its source's malformed first-token retry. Its revised oracle verifies
  retirement, fresh authentication and binding on the existing transports,
  followed by failed bound reauthentication. Bad signatures preserve the session;
  an authenticated different owner cannot replace it. Samba's conflicting
  terminal-survival expectation is documented separately from those branches.
- The old two-transport complex-sequence collector abandoned one wait, which
  could consume the next wake-up. Canceling/joining that wait preserves every
  original key/state/break/status/byte assertion. A queued unsolicited notice
  may also precede an ACK response; peers buffer and validate it rather than
  discard it. Disposal asserts the notice buffer is empty.

No expected-failure conversion, skip or automatic retry makes these tests pass.
Broader exact-grant/source conventions remain ordinary failing tests below.

## Independent native interoperability

Against the integrated explicit recovery host, native Samba 4.19.5 runs:

| Selection | Result | Scope |
|---|---|---|
| Signed primary/default | 18/18 processes pass | Exact-byte roundtrips, interface query, real multichannel oplock exchange, v1 reconnect/position and v2 reconnect on 300/302/311. |
| Additional durable/capacity | 9/12 pass | All capacity and v1 lock-retention processes pass. Three v2 leased reconnect processes retain the older filename-status mismatch. |
| Required encryption | 9/9 pass | Encrypted exact bytes, interface query and durable-v1 lock reconnect on each dialect. |
| Pinned Go public client | 6/6 pass | Signed I/O and actual BindChannel/same-FileId reads after primary TCP loss, including 311. |

These are processes in overlapping bounded selections, not new harness cases or
whole-suite conformance. Native shutdown completes without forced termination.
Samba's three retained failures expect INVALID_PARAMETER for a v2 leased wrong
filename; current 3.3.5.9.12 requires OBJECT_NAME_NOT_FOUND. The independent
maintained client checks that status and subsequent rightful recovery.

The Go client revision is `7f69f65878329522ceb556435bdeb3cde6552656`.
An earlier assessment inferred SMB311 key reuse from a stale public comment.
Inspection of the actual protocol implementation and successful execution
correct that assessment: binding requests use the original key, while the new
transcript/authentication exchange derives and verifies the channel key. The
client was not patched to bypass verification. Samba tool binaries are Ubuntu
4.19.5, distinct from the newer pinned source inventory; source/version hashes
and that distinction are retained in external evidence.

## Remaining failures and boundaries

The [exact name differences](recovery-failure-differences.txt) list 127 resolved
baseline names, 100 retained failures and zero new failing names. All 371 new
registrations pass. Of the remaining failures, 84 are Samba continuation and
16 are previously retained inventory/original-Samba cases. Whole-project
acceptance remains failed.

Seven retained durable/replay source rows need explicit interpretation:

- `durable.{1,2}.lock-no-write-lease` expects RH loss. Current connection-loss
  and reconnect rules preserve held HANDLE caching; successful RH recovery is
  tested on TCP. Purging merely because WRITE is absent would violate that rule.
- `replay.source.batch-none` expects a changed response grant, and
  `replay.source.batch-to-lease` expects ACCESS_DENIED for an added lease request
  on an originally nonleased replay. Current processing reconstructs the
  established Open and applies the lease-denial predicate when Open.Lease exists.
  The selected implementation preserves the established grant without inventing
  a new lease; the source expectations remain failing.
- Three `replay.recovery.*` rows require cross-session CREATE replay recovery
  without explicit DH2C. Current rules return DUPLICATE_OBJECTID for another
  session; the cross-session persistent recovery branch requires persistent
  capability, a CA share and the persistent flag, none of which are offered.
  Tests independently verify explicit DH2C followed by same-session replay.

Other unresolved cache workflows include exact split RH-to-R overwrite targets,
Caching-profile share-denial-first notification sequencing, contended promotion,
mixed classic/lease grants, lock-bearing caching, version/epoch and namespace
preferences. Notify event reproducers, optional streams, descriptor markers and
other inherited cases remain visible. Both bounded cross-session complex cases
are repaired; this does not imply all cache/notification sequences are complete.

Linux evidence cannot certify native Windows JIT/AOT, UNC behavior or real-NIC
failover. Native Windows remains unexecuted. The delivery does not establish
full Kerberos/domain integration, complete security/dialect conformance or
external filesystem coherence.
