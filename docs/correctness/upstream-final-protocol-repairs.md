# Final bounded IOCTL and reauthentication repairs

Subsequent [multichannel/durable work](multichannel-durable-reconnect.md) adds
SMB311 channel transcripts and response-protection retirement fixes while keeping
all 17 regressions here passing. It also reconciles terminal binding GSS failure
with primary-spec teardown. Counts and source hashes below identify this earlier
handoff; current results are in the later report and platform validation.

This report follows the settled 737-case Samba continuation handoff (523 PASS,
214 FAIL). It addresses the three assessed findings only. Earlier cache,
authentication/parser, descriptor, CREATE authorization and grant repairs remain
in place. No prior evidence archive was modified. New evidence is in the fresh
external campaign allocation `final-protocol-repair/`; tests have no dependency
on that allocation, network downloads or foreign implementations.

## Normative assessment and changes

[MS-SMB2 3.3.5.15](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/c348a671-7750-49f8-9e61-cc59fa1a5701)
requires NOT_SUPPORTED for IOCTL Flags other than SMB2_0_IOCTL_IS_FSCTL. It
requires the all-ones FileId for DFS_GET_REFERRALS, DFS_GET_REFERRALS_EX,
QUERY_NETWORK_INTERFACE_INFO, VALIDATE_NEGOTIATE_INFO and PIPE_WAIT, with
INVALID_PARAMETER for violations. Ordinary controls must locate the open and
return FILE_CLOSED when absent. These are MUST requirements; optional-control
support and compatibility policies are separate.

The dispatcher now validates Flags, then the server-control FileId, then ordinary
open existence, before profile checks and control-specific parsing/output size.
The existing compound FileId classification also governs operation lifetime
acquisition, so a server control carrying a real file's ID cannot accidentally
enter file/tree ownership checks ahead of its sentinel validation. Both halves
of the sentinel are required. Valid network-interface requests retain capability,
profile and output-size behavior. Zero-access and ordinary tree policies remain
covered by the unchanged `limited-tree-controls` case. No new backend capability
or mutation is introduced.

The original `compound.bad-ioctl` RED was **not an open-lookup defect**. Its packet
is a valid file-scoped control (0x900c0, Flags=1, fixed size57, no input). However,
its two preparatory ECHOs only obtained IDs through96; the first compound
component used101, outside that window. The dispatcher correctly rejected the
sequence before IOCTL handling. A single preparatory signed ECHO now obtains
the additional grant. The original two-component [FILE_CLOSED, FILE_CLOSED]
IOCTL/dependent-CLOSE vector and all signing assertions are unchanged. With this
fixture correction alone, unchanged production passes. An independent TCP probe
using sequential granted IDs also passed before any production change. The
original failing log and complete original source remain archived.

[MS-SMB2 3.3.4.1.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d594481c-f6d5-4de5-8842-9099063d41e7)
says the server SHOULD sign applicable signed-request responses. Once an SMB3
non-success SESSION_SETUP response is signed, use of Session.SigningKey instead
of Channel.SigningKey is MUST. The separate
[client verification rule, 3.2.5.1.3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/36172e53-ac81-48fb-b2e3-caa3761b9157)
requires verification with the established session key for these responses and
discard on failure. The original unsigned terminal LOGON_FAILURE therefore
breaks this existing-session client exchange; the server's general signing
recommendation is not relabeled a blanket MUST.

Failed reauthentication now captures only a response-local copy of the original
signing key before retiring the session. It still closes trees/opens, terminates
pending notify with NOTIFY_CLEANUP, clears channels and removes session indexes.
The response does not retain a failed live session or accept subsequent old-ID
operations. Non-success SESSION_SETUP assembly selects the session key; ordinary
responses select the channel key. Bound-channel probes prove this distinction
with independently negotiated, unequal session/channel keys. Initial unsigned
authentication failures/challenges still have no signer. A bad request signature
is rejected before authentication and preserves the existing session, unlike a
validly signed terminal authentication failure. Encryption negotiation and
transport wrapping were not changed.

## New independent probes and RED/GREEN evidence

`UpstreamFinalProtocolTests.Cases()` adds 17 ordinary registrations under
`upstream.final-protocol.`. Every probe executes public SMB messages. The IOCTL
matrix uses signed direct dispatch except the independently signed compound TCP
probe. All authentication probes perform actual loopback TCP NEGOTIATE/NTLM;
no session, channel key, open or pending-notify record is injected. Existing
NTLM and CMAC helpers construct tokens and signatures; literal statuses, response
fields, BCL HMAC for SMB2, old-key verification, cross-session bytes and lifecycle
outcomes provide the oracles. These are local adapted clients, not independent
external-client interoperability claims.

| Probe group | Registrations | Observed pre-repair result | Final result |
|---|---:|---|---|
| Granted-ID compound IOCTL/CLOSE | 1 | PASS; confirms original fixture fault | PASS |
| Ordinary control Flags/open/structure ordering | 1 | FAIL: FILE_CLOSED instead of NOT_SUPPORTED for invalid Flags | PASS |
| Five server controls, both output limits, partial/zero/real IDs, ordinary/zero-access trees | 5 | FAIL: control-specific errors or empty termination instead of sentinel rejection | PASS |
| Network profile and output bounds | 1 | FAIL: profile rejection precedes invalid FileId | PASS |
| Failed reauth over SMB202/210/300/302/311 TCP | 5 | FAIL: terminal LOGON_FAILURE unsigned | PASS |
| Failed reauth over separately authenticated SMB300/302 bound channels | 2 | FAIL: continuation signed with channel key instead of session key | PASS |
| Invalid request signature preserves session | 1 | PASS | PASS |
| Initial failed authentication has no key | 1 | PASS | PASS |
| Total | 17 | 3 PASS / 14 FAIL | 17 PASS / 0 FAIL |

The first RED build/run preceded production edits. No new probe or its expected
result changed afterward. `original-red-0/1/2` preserve the three original
failures. `fixture-corrected-original` records the compound fixture correction
passing against unchanged production. `independent-red` and `independent-green`
record the new cases. Every capture has exact argument arrays, complete relevant
source archive, before/after SHA-256 maps, status and staged/unstaged diff,
original output and exit status. All build/run source maps are stable within
their captures. Four fresh build output sets have assembly name/version/MVID/
SHA-256 identities; runtime logs identify the actual loaded core assemblies.
The fresh Release builds report zero warnings/errors.

## Regression results and handoff

The prior 940 tests all passed across the captured selections; their exact union
is recorded in `prior-940-summary.json`. This union uses the established prior
registrations, not a claim that every substring-filter result passed: `wire.`
also selects later source-compatibility names, including four unchanged durable
recovery failures. The focused `compound.` selection likewise retains its four
previously archived compatibility failures. Three initially misspelled repair
filters selected no tests (exit2); corrected selections below executed normally.
No skipped or expected-failure registration was introduced.

| Selection | Final observed result |
|---|---|
| Prior regression union | 940 / 940 PASS |
| Go | 83 / 83 PASS |
| Microsoft | 297 / 297 PASS |
| Descriptor / descriptor findings | 25 / 25 and 2 / 2 PASS |
| CREATE authorization / grant repairs | 34 / 34 and 24 / 24 PASS |
| Cache repair / prior file repair | 27 / 27 and 7 / 7 PASS |
| Original Samba auth | 31 / 31 PASS |
| Original Samba session | 40 PASS / 1 retained OS2-name compatibility FAIL |
| IOCTL continuation / notify auth lifetime | 9 / 9 and 4 / 4 PASS |
| New independent probes | 17 / 17 PASS |
| Complete Samba continuation | 737 total / 526 PASS / 211 FAIL |

The complete continuation capture has exactly the previous failure set minus the
three assessed findings, with **zero new failing names**. Two retained failures
have different first diagnostics: `notify.security-update.100.False` reports
"No recorded send" instead of the earlier generic timeout;
`lease.cross-session-complex.False` reaches its RH-grant assertion (actual NONE)
instead of the earlier timeout. These remain unresolved, with neither retry nor
expectation change. `samba-more-comparison.json` records the exact name/error
comparison. The compound improvement is attributed to the verified fixture
correction, not production. This is not a passing continuation suite.

The maintained registration list has **3,144 unique names**, with no duplicates:
3,127 previous names plus17 new names. `registrations.txt` SHA-256 is
`019d63668f4fa26336dca01395c4340d23919daf14c8e87c04e8fcf0024c2673`.
The settled executable source-map aggregate is
`9f24928c81382e33155ea904fc3ca04573c450e4438b884bb08fc5f713767d66`;
`settled-source.json` specifies its canonical-JSON hashing method and every file.
The only production file changed by this task is `Smb2Dispatcher.cs`, SHA-256
`d82793ad870445da16bc42ee60c5b1bbd88d6bbca011315fe6d8ddec4cf5aa58`.
The other executable source changes are one registration line, the narrowly
corrected compound credit setup, and the new independent test file. The index
remains byte-for-byte unchanged; no staging, commit, restore or reformat occurred.

Full published JIT/Native AOT harness and real LocalFileStore TCP platform gates
remain parent-owned after source freeze; this task did not run that driver.
Native Windows is unavailable. Cache grant/retention choices, cache timeouts,
backend notify timing, stream promotions and inheritance compatibility failures
retain the boundaries documented in the existing reports. This change does not
convert those failures into passes or promise broader auth/encryption architecture.
