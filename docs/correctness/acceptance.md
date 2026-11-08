# Correctness acceptance

The first upstream campaign's Linux JIT/AOT delivery on 2026-11-08 passed
940/940 tests per mode plus actual LocalFileStore
TCP workloads. See [platform validation](platform-validation.md) for commands and
remaining native Windows verification.

The [upstream-test campaign](upstream-tests.md) added 86 adapted scenarios from
pinned Samba, SMBLibrary and Microsoft FileServer conformance tests. The captured
original production baseline passed 66 and failed 20 of those additions; six
focused defect groups were repaired with retained RED/GREEN evidence. The final
published Linux gate passed all 26 delivery steps with stable source. This does
not waive the historical qualifications below. The broader second campaign
supersedes those counts: 3,144 registered cases, including authentication and
independent Go/Samba client execution. Its inventories and repair records are
linked from [the campaign report](upstream-tests.md); final published results
are recorded in [platform validation](platform-validation.md): JIT and Native AOT
each pass 2,917/3,144 with the same 227 failures. All other 24 driver stages pass,
including both actual local TCP workloads; source is stable during the capture.
The aggregate platform result remains fail. Test-port completion
does not mean functional acceptance: compatibility failures and unresolved bounded
cache/notification reproducers remain ordinary failures.

Windows and Linux LocalFileStore support are required. Native-host JIT and Native
AOT runs must exercise the full harness and the actual LocalFileStore TCP workload
on both platforms. Windows execution is outstanding; the user will run it later.
Cross-compilation and Wine results cannot certify native Windows AOT.

Historical P0–P7c repairs and local P8 validation established useful Linux behavior.
The historical 837/837 JIT and Native AOT results apply to that earlier source,
not to subsequent platform or QUIC changes. Native Windows execution is still
required for both-platform acceptance.

The following historical test-first qualifications remain unapproved. Moving raw
evidence does not waive them, and later GREEN tests cannot recreate their order.

| Phase | Qualification |
|---|---|
| P2 | Send-failure candidate preceded a valid fixture; withdrawn, then reproduced RED before the final repair. |
| P5 | READ size and invalid directory-class drafts preceded valid REDs; withdrawn, reproduced and reapplied. |
| P6 | Timeout/release, backend withholding, READ/COPY and v2 epoch branches first tested GREEN; COPY cancellation forwarding preceded a valid physical-retirement fixture. |
| P7a | Pipe CREATE initialization preceded pipe-specific RED; corrected CLOSE fixture first passed GREEN; initial inspection evidence was incomplete. |
| P7c | Detached same-client lease fallback preceded a valid negotiated fixture; reconnect predicates lack independent original RED; some combinations first tested GREEN. |

Strict M1/M2 acceptance remains incomplete. Other limits persist:

- The earlier external-auth blocker was reproduced and repaired. Fresh signed
  Samba operations and two pinned independent Go clients execute selected file
  workflows; this establishes those selections, not entire-suite interoperability.
- SMB 3.1.1 bound signing/preauthentication blocked advanced recovery validation;
  multichannel and durable recovery remain withheld for that dialect.
- Persistent handles and continuous availability lack an atomic recovery journal
  and process-restart/failover tests; they remain unavailable.
- QUIC import/generation provenance is incomplete. Later user edits require their
  own review; historical byte-match observations do not certify the current tree.

The user explicitly included protocol/authentication coverage in the second
campaign, superseding the original authentication exclusion. Focused signing,
encryption-boundary, descriptor and CREATE admission repairs are documented;
broader security architecture, privilege/claims support and unavailable domain
infrastructure remain limited. No security, full SMB3 conformance, production-readiness or
unqualified redistribution claim follows from passing local tests.

Raw historical evidence is retained externally without rewriting recorded paths,
hashes, or results. Maintained source and tests have no dependency on that archive.
