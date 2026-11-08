# Correctness acceptance

Review of the Windows/Linux implementation and fresh Linux JIT/AOT delivery
validation completed on 2026-11-08: 854/854 tests per mode plus actual LocalFileStore
TCP workloads. See [platform validation](platform-validation.md) for commands and
remaining native Windows verification.

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

- External Samba 4.19.5 attempts stopped during excluded authentication before file
  operations; no external file-operation pass was established.
- SMB 3.1.1 bound signing/preauthentication blocked advanced recovery validation;
  multichannel and durable recovery remain withheld for that dialect.
- Persistent handles and continuous availability lack an atomic recovery journal
  and process-restart/failover tests; they remain unavailable.
- QUIC import/generation provenance is incomplete. Later user edits require their
  own review; historical byte-match observations do not certify the current tree.

Authentication, authorization, signature verification, encryption, key derivation,
preauthentication integrity and security-oriented path isolation remain outside
this correctness task. No security, full SMB3 conformance, production-readiness or
unqualified redistribution claim follows from passing local tests.

Raw historical evidence is retained externally without rewriting recorded paths,
hashes, or results. Maintained source and tests have no dependency on that archive.
