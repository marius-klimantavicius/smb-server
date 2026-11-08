# Source and license provenance

The reconstructed package is SMB-Server 2.1.1. Its original package SHA-256 is
`decda113d70df16bcd5805f1da941642fd6c54faf3fc9ebaf9618ed151774185`.
The original Apache-2.0 [LICENSE](../../LICENSE) is preserved. [NOTICE](../../NOTICE)
and [component notices](../notices/) retain demonstrated .NET, MsQuic, picotls and
DotCC MIT attribution. No native SMB implementation is used.

Historical P8 inspection matched 47 of 80 pre-existing QUIC files exactly to
inspected current, generated or historical outputs; 33 remained unmatched. The
candidate upstream pins were MsQuic `80a065112426bce68c1da42d026478d3e40fd45e`
and picotls `3598470df01264da85157025ed10db0f7e103790`. Exact matches establish
observed bytes, not the complete input-to-output import/generation chain.

The full import manifest, exact wrapper/generator/runtime revisions, input closure
and modification attribution remain unresolved. User QUIC edits made after P8
are outside that historical byte-match assessment. No unqualified redistribution
or provenance acceptance is claimed.

All six runtime projects use source project references. Routine builds, tests and
publishes must load their rebuilt output without requiring original package DLLs,
external evidence or a machine-specific directory. Native AOT has no individually
loaded assembly files; JIT identity checks use the application output directory.

Historical public persistent JSON methods emitted IL2026 and IL3050 for reflection
serialization/deserialization. Supported profiles reject that persistent store;
those methods are not certified AOT persistence APIs. The fixture identity reader
has also emitted IL3000. Current diagnostics must be assessed on each fresh run.
