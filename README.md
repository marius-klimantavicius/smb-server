# SmbServer

Maintained C# source reconstruction of KaimoSystemSolutions **SMB-Server 2.1.1**,
with correctness repairs through P7c/P8 and an expanded upstream protocol/auth campaign.
This is a reviewable checkout, not a production-ready or certified SMB release.
The coordinator still owns acceptance: historical TDD-order exceptions are pending,
native Windows is untested, and QUIC
attribution is not fully resolved. See [acceptance](docs/correctness/acceptance.md).

Use the .NET SDK selected by `global.json` (observed 10.0.114). The core runtime
projects use source project references with no original package DLLs. The optional
[SQLite provider](docs/sqlite-provider.md) uses the supplied transpiled C# SQLite
engine and Ews.Common.Sqlite framework. It needs no native SQLite deployment.
The executable harness uses no third-party test framework.
Optional [durable restart recovery](docs/durable-recovery.md) adds an abstract
recovery journal with a SQLite implementation. Clients authenticate again after restart.

```sh
dotnet restore SmbServer.slnx
dotnet build SmbServer.slnx -c Release
dotnet run --project tests/Smb.Tests -c Release -- --list
dotnet run --project tests/Smb.Tests -c Release
dotnet run --project test-host/Smb.TestHost -c Release -- localtest
# Fresh restore, rebuild, JIT/native publish, full tests, hosts, stress and identities.
# The output path must not already exist.
python3 scripts/validate-platform.py --out "$SMB_VALIDATION_OUTPUT"
```

Set `SMB_VALIDATION_OUTPUT` to a new directory outside the source tree. The portable
runner builds and runs on its native Windows or Linux host; on Windows use
`python scripts/validate-platform.py --out $env:SMB_VALIDATION_OUTPUT` in PowerShell.
Native AOT needs the host C++ toolchain. No external archive is required.

`dotnet test` is not the harness entry point. Historical P8 published JIT and linux-x64
Native AOT harnesses passed **837/837** tests; that result does not validate later source.
The former F08 baseline assertion now passes normally. Both published hosts run
`selftest` (fake backend) and `localtest` (actual local backend, real TCP,
required signing). Four persistent JSON AOT diagnostics and the fixture identity
reader IL3000 have been recorded; see [provenance](docs/correctness/provenance.md).
Windows AND Linux are required local-backend platforms. The platform implementation
has been reviewed; the first upstream campaign passed **940/940** in Linux JIT
and Native AOT plus actual LocalFileStore TCP workloads. That result is historical.
Native Windows execution is outstanding and
will be tested by the user. See [platform validation](docs/correctness/platform-validation.md).
The historical [broader upstream campaign](docs/correctness/upstream-tests.md) has **3,144
registered cases**: the previous 940 plus 2,068 protocol/auth adaptations and 136
focused repair regressions. It surveys pinned Samba, Microsoft FileServer and five
Go server/client projects. Run `--filter upstream.` for upstream-related cases;
some deliberately retain failing compatibility expectations. Use the platform
driver's `--keep-going` to capture all independent gates with a failing final exit.
That campaign's Linux JIT and Native AOT each pass **2,917/3,144**, with the same **227
failures**. Both host/TCP workloads and repeated stress/expiry checks pass; the
aggregate gate remains failed. See the campaign report for exact dispositions.

| Explicit profile | Copy | File caching | Multichannel | In-memory durable |
| --- | --- | --- | --- | --- |
| Restricted (default) | No | No | No | No |
| CopyOnly | Yes | No | No | No |
| Caching / CachingWithCopy | Optional | Yes | No | No |
| MultichannelOnly / MultichannelWithCopy | Optional | No | Yes | No |
| MultichannelWithCaching / MultichannelWithCachingAndCopy | Optional | Yes | Yes | No |
| Durable / DurableWithCopy | Optional | Yes | No | Yes |
| DurableWithMultichannel / DurableWithMultichannelAndCopy | Optional | Yes | Yes | Yes |

Multichannel also requires `EnableMultichannel=true` and supports **SMB
3.0/3.0.2/3.1.1**. In-memory durable v1 supports **SMB 2.0.2 through 3.1.1**;
v2 requires SMB3. Mandatory SMB3 channel sequencing applies under every profile,
including Restricted. The [recovery delivery](docs/correctness/multichannel-durable-reconnect.md)
adds 371 regressions, bringing the harness to **3,515 cases**. Its settled
integration run passes **3,415**, with **100 retained failures** and no new
failing names. See [platform validation](docs/correctness/platform-validation.md)
for published-mode results and [Linux/Windows recovery examples](docs/correctness/multichannel-durable-configuration.md)
for explicit opt-in configuration.

The subsequent [remaining-failure repairs](docs/correctness/remaining-failure-repairs.md)
resolve all 100 registered failures and add 382 regressions. The settled
integration harness and published Linux JIT/Native AOT each pass **3,897/3,897**,
including all prior cases. All 26 Linux platform stages pass. Production
repairs and documented specification/profile oracle corrections are distinguished
in the report; original source expectations and results remain archived. Current
published Linux results are recorded in platform validation. This is not native
Windows or whole-dialect certification.

Caching/durable grants require a stable-identity coherent backend and an explicit
exclusive-server-access assertion. `new LocalFileStore(root, false)` permits
ordinary operations but withholds caching. Only use its four-argument constructor
with `exclusiveServerAccess:true` when all backing-data access and mutation go
through one server state. This is a deployment assertion, not an OS lock.

Directory leases, persistent handles, CA shares and local allocation are unsupported.
`FileDurableHandleStore` is rejected by profile validation; there is no cold recovery.
Streams/EAs, including promoted logical default streams, are process-memory only;
native unnamed-source to named-stream rename remains unsupported. Unbuffered I/O is advisory; local metadata is
not an NTFS implementation. See [capabilities](docs/correctness/capabilities.md).

For a disposable loopback share, provide an existing credential file:

```sh
dotnet run --project test-host/Smb.TestHost -c Release -- serve /absolute/disposable/root 1445 WORKGROUP testuser /absolute/password-file
```

The share is `P0`; the published JIT/native host accepts the same arguments.
Signing remains required. No authentication, authorization, signature, encryption,
key-derivation, preauth or security-path certification is implied. Existing user
QUIC edits and attribution limitations remain outside this platform repair.
The expanded campaign includes authentication tests and focused repairs. Fresh
signed Samba file operations and independent Go client operations now execute;
see [acceptance](docs/correctness/acceptance.md) for their limits.

The [repair plan](docs/correctness-repair-plan.txt), [findings](docs/correctness/findings.md),
[acceptance gaps](docs/correctness/acceptance.md) and [test API notes](tests/README.md)
retain the current contracts and limits. Raw historical evidence and original
archive inputs are external; ordinary builds, tests and workloads do not require them.
Reconstruction is separate from behavioral repairs; see [build reconstruction](docs/validation/build-reconstruction.txt).

The original [Apache-2.0 LICENSE](LICENSE) is unchanged. [NOTICE](NOTICE) and
[provenance summary](docs/correctness/provenance.md) describe pre-existing MIT components
and the remaining attribution blocker. The top-level license does not replace
third-party notices.
