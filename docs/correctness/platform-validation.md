# Windows and Linux platform correction — 2026-11-08

The local backend now has Windows and Linux implementations. Supervisor review
and fresh Linux delivery validation are complete. Native Windows JIT/AOT execution
is unexecuted; the user will test it later. Both-platform acceptance remains open.

## Implementation

Windows uses UTF-16 Win32 APIs and SafeFileHandle lifetime management. Identity
is the volume serial and all 128 file-ID bits returned by
[GetFileInformationByHandleEx](https://learn.microsoft.com/en-us/windows/desktop/api/winbase/nf-winbase-getfileinformationbyhandleex).
Microsoft documents comparison of the complete volume/file-ID pair for object
identity in [FILE_ID_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info).
There is no pathname-derived identity fallback. Linux retains statx device/inode
identity and pinned descriptors. The deterministic 64-bit wire index is separate
from the full coordination identity.

Windows directory pins use backup semantics and read/write/delete sharing through
[CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).
Native rename/disposition handles verify the expected full identity before mutation;
final nonrecursive deletion runs while the last backend pin remains held. Metadata
access reopens the acquired object through
[ReOpenFile](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-reopenfile).
Rename and disposition layouts follow
[FILE_RENAME_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info)
and [FILE_DISPOSITION_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_disposition_info).

The repair covers same-name/case-only rename, descendant names and pending-delete
paths, shared hard-link disposition, pinned metadata, stable enumeration indexes,
host case matching, Unicode/drive/UNC API paths, directory pin cleanup and native
handle sampling. Shell hard-link fixtures and the Linux-only case expectation
were replaced with portable native fixtures and explicit host expectations.
The actual LocalFileStore workload still uses TCP and the production OS watcher.

Five Linux-reproducible defects had observed behavioral REDs before their repairs:
same-name rename, enumeration object indexes, metadata after pathname replacement,
named-stream indexes after rename, and pending-child deletion after parent rename.
All passed GREEN. Some captures observed concurrent user formatting; those records
do not claim frozen source. Windows-only contracts remain prospective tests,
without fabricated REDs or runtime results. A timing-sensitive cache test was also
corrected to await the owner's final WRITE before inspecting its bytes.

## Reproduce

Install the SDK selected by `global.json`, Python 3.9 or later, and the native
host toolchain. Linux needs clang and development dependencies; Windows needs the
Visual Studio Desktop development with C++ workload and Windows SDK. See
[Native AOT prerequisites](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/).

Set `SMB_VALIDATION_OUTPUT` to a fresh directory outside the source tree, then run
from the repository root:

```sh
python3 scripts/validate-platform.py --out "$SMB_VALIDATION_OUTPUT"
```

Windows PowerShell:

```powershell
python scripts/validate-platform.py --out $env:SMB_VALIDATION_OUTPUT
```

The same runner restores/rebuilds, publishes both JIT and Native AOT harness/host,
runs the full harness, selftest and actual localtest, and repeats stress/expiry
checks three times per mode. It selects the native host RID and records commands,
host identity, source hashes and artifact hashes. Optional `--temp-root` accepts
an existing writable scratch root, including a configured UNC share, for fixture
coverage. It never treats cross-publish or Wine as native Windows validation.

Ordinary restore/build/test and the runner require no evidence archive. The
optional `scripts/audit_evidence.py` utility requires `--evidence-archive` or
`SMB_EVIDENCE_ARCHIVE`, plus fresh `--out`; it accepts optional `--baseline` and
`--quic-source`/`SMB_QUIC_SOURCE`. Invalid configuration fails before output writes.
Run its focused configuration checks with:

```sh
python3 scripts/test_portable_tools.py
```

## Observed supervisor results

Linux x64, kernel 6.8, glibc 2.39, SDK 10.0.114, Python 3.12.3: all 26 delivery
steps exited zero. Published JIT and Native AOT each passed 854/854 tests, both
host selftests and 12-round real LocalFileStore TCP workloads. Each mode also
passed three 8-test stress selections and three 1-test expiry-race selections.
All 52 per-step source manifests matched the initial and current source; all
430 published artifact hashes verified. No source drift occurred in this run.
The only analyzer categories recorded were existing IL2026/IL3050 at persistent
JSON sites; supported profiles reject that persistent store.

The portable-tool suite passed 12/12 checks. A final maintained-tree audit checked 483
files and found no machine-specific evidence dependencies or broken Markdown
links. The raw evidence tree was relocated losslessly: 6,180 files and
1,244,875,645 bytes; the historical review was preserved byte-for-byte. Three
earlier temporary script edits were reversed with edited copies and restoration
hashes retained externally. The separate original 360-file archive still matches
its baseline. No repository evidence directory, symlink, GitHub configuration,
staging operation, commit or push was introduced by the agents.

## Outstanding validation and limits

Native Windows and UNC execution, Windows error/cleanup behavior, case-only rename,
disposition and Native AOT interop still need actual host runs. FILE_ID_INFO-capable
filesystems are required. Specialized Windows per-directory case-sensitive setups
are unvalidated. External OS handles can defer Windows final deletion; coordinated
namespace access remains required. Streams/EAs are process-memory, ChangeTime is
approximate and notifications are best effort. Historical TDD exceptions,
external authentication blockers, persistent/CA and QUIC provenance limitations
remain in [acceptance](acceptance.md) and [provenance](provenance.md).
