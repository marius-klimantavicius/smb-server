# Supported contracts and limits

The required local backend platforms are Windows and Linux. The platform code has
been reviewed and fresh Linux JIT/AOT runs pass 854/854 tests per mode plus actual
local-backend TCP workloads. Native Windows JIT/AOT execution remains outstanding.
See [platform validation](platform-validation.md) and [acceptance](acceptance.md).

| Explicit profile | Copy | File caching | Multichannel | In-memory durable |
|---|---|---|---|---|
| Restricted (default) | No | No | No | No |
| CopyOnly | Yes | No | No | No |
| Caching / CachingWithCopy | Optional | Yes | No | No |
| MultichannelOnly / MultichannelWithCopy | Optional | No | Yes | No |
| MultichannelWithCaching / MultichannelWithCachingAndCopy | Optional | Yes | Yes | No |
| Durable / DurableWithCopy | Optional | Yes | No | Yes |
| DurableWithMultichannel / DurableWithMultichannelAndCopy | Optional | Yes | Yes | Yes |

Multichannel also requires `EnableMultichannel=true`. Advanced multichannel and
durable recovery are limited to SMB 3.0/3.0.2. Mandatory SMB3 channel sequencing
applies under every profile. SMB 3.1.1 recovery remains withheld.

| Surface | Contract and practical limit |
|---|---|
| Stable identity | Identity must be acquired from a live OS handle, survive rename/hard links and remain valid while the handle is held. Linux uses statx device/inode; Windows requires volume serial plus stable file ID. No pathname-derived identity fallback. |
| Deletion | Shared object/stream delete-pending, rejection of new opens, clearing through a live open, fallible final close and nonrecursive directory deletion. Replacement objects must not be deleted. |
| Caching / durable | Requires a stable-identity coherent backend and explicit `exclusiveServerAccess:true`: all access, aliases and mutation use one server state. This deployment assertion is not an OS fence. |
| Enumeration | Bounded resumable cursor, restart/reopen/pattern handling and cleanup. Matching follows the explicit host case contract. |
| Notifications | Per-open bounded FIFO, filter/subtree, loss/error rescan and actual OS watcher. Best effort, not a journal. |
| Copy | Explicit profiles only; source/destination locks, operation lifetime and cache coordination, overlap/partial progress. |
| Allocation / buffering | Local allocation unsupported; unbuffered I/O advisory. Flush/write-through tests do not prove power-loss durability. |
| Metadata | Streams/EAs are per-store process memory; base data and host timestamps persist. ChangeTime is approximate; no full NTFS metadata guarantee. |
| Persistent / CA | No grants; FileDurableHandleStore is rejected by supported profiles. Public JSON APIs remain outside supported AOT persistence. |
| Legacy stores | Conservative per-store identity; shared deletion and coherent caching require explicit backend opt-in. Overlapping namespaces need shared coordination. |

The test harness uses independent raw-wire expectations and real local TCP
workloads. Passing selected cases does not establish whole-dialect conformance or
external client interoperability. Current test commands are in [tests](../../tests/README.md).
