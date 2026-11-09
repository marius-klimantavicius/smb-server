# Supported contracts and limits

The required local backend platforms are Windows and Linux. The platform code has
been reviewed. The historical first campaign passed 940/940 per Linux mode plus
local-backend TCP workloads; the expanded 3,144-case campaign retains compatibility
failures. Native Windows JIT/AOT execution remains outstanding.
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

Multichannel also requires `EnableMultichannel=true` and supports SMB 3.0, 3.0.2
and 3.1.1, with independently negotiated and authenticated TCP channels. The
configurable `MaxChannelsPerSession` defaults to 32, including the original
channel. Mandatory SMB3 channel sequencing applies under every profile.
In-memory durable v1 reconnect supports SMB 2.0.2, 2.1, 3.0, 3.0.2 and 3.1.1;
v2 requires SMB3. Grants require eligible Batch or HANDLE-caching file opens,
an explicit Durable profile and a coherent backend. Reconnect retains the
original acquired handle within the running process and its retention timeout.
See [configuration examples](multichannel-durable-configuration.md).

| Surface | Contract and practical limit |
|---|---|
| Stable identity | Identity must be acquired from a live OS handle, survive rename/hard links and remain valid while the handle is held. Linux uses statx device/inode; Windows requires volume serial plus stable file ID. No pathname-derived identity fallback. |
| Deletion | Shared object/stream delete-pending, rejection of new opens, clearing through a live open, fallible final close and nonrecursive directory deletion. Replacement objects must not be deleted. |
| Caching / durable | Requires a stable-identity coherent backend and explicit `exclusiveServerAccess:true`: all access, aliases and mutation use one server state. This deployment assertion is not an OS fence. |
| Enumeration | Bounded resumable cursor, restart/reopen/pattern handling and cleanup. Matching follows the explicit host case contract. |
| Notifications | Per-open bounded FIFO, filter/subtree, loss/error rescan and actual OS watcher. Best effort, not a journal. |
| Copy | Explicit profiles only; source/destination locks, operation lifetime and cache coordination, overlap/partial progress. |
| Allocation / buffering | Local allocation unsupported; unbuffered I/O advisory. Flush/write-through tests do not prove power-loss durability. |
| Metadata | Streams/EAs, Linux DOS flags, retained birth times and default descriptors are process memory. Named-stream families are shared by acquired identity across backend aliases. Promoted logical default streams also remain in memory; old native unnamed handles retain their original extent. Ordinary host base data/timestamps persist; ChangeTime is approximate. No full NTFS persistence guarantee. |
| Stream/namespace rename | Named-source rename, collision/replacement and logical default promotion preserve acquired handles and stream identity. Native unnamed-source to named rename remains unsupported. SMB directory rename atomically rejects remaining acquired descendants; generic backend relocation has a separate contract. Third-party stores need `IFileNamespaceStore` for the same atomic descendant guarantee. |
| Persistent / CA | No grants; FileDurableHandleStore is rejected by supported profiles. Public JSON APIs remain outside supported AOT persistence. |
| Legacy stores | Conservative per-store identity; shared deletion and coherent caching require explicit backend opt-in. Overlapping namespaces need shared coordination. |
| Authorized CREATE | LocalFileStore authorizes existing objects and missing-object parents before mutation under a guarded identity/descriptor contract. Descriptor-aware legacy stores must implement `IAuthorizedCreateStore` for safe mutations; allowed legacy mutations otherwise return NOT_SUPPORTED. Wrappers must forward the grant-aware overload for local readonly-grant semantics. |
| Descriptors | Basic ordered allow/deny, generic masks, owner control rights and new-child inheritance; aliases/streams share base-object policy. Richer ACEs and inheritable creator substitution are explicitly declined. No full privileges, SACL audit, claims, dynamic subtree propagation or persistent identity generations. |

The [adapted upstream campaign](upstream-tests.md) adds pinned independent
CREATE/namespace, lock/cancel, compound/credit, enumeration/notify and supported
lease/durable/replay assertions. Local enumeration applies SMB `*.*` and DOS
wildcard semantics while retaining the explicit host case contract.

The [recovery delivery](multichannel-durable-reconnect.md) records the completed
feature gates, independent native clients and source/spec mappings. Its published
Linux modes executed 3,515 cases with 100 retained failures. The subsequent
[failure repairs](remaining-failure-repairs.md) resolve those cases and pass all
3,897 cases in integration and both published Linux modes. Detailed results are in platform
validation; native Windows and full conformance acceptance remain incomplete.

The test harness uses independent raw-wire expectations and real local TCP
workloads. Passing selected cases does not establish whole-dialect conformance or
external client interoperability. Current test commands are in [tests](../../tests/README.md).
