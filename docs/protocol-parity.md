# Protocol parity contract

Birak and Sebastian expose the same filesystem protocols. Both gateways access
local files directly. Birak additionally watches those files, tracks metadata,
and replicates completed changes between nodes. Sebastian has no node, watcher,
metadata-database, or replication dependency.

This document is kept identical in both repositories. Protocol fixes should be
reviewed for applicability to both projects; repository-specific behavior is
listed explicitly below.

## Shared behavior

| Area | Contract | Regression coverage |
| --- | --- | --- |
| Cross-protocol access | Disk, S3, WebDAV, HTTP browser, and SFTP writes are readable through every other interface; renames and deletions are visible across protocols. | `TestProtocolMatrix` |
| Root paths | Absolute, relative, and symlinked storage roots work with multipart; its store receives an absolute, validated destination. | `TestMultipart_RootPaths` |
| Reserved state | Only the root-level state directory is reserved; the same directory name inside an ordinary bucket remains user data. Requests also validate resolved symlink targets. | Gateway namespace tests; `TestNestedStateDirectoryIsAnOrdinaryObjectPrefix` |
| Scratch files and directories | Temporary and backup names at any depth are rejected in client paths and omitted from listings, including S3 prefixes and buckets. | Namespace tests in all four gateways; `TestListHidesScratchDirectories` |
| S3 symlinks | Object paths must remain inside their bucket. Safe file aliases have matching LIST/HEAD metadata; unsafe aliases are omitted. | S3 parity tests |
| S3 checksums | PUT and UploadPart validate declared Content-MD5 and concrete SHA-256 digests; a rejected PUT preserves the existing object. | S3 checksum tests; multipart checksum tests |
| S3 listing | V1/V2 pagination is stable; V2 KeyCount includes returned objects and CommonPrefixes. Path and virtual-host routing apply the same namespace restrictions. | S3 listing tests; `TestScratchRoutingMatchesAddressStyles` |
| Multipart recovery | Parts survive restart. Duplicate part versions left by a crash resolve to one newest part, with deterministic tie-breaking. Completion verifies parts before publication. | `TestRestartRecoveryChoosesNewestDuplicatePart`; multipart integrity tests |
| Multipart isolation | Staging is hidden from gateways. The store rejects unsafe destinations, and unavailable staging prevents bucket deletion. | Multipart path tests; `TestParity_DeleteBucketUnavailableStaging` |
| Upload limits | Omitted active-upload cap is 10,000; explicit YAML/environment zero is unlimited. Environment overrides YAML. Negative YAML limits are rejected. | `TestUploadLimitContract` |
| SFTP directory paging | Hidden batches do not produce premature EOF or empty NAME replies. Requests read bounded batches until visible entries or actual EOF. | `TestReaddirHiddenEntriesAndPaging` |
| WebDAV | COPY/MOVE, overwrite conditions, recursive copies, byte limits, and lock enforcement share behavior. Locks are in memory and apply to that WebDAV gateway. | WebDAV compatibility and lock tests |
| Authentication | S3 uses SigV4; WebDAV/HTTP use Basic Auth; SFTP uses SSH. Empty credential pairs select open access; partial credentials do not disable authentication. | Gateway authentication tests |

`max_upload_bytes: 0` is unlimited for S3/WebDAV/SFTP. The HTTP browser keeps its
1 GiB default request cap. SFTP writes directly to open files; atomic HTTP PUT
and multipart publication do not imply atomic SFTP uploads. Recursive WebDAV
COPY skips symlinks found inside the source tree.

## Intentional differences

| Area | Birak | Sebastian |
| --- | --- | --- |
| Storage setting | `sync_dir`, default `./sync` | `root_dir`, default `/data/files` |
| Replication | Peers, watcher, SQLite metadata, repair/reconciliation | None |
| Ignore rules | Shared with node synchronization and applied to gateways | No user ignore rules |
| Empty parent directories | Sync-aware cleanup after relevant delete/move operations | Preserved until explicitly removed |
| Reserved state | `.birak/` | `.sebastian/` |
| Scratch names | `.birak-tmp-*`, `.birak-bak-*` | `.seb-tmp-*`, `.seb-bak-*` |
| SSH host-key default | Generated in `meta_dir` unless overridden | Explicit `host_key_path` required; generated there when absent |
| Enabled gateways | May all be disabled for a replication-only node | At least one must be enabled |
| Missing explicit config file | Continues with defaults/environment | Startup error |
| Identity and presentation | Birak module, environment prefix, S3 owner and UI branding | Sebastian equivalents |

Birak's `TestMultipartReplicationPublishesOnlyCompletedObject` additionally
checks that staging is neither indexed nor replicated and only the completed
object arrives at a peer. These node-specific tests belong only to Birak.

## Maintaining parity

1. Put shared behavior changes in gateway/multipart/config code; keep node
   integration in Birak. Avoid copying mixed protocol-and-sync commits wholesale.
2. Port the applicable implementation and regression scenarios together. Adapt
   imports, constructors, state prefixes, and documented storage differences.
3. Reuse existing coverage when it already checks the same behavior; test names
   and total counts need not match. Review endpoint behavior, not just helpers.
4. Run the shared contracts in both repositories and all node tests in Birak.
5. Update both copies of this matrix when intentionally changing a contract or
   adding an exception. Keep each repository's CI toolchain sourced from go.mod.

```sh
go test -race ./...
go vet ./...
```
