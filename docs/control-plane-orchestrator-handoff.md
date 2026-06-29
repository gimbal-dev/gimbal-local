# Cloud orchestrator handoff

Last updated: 2026-06-29

This is the starting brief for the agent/repo that will build the sister
control plane for Gimbal / `gimbal-local`.

The important architectural decision: **the local runtime is not the
orchestrator**. This repo owns local Mac execution of restored snapshots through
`chm` / `chm serve`. The sister repo owns lifecycle, desired state, cloud
resources, artifact movement, and user/team control.

## North-star product

A user should be able to ask for a sandbox, have the system acquire suitable
remote compute, capture or retrieve a Linux/KVM Cloud Hypervisor snapshot, move
it to the user's Mac, run it locally through `gimbal-local`, and move resulting
artifacts/snapshots back to cloud storage.

Initial target:

```text
control plane -> cloud/Pi capture host -> snapshot store -> local Mac runner
```

Later target:

```text
team control plane -> many cloud accounts/hosts -> many local runners
```

## MVP goals

The first control-plane version should allow:

1. requesting cloud resources;
2. creating cloud resources;
3. viewing state of cloud resources and local runners;
4. storing snapshots and retrieving them from both local and cloud locations.

That is enough for a first vertical slice if the boundaries below are honored.

## Extra things that must be in the first design

### 1. Resource leases

Every cloud resource should be attached to a lease:

```text
lease_id
owner
provider
region
resource_ids
created_at
expires_at
status
cleanup_policy
```

Reason: cost safety. We already learned AWS bare metal can become expensive
quickly, and the local runtime should not be trusted to remember cleanup.

MVP behavior:

- leases have explicit TTLs;
- expired leases become cleanup candidates;
- cleanup is idempotent;
- resources are tagged with project and lease IDs.

### 2. Idempotency and operation records

All create/capture/push/cleanup actions should have operation records:

```text
operation_id
idempotency_key
requested_by
operation_type
target_resource
status
started_at
updated_at
error
```

Reason: cloud APIs fail halfway. The orchestrator must be able to retry safely
without double-launching hosts, double-uploading artifacts, or losing track of
cleanup.

### 3. Artifact manifests

Do not treat a snapshot as "just a folder". Store a manifest for every snapshot:

```text
snapshot_id
source_kind          # aws | raspberry-pi | local-lima | uploaded
source_host_id
capture_tool_version
gimbal_local_commit
created_at
architecture        # aarch64
kvm_required        # true
gic_mode            # gicv2m-message-spi | its-lpi
vcpu_count
memory_bytes
object_locations
checksum_tree
compatibility_status
```

Critical compatibility field:

```text
gic_mode = gicv2m-message-spi
```

`gimbal-local` currently cannot run stock ITS/LPI-routed arm64 Cloud Hypervisor
snapshots on Apple HVF. The orchestrator must know this and avoid presenting
unsupported snapshots as runnable.

### 4. Local runner contract

The local Mac runtime should be treated as an agent/worker, not as the source of
truth.

Initial local runner capabilities:

```text
register runner
heartbeat runner
report local capacity
list local snapshots
pull snapshot from object store
run snapshot through chm/chm serve
stream/report console state
push overlays/artifacts back to object store
stop/cleanup local run
```

The local runner should expose state, not make global orchestration decisions.

### 5. Cloud account trust model

Start with bring-your-own cloud account/subscription.

MVP rules:

- no shared service credentials;
- no long-lived AWS keys stored in the control plane unless explicitly designed
  and encrypted;
- prefer user-owned credentials, short-lived credentials, or a narrow
  customer-managed role;
- every cloud resource is tagged for cleanup;
- every destructive cleanup path has a dry-run/readable preview.

From the AWS work in this repo, the tag to preserve is:

```text
Project=gimbal-local
```

If also supporting migration from older docs/scripts:

```text
Project=cloud-hypervisor-mac
```

### 6. Cost and cleanup controls

The orchestrator should treat cost safety as a product feature.

Minimum controls:

- global "show me everything running" view;
- per-lease expiry;
- per-provider cleanup;
- "panic cleanup" for all resources created by the orchestrator;
- visible estimated hourly burn for running resources;
- explicit warning for AWS bare-metal hosts.

AWS note: EC2 On-Demand Standard quota is in vCPUs. A default value of 5 vCPUs
is not enough for `c7g.metal`; that commonly needs 64 vCPUs.

### 7. State reconciliation

The orchestrator cannot rely only on its database. It should periodically
reconcile desired/known state with provider APIs and local runners:

```text
db says instance running -> AWS says terminated -> mark terminated
db says snapshot uploaded -> object store missing -> mark artifact_missing
runner heartbeat stale -> mark runner offline
lease expired -> enqueue cleanup
```

This should exist in MVP even if it is just a manual "refresh state" button or
CLI command.

### 8. Audit log

Every meaningful action should write an audit event:

```text
who requested
what changed
provider/resource affected
before/after status
timestamp
error if any
```

This matters before there are teams, because cloud cleanup mistakes are costly.

## Suggested entities

### User

For MVP this can be one local developer, but model it explicitly.

```text
user_id
display_name
auth_provider
created_at
```

### Runner

Represents a local Mac capable of running restored snapshots.

```text
runner_id
owner
hostname
platform
arch
gimbal_local_version
last_seen_at
status
capabilities
```

### Cloud provider account

Represents user-owned cloud credentials or role connection.

```text
account_id
owner
provider
display_name
auth_mode
regions_enabled
status
```

### Capture host

Represents AWS bare metal, Raspberry Pi, Oracle bare metal, or another arm64
Linux/KVM host.

```text
host_id
provider
account_id
region
instance_type
public_endpoint
kvm_status
vgic_status
status
lease_id
```

### Snapshot

Logical snapshot record plus object-store locations.

```text
snapshot_id
sandbox_id
source_host_id
manifest
storage_locations
status
created_at
```

### Sandbox

User-facing thing the product manages.

```text
sandbox_id
owner
name
desired_state
current_state
active_snapshot_id
active_runner_id
created_at
updated_at
```

## Suggested API surface

Keep the first API boring and explicit.

### Cloud resources

```text
POST /cloud/accounts
GET  /cloud/accounts
POST /cloud/resources/requests
GET  /cloud/resources
GET  /cloud/resources/{id}
POST /cloud/resources/{id}/cleanup
POST /cloud/reconcile
```

### Snapshots

```text
POST /snapshots/capture-requests
GET  /snapshots
GET  /snapshots/{id}
GET  /snapshots/{id}/manifest
POST /snapshots/{id}/presigned-download
POST /snapshots/{id}/presigned-upload
POST /snapshots/{id}/mark-local-copy
```

### Local runners

```text
POST /runners/register
POST /runners/{id}/heartbeat
GET  /runners
GET  /runners/{id}
POST /runners/{id}/assign-run
POST /runners/{id}/stop-run
```

### Sandboxes

```text
POST /sandboxes
GET  /sandboxes
GET  /sandboxes/{id}
POST /sandboxes/{id}/start-local
POST /sandboxes/{id}/snapshot
POST /sandboxes/{id}/push-artifacts
POST /sandboxes/{id}/cleanup
```

## First vertical slice

Build the smallest end-to-end path:

1. Register one local Mac runner.
2. Register one remote capture target:
   - Raspberry Pi first if AWS quota is still blocked;
   - AWS Graviton bare metal once quota is available.
3. Request a capture.
4. Capture host produces `CH_GIC_V2M=1` snapshot.
5. Orchestrator stores snapshot manifest and object location.
6. Local runner downloads snapshot.
7. Local runner invokes `gimbal-local` / `chm`.
8. Runner reports status and console summary.
9. Runner uploads overlays/proof artifacts.
10. Orchestrator can show:
    - cloud host state;
    - snapshot state;
    - local runner state;
    - active sandbox state.
11. Orchestrator can cleanup the cloud host/resources it created.

## Non-goals for the first repo pass

- No multi-tenant SaaS architecture.
- No hosted shared AWS account.
- No attempt to make stock ITS/LPI snapshots runnable on Mac.
- No scheduling fleet or autoscaling complexity.
- No GUI polish before the state model and API contract exist.
- No secret-heavy design that requires storing broad cloud admin credentials.

## Interface with this repo

This repo currently provides:

- `chm run <snapshot-dir>`;
- `chm serve <library>`;
- `scripts/hvf/capture-arm-snapshot.sh`;
- `scripts/hvf/capture-on-mac.sh`;
- `scripts/aws-cleanup-chm.sh`;
- docs for AWS and Raspberry Pi setup.

The control-plane agent should read:

- `docs/project-state-handoff.md`;
- `docs/agent-chat-history.md`;
- `docs/macos-local-runtime.md`;
- `docs/aws-byo-setup.md`;
- `docs/raspberry-pi-offbox-plan.md`.

## Questions to answer early

1. Does the local runner pull work from the control plane, or does the control
   plane call into a locally exposed endpoint?
2. How are local runners authenticated?
3. Does the orchestrator store snapshots in its own object store, user-owned
   object stores, or both?
4. What is the minimum safe credential model for AWS BYO?
5. What exact fields make a snapshot compatible with `gimbal-local`?
6. What is the panic-cleanup UX?
7. What state must remain local-only for privacy/security?

## Recommended first implementation approach

Start as a small API service plus CLI, not a full app:

```text
control-plane-api
control-plane-worker
control-plane-cli
```

Use a simple relational database for state, an object store abstraction for
snapshots, and provider adapters for AWS and SSH/Pi. Keep the state machine
plain and inspectable before adding UI.

The first successful demo should be:

```text
control-plane CLI requests capture
remote host captures snapshot
snapshot manifest appears
local runner pulls and runs snapshot
control-plane shows cloud/local/snapshot state
cleanup removes cloud resources
```

