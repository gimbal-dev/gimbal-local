# Security Policy

Gimbal Local is intended to put a narrow boundary between a Linux guest, the
host filesystem, local credentials, and the network. That boundary has not had
human line-by-line code review. Do not treat it as hardened, and do not use it
to isolate untrusted or hostile workloads.

Security reports are still welcome, especially when they show the implemented
boundary is weaker than the documentation says.

## Supported versions

The supported public release is the latest release on the
[releases page](https://github.com/gimbal-dev/gimbal-local/releases/latest).
If you are testing `main`, say so in the report and include the commit SHA.

## Reporting a vulnerability

For now, security coordination goes through this repository's GitHub issues. A
dedicated private reporting channel is not offered at this stage.

Because GitHub issues in a public repository are visible to everyone, do **not**
include secrets, credentials, API tokens, private keys, personal data, or a
working exploit / proof-of-concept. Describe the concern at a high level: the
affected area, the type of issue, and the impact. If safely demonstrating it
would require sensitive details, say so in the issue and wait for a maintainer to
respond before sharing anything further.

Include non-sensitive context where you can:

- the affected version or commit;
- the host Mac model and macOS version;
- whether the guest was a rehydrated snapshot or a cold boot;
- the command line or app path used to start it;
- the expected boundary and how it appeared to fail.

Open the report at <https://github.com/gimbal-dev/gimbal-local/issues/new>.

## What is in scope

Examples of issues that are in scope:

- a guest escaping the documented network egress policy;
- a guest reaching host loopback, private LAN, or link-local metadata when the
  host-isolation guard should block it;
- a guest reading or writing host files outside its bundle, disk image, or
  overlay;
- a sandbox obtaining a credential that should have remained host-held;
- daemon socket authorization bypasses;
- signed-manifest or bundle-verification bypasses;
- crashes or wedges that can be triggered by a malicious snapshot and leave the
  user with a misleading or unsafe state.

## What is usually out of scope

Please use an ordinary issue title rather than a security-sensitive title for:

- unsupported hardware or macOS versions;
- a guest workload that cannot boot because it lacks a kernel, virtio modules,
  `ip`, `ifconfig`, or other expected userspace tools;
- egress denied by policy when no allow-list entry exists;
- performance problems without a confidentiality, integrity, or availability
  impact;
- stale documentation without a security consequence.

## Security model

The detailed model is in [`docs/security-model.md`](docs/security-model.md). The
short version:

- no host filesystem passthrough is exposed to the guest;
- writable overlays are private to the runtime;
- the daemon socket is local and owner-only;
- network egress is mediated by the userspace NAT;
- new sandboxes default to fail-closed egress;
- host-held credentials are attached by the credential proxy as traffic leaves
  the guest, rather than being copied into the guest.

Those are implemented security controls, not aspirations. They are also
AI-authored and not human-reviewed. If you can produce a counterexample, please
report it through the issue-tracker process above.
