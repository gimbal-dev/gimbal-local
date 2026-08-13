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

Please use GitHub's private vulnerability reporting, which is enabled on this
repository: open the [Security tab](https://github.com/gimbal-dev/gimbal-local/security/advisories/new)
and file a draft advisory. That keeps the report private until a fix ships.

Do not open a public issue for a vulnerability. The repository is public, so an
issue discloses the problem to everyone before there is anything to upgrade to.

There is no SLA. This is a preview built by one person, so expect a
best-effort response rather than a committed timeline.

In a private advisory a proof-of-concept is welcome and makes the report far
easier to act on. Only if you are ever asked to move a discussion to a public
issue, keep secrets, credentials, API tokens, private keys, personal data and
working exploits out of it.

Include context where you can:

- the affected version or commit;
- the host Mac model and macOS version;
- whether the guest was a rehydrated snapshot or a cold boot;
- the command line or app path used to start it;
- the expected boundary and how it appeared to fail.

Open the report at
<https://github.com/gimbal-dev/gimbal-local/security/advisories/new>.

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
report it through the private advisory process above.
