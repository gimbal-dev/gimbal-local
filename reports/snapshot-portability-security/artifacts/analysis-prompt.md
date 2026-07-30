# Analysis methodology

Use `raw-discovery.json`, `snapshot-validation.json`, and the target repository
to reassess whether Gimbal Local securely runs cloud-origin Cloud Hypervisor
snapshots for coding-agent sessions.

## Entity grouping

Group evidence into these product surfaces:

1. Snapshot capture and archive intake
2. Provenance and integrity
3. KVM-to-HVF state translation
4. Restored devices and guest execution
5. CPU and timer compatibility
6. Network and egress controls
7. Host isolation and resource controls
8. Coding-agent image/workload readiness
9. Control plane and state CDN
10. Verification, CI, and product-status reporting

## Assessment dimensions

Rate every surface on:

| Rating | Meaning |
| --- | --- |
| ✅ | Implemented and directly verified against relevant hardware/artifacts |
| ⚠️ | Implemented but opt-in, partially verified, externally dependent, or materially constrained |
| ❌ | Missing, contradicted by evidence, or blocks the stated product goal |

Do not equate a unit test with end-to-end evidence. Do not equate a documented
claim with implementation. Separate:

- **Portability:** does the VM actually resume?
- **Utility:** can a coding agent do useful work?
- **Security:** is untrusted input authenticated, confined, and governed?
- **Maturity:** is the behavior repeatable in automation and supportable?

## Risk scoring

Score each gap from 1 to 10:

`impact (1-4) + likelihood/exposure (1-3) + product-blocking (0-2) + evidence-gap (0-1)`

| Score | Risk |
| --- | --- |
| 9-10 | 🔴 Critical |
| 7-8 | 🟠 High |
| 4-6 | 🟡 Medium |
| 1-3 | 🟢 Low |

Security severity and product-readiness risk are different. Preserve the
security specialist's severity label while allowing a larger readiness score
when a medium-severity security default blocks the advertised trust model.

## Default assumptions

- Attached archives are untrusted until archive entries and provenance are
  validated.
- A local `chm run <dir>` is a primary product path, not a developer-only
  escape hatch.
- Coding-agent workloads are hostile and may attempt network exfiltration,
  guest-kernel exploitation, terminal injection, and resource exhaustion.
- Apple Hypervisor.framework is trusted as the isolation boundary; side-channel
  and HVF implementation vulnerabilities are out of scope.
- No production telemetry is available unless a concrete source is supplied.

## Output expectations

The report must:

- State a direct verdict, including separate scores for portability, secure
  cloud-to-local delivery, coding-agent usefulness, and operational maturity.
- Identify an exemplary implemented surface.
- List every material gap with code/document evidence.
- Distinguish agent-fixable work from human/cross-team decisions.
- Record the exact snapshot validation performed without embedding raw
  untrusted console bytes.
- Call out contradictory status language and misleading posture semantics.
