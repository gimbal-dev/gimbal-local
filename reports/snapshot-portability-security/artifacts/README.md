# Investigation artifacts

| Artifact | Source | Contents |
| --- | --- | --- |
| `discover.sh` | Repository static analysis | Rerunnable enumeration of claims, trust boundaries, portability surfaces, tests, and CI |
| `raw-discovery.json` | Output of `discover.sh` | Latest structured repository evidence |
| `analysis-prompt.md` | Investigation methodology | Grouping, rating, scoring, and output rules |
| `snapshot-validation.json` | Local Apple-Silicon validation | Archive hashes, safe-inventory result, payload hashes, live-resume outcomes, and test counts |

## Re-run

From the repository root:

```sh
./reports/snapshot-portability-security/artifacts/discover.sh "$(pwd)"
```

Then reassess the generated `raw-discovery.json` using
`analysis-prompt.md`. Snapshot validation is intentionally not automated by the
discovery script: attached snapshots are untrusted, multi-gigabyte inputs whose
execution requires an Apple-Silicon host and explicit review of archive entries.

To refresh snapshot evidence:

1. Record each archive's SHA-256 digest.
2. List archive headers and reject absolute paths, `..`, links, devices, and
   unexpected members before extraction.
3. Extract without preserving owners or permissions into a new private `0700`
   directory outside the repository.
4. Build and ad-hoc sign `chm` with `scripts/build-chm.sh`.
5. Capture console output to a file, apply strict time/idle bounds, and sanitize
   control bytes before inspection.
6. Update `snapshot-validation.json`; never commit raw guest console output or
   extracted guest disks.

## Telemetry

No production observability source was connected or required for this local
runtime audit. The verification sources were repository code, Git history,
existing tests, the local Apple-Silicon host, and the three supplied snapshots.
