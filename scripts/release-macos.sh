#!/usr/bin/env bash
# Copyright © 2024 Cloud Hypervisor contributors
#
# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

#
# Build, sign, notarize and publish a macOS release of Gimbal Local.
#
# Usage:
#   scripts/release-macos.sh [--publish]
#
#   Without --publish it does everything up to and including the Gatekeeper
#   assessment, and leaves the .zip in target/. That is the useful mode: it is
#   the whole risky part, and it is reversible. --publish adds the one step
#   that is not reversible.
#
# Environment:
#   GIMBAL_SIGN_IDENTITY  Developer ID Application identity. Required — an
#                         ad-hoc signature cannot be notarized, so there is no
#                         sensible default here.
#   GIMBAL_NOTARY_PROFILE notarytool keychain profile (default gimbal-notary).
#   GIMBAL_VERSION        Release version, also the tag (default 0.1.0).
#   GIMBAL_BUILD          CFBundleVersion (default 1).
#
# Why this script runs the test suite in *release* configuration:
#
#   Shipping the first signed build found a hang that existed only in optimized
#   code. `fcntl` is variadic in C, and the Rust declaration named its third
#   argument as fixed. On Apple arm64 a variadic argument arrives on the stack
#   and a fixed one in a register, so the flag actually applied was whatever
#   the stack happened to hold — measured as 0x0 at opt-level=0 and 0x4000c0 at
#   opt-level=s. O_NONBLOCK was never set, a drain read blocked forever, and
#   every vCPU parked before executing a single instruction.
#
#   Correct tests for that behaviour already existed and passed. They passed
#   because the suite had only ever been run in debug. So the gate is not "run
#   the tests" — it is *run them in the configuration you are about to ship*. A
#   release that skipped this would have shipped an app that never starts.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

publish="no"
version="${GIMBAL_VERSION:-0.1.0}"

# A loop, not a single positional read: the earlier form inspected only $1, so
# `--publish --version 0.2.0` would have published 0.1.0 without complaining.
while [[ $# -gt 0 ]]; do
    case "$1" in
        --publish) publish="yes"; shift ;;
        --version)
            [[ -n "${2:-}" ]] || { echo "release-macos.sh: --version needs a value" >&2; exit 2; }
            version="$2"; shift 2 ;;
        --version=*) version="${1#*=}"; shift ;;
        -h|--help) echo "usage: release-macos.sh [--publish] [--version X.Y.Z]"; exit 0 ;;
        *)
            echo "release-macos.sh: unknown argument: $1" >&2
            echo "usage: release-macos.sh [--publish] [--version X.Y.Z]" >&2
            exit 2 ;;
    esac
done

identity="${GIMBAL_SIGN_IDENTITY:-}"
notary_profile="${GIMBAL_NOTARY_PROFILE:-gimbal-notary}"
build_number="${GIMBAL_BUILD:-1}"

step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die() { printf '\n\033[1;31mrelease-macos.sh: %s\033[0m\n' "$1" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Preflight. Every one of these is checked before anything is built, because
# each failure has a specific remedy and finding out 10 minutes into a release
# build is worse than finding out now. Each message names the exact command.
# ---------------------------------------------------------------------------

step "Preflight"

[[ "$(uname -s)" == "Darwin" ]] || die "this builds a macOS .app; it must run on macOS."

if [[ -z "$identity" ]]; then
    die "GIMBAL_SIGN_IDENTITY is not set.

  A release must be signed with a Developer ID Application certificate — an
  ad-hoc signature cannot be notarized, and an un-notarized app is refused by
  Gatekeeper on every Mac but the one that built it.

  List the identities you have:
      security find-identity -v -p codesigning

  Then, using the full string including the team ID in parentheses:
      export GIMBAL_SIGN_IDENTITY='Developer ID Application: Your Name (TEAMID)'"
fi

if ! security find-identity -v -p codesigning | grep -qF "$identity"; then
    die "no codesigning identity matches:
      $identity

  Available:
$(security find-identity -v -p codesigning | sed 's/^/      /')"
fi

case "$identity" in
    "Developer ID Application:"*) ;;
    *) die "\"$identity\" is not a Developer ID Application certificate.

  Apple Development and Mac Developer certificates work on your own machine but
  cannot be notarized, so the result would not run on anyone else's." ;;
esac

# Ask Apple, rather than checking that a local file exists. A profile can be
# present and hold credentials that no longer authenticate; the only way to
# know is a round trip.
if ! xcrun notarytool history --keychain-profile "$notary_profile" >/dev/null 2>&1; then
    die "the notary profile \"$notary_profile\" does not authenticate with Apple.

  Create it with an app-specific password from appleid.apple.com:
      xcrun notarytool store-credentials \"$notary_profile\" \\
          --apple-id you@example.com \\
          --team-id TEAMID \\
          --password xxxx-xxxx-xxxx-xxxx"
fi

if [[ "$publish" == "yes" ]]; then
    command -v gh >/dev/null || die "gh is not installed, and --publish needs it to create the release."
    gh auth status >/dev/null 2>&1 || die "gh is not authenticated. Run: gh auth login"

    # The README tells people where to download this. If it names a different
    # repo than the one we are about to publish to, the very first thing a
    # downloader does -- click that link -- fails, and the artifact is perfect
    # and unreachable. This is not hypothetical: the first release was nearly
    # cut with README pointing at a repo that does not exist.
    target_repo="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"
    if ! grep -q "github.com/$target_repo/releases" README.md; then
        die "README.md does not point at $target_repo/releases, so the download
      link people follow will not lead to this release.

      Found instead:
$(grep -n 'github.com/[^)]*/releases' README.md | sed 's/^/        /' || echo '        (no releases link at all)')"
    fi

    # gh refuses to create a release when a tag of that name exists locally but
    # not on the remote -- and it refuses at publish time, i.e. after the build,
    # the notarization round trip and the staple. That is the whole point of a
    # preflight: find it now, not four minutes of Apple's time later. This is
    # reachable in practice because deleting a release with --cleanup-tag
    # removes the remote tag and leaves the local one behind.
    if git rev-parse -q --verify "refs/tags/v$version" >/dev/null 2>&1 \
        && ! git ls-remote --exit-code --tags origin "refs/tags/v$version" >/dev/null 2>&1; then
        die "the tag v$version exists here but not on $target_repo, and gh will refuse
      to create the release -- after the build and notarization have run.

      Delete the stale local tag and re-run:
          git tag -d v$version"
    fi
fi

# One artifact must not carry two version numbers. --version sets the bundle's
# CFBundleShortVersionString, but `chm --version` prints CARGO_PKG_VERSION from
# chm/Cargo.toml, so the two drift apart the moment one moves without the other.
# v0.1.1 shipped exactly that: an app reporting 0.1.1 whose own bundled chm said
# 0.1.0, which means a bug report quotes a version that does not identify the
# build it came from.
#
# Refuse rather than rewrite chm/Cargo.toml here. The version is a fact about
# the source, recorded in a commit and covered by the tag; a script editing it
# mid-release would make the published tree disagree with the tree that built
# it, and the disagreement would be invisible afterwards.
chm_version="$(awk '/^\[package\]/{p=1;next} /^\[/{p=0} p&&/^version *=/{gsub(/[",]/,"");print $3;exit}' chm/Cargo.toml)"
[[ -n "$chm_version" ]] || die "could not read the package version from chm/Cargo.toml."
if [[ "$chm_version" != "$version" ]]; then
    die "chm/Cargo.toml says $chm_version but this release is $version, so the app
      would report $version while its own bundled chm reports $chm_version.

      Bump it, commit, and re-run:
          chm/Cargo.toml  version = \"$version\""
fi

echo "  identity        $identity"
echo "  notary profile  $notary_profile"
echo "  version         $version (build $build_number)"

# ---------------------------------------------------------------------------
# The gate. See the header comment: the tests must run in the configuration
# being shipped, or they are not evidence about the artifact.
# ---------------------------------------------------------------------------

step "Tests, in the release configuration this ships"

cargo test -p hypervisor --release --no-default-features \
    --features hvf,kvm-snapshot --lib \
    || die "hypervisor tests failed in release configuration.

  Do not ship this. A failure here that does not reproduce in debug is exactly
  the class of bug this gate exists to catch — see the header of this script."

cargo test -p gimbal-local --release \
    || die "chm tests failed in release configuration. Do not ship this."

swift test -c release --package-path app/GimbalLocal \
    || die "app tests failed in release configuration. Do not ship this."

# ---------------------------------------------------------------------------

step "Building and signing the app"

GIMBAL_SIGN_IDENTITY="$identity" \
GIMBAL_VERSION="$version" \
GIMBAL_BUILD="$build_number" \
    scripts/build-gimbal-local-app.sh --release

bundle="$repo_root/target/GimbalLocal.app"
[[ -x "$bundle/Contents/MacOS/chm" ]] \
    || die "the release bundle has no Contents/MacOS/chm.

  The app uses the presence of a bundled chm as its signal that it is a shipped
  copy; without it a downloaded app would look for a source checkout that is
  not there."

codesign --verify --deep --strict "$bundle" \
    || die "the signed bundle does not verify."

step "Notarizing (this uploads to Apple and waits)"

zip="$repo_root/target/GimbalLocal-$version.zip"
rm -f "$zip"
# ditto, not `zip`: it is the only archiver that preserves the bundle structure
# and extended attributes notarization requires.
ditto -c -k --keepParent "$bundle" "$zip"

xcrun notarytool submit "$zip" --keychain-profile "$notary_profile" --wait \
    || die "notarization failed.

  For the detail Apple recorded:
      xcrun notarytool history --keychain-profile \"$notary_profile\"
      xcrun notarytool log <submission-id> --keychain-profile \"$notary_profile\""

step "Stapling and verifying"

# Staple the .app, then re-zip. The ticket has to live inside the bundle the
# user ends up with, so that it validates on a Mac that is offline.
xcrun stapler staple "$bundle" || die "stapling failed."
xcrun stapler validate "$bundle" || die "the stapled ticket does not validate."

assessment="$(spctl --assess --type execute --verbose=4 "$bundle" 2>&1 || true)"
echo "$assessment" | sed 's/^/  /'
grep -q "accepted" <<<"$assessment" \
    || die "Gatekeeper would refuse this app. Do not publish it."
grep -q "Notarized Developer ID" <<<"$assessment" \
    || die "Gatekeeper accepted it, but not as a notarized Developer ID app."

rm -f "$zip"
ditto -c -k --keepParent "$bundle" "$zip"

step "Done"
echo "  $zip"
echo
echo "  Verified: signed with Developer ID, hardened runtime, notarized by"
echo "  Apple, ticket stapled, and accepted by Gatekeeper as a notarized app."

if [[ "$publish" != "yes" ]]; then
    echo
    echo "  Not published. To publish this exact artifact:"
    echo "      scripts/release-macos.sh --publish"
    exit 0
fi

step "Publishing v$version"

notes="$repo_root/target/release-notes-$version.md"
cat >"$notes" <<NOTES
Gimbal Local $version — Cloud Hypervisor snapshots, rehydrated on Apple silicon.

A vanilla Cloud Hypervisor \`arm64\` snapshot captured on a Linux/KVM host — no
fork, no patches, no flags — resumes on Apple Hypervisor.framework and comes
back to a live shell. Or cold-boot a stock kernel with no snapshot at all.

### What you need

- An Apple silicon Mac (M1 or later) running macOS 14 or newer.

### What you do not need

Worth saying plainly, because every comparable tool asks for at least one:

- No Linux host and no KVM machine. The Mac is the hypervisor.
- No control plane, no account, no network. Everything runs locally.
- No Rust toolchain, no Xcode, no source checkout. \`chm\` ships inside the app.

The app is signed with a Developer ID certificate and notarized by Apple, so it
opens without a Gatekeeper warning and its ticket verifies offline.

### Install

1. Download \`GimbalLocal-$version.zip\` below and unzip it.
2. Move **Gimbal Local.app** to /Applications.
3. Open it. The engine starts itself.

\`chm\` ships inside the app. To use it from a terminal:

\`\`\`
/Applications/GimbalLocal.app/Contents/MacOS/chm --help
\`\`\`

### Before it can start anything

The app creates \`~/gimbal-snapshots\` and \`~/gimbal-images\` on first launch,
and both are empty — it does not ship a guest. You need one of:

- a Cloud Hypervisor **arm64 snapshot** (\`state.json\` + \`snapshot/memory-ranges\`,
  from \`ch-remote … snapshot\` on a Linux host) to rehydrate; or
- a directory holding an uncompressed arm64 kernel \`Image\` to cold-boot; or
- nothing but a container reference — \`chm image build alpine:3.20\` builds a
  bootable image from Docker Hub on this Mac.

### Known limits

- One guest at a time. \`hv_vm_create\` is process-global on macOS.
- A guest resumed from a snapshot inherits the capture host's CPU feature
  view. On Graviton that means \`CTR_EL0.DIC\` disagrees with this Mac, which
  breaks JIT-heavy workloads such as \`npm\`. Cold-booted guests are immune by
  construction, because their kernel reads this Mac's own \`CTR_EL0\`.
- **arm64 guests only.** A \`sandbox.json\` asking for \`x86_64\`, and an
  amd64-only container image, are both refused by name up front. An \`x86_64\`
  *snapshot* is not recognised as such and will fail less clearly.
NOTES

gh release create "v$version" "$zip" \
    --title "Gimbal Local $version" \
    --notes-file "$notes"

echo
echo "  Published: $(gh release view "v$version" --json url --jq .url)"
