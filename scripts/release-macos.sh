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
if [[ "${1:-}" == "--publish" ]]; then
    publish="yes"
elif [[ -n "${1:-}" ]]; then
    echo "release-macos.sh: unknown argument: $1" >&2
    echo "usage: release-macos.sh [--publish]" >&2
    exit 2
fi

identity="${GIMBAL_SIGN_IDENTITY:-}"
notary_profile="${GIMBAL_NOTARY_PROFILE:-gimbal-notary}"
version="${GIMBAL_VERSION:-0.1.0}"
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

swift test --package-path app/GimbalLocal \
    || die "app tests failed."

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

Requires an Apple silicon Mac (M1 or later) running macOS 14 or newer.

It does **not** require a Linux host, a KVM machine, a control plane, or an
account anywhere. Everything runs on your Mac.

The app is signed with a Developer ID certificate and notarized by Apple, so it
opens without a Gatekeeper warning.

### Install

1. Download \`GimbalLocal-$version.zip\` below and unzip it.
2. Move **Gimbal Local.app** to /Applications.
3. Open it. The engine starts itself.

\`chm\` ships inside the app. To use it from a terminal:

\`\`\`
/Applications/GimbalLocal.app/Contents/MacOS/chm --help
\`\`\`
NOTES

gh release create "v$version" "$zip" \
    --title "Gimbal Local $version" \
    --notes-file "$notes"

echo
echo "  Published: $(gh release view "v$version" --json url --jq .url)"
