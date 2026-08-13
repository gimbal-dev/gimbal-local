#!/usr/bin/env bash
# Copyright © 2024 Cloud Hypervisor contributors
#
# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

#
# Build, sign and notarize a macOS release of Gimbal Local, or promote an
# already-reviewed artifact without rebuilding it.
#
# Usage:
#   GIMBAL_VERSION=0.2.1 scripts/release-macos.sh
#   scripts/release-macos.sh --promote target/GimbalLocal-0.2.1.release-metadata
#
#   The first command does everything up to and including the Gatekeeper
#   assessment, then leaves a ZIP and integrity metadata in target/. Review and
#   install that ZIP as a stranger would. The second command re-verifies and
#   publishes those exact bytes. It never builds, signs, or notarizes.
#
# Environment:
#   GIMBAL_SIGN_IDENTITY  Developer ID Application identity. Required — an
#                         ad-hoc signature cannot be notarized, so there is no
#                         sensible default here.
#   GIMBAL_NOTARY_PROFILE notarytool keychain profile (default gimbal-notary).
#   GIMBAL_VERSION        Release version, also the tag. Required when building.
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

step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die() { printf '\n\033[1;31mrelease-macos.sh: %s\033[0m\n' "$1" >&2; exit 1; }
usage() {
    echo "usage: release-macos.sh [--version X.Y.Z]"
    echo "       release-macos.sh --promote METADATA [--version X.Y.Z]"
}

mode="build"
metadata_arg=""
version="${GIMBAL_VERSION:-}"
cli_version=""

# A loop, not a single positional read: the earlier form inspected only $1, so
# `--publish --version 0.2.0` would have published 0.1.0 without complaining.
while [[ $# -gt 0 ]]; do
    case "$1" in
        --promote)
            [[ -n "${2:-}" ]] || die "--promote needs the release metadata path."
            [[ "$mode" == "build" && -z "$metadata_arg" ]] \
                || die "--promote may be specified only once."
            mode="promote"; metadata_arg="$2"; shift 2 ;;
        --promote=*)
            [[ -n "${1#*=}" ]] || die "--promote needs the release metadata path."
            [[ "$mode" == "build" && -z "$metadata_arg" ]] \
                || die "--promote may be specified only once."
            mode="promote"; metadata_arg="${1#*=}"; shift ;;
        --publish)
            die "--publish no longer builds and publishes in one step.

  First build and review an artifact:
      GIMBAL_VERSION=X.Y.Z scripts/release-macos.sh

  Then promote the exact ZIP named by its metadata:
      scripts/release-macos.sh --promote target/GimbalLocal-X.Y.Z.release-metadata" ;;
        --version)
            [[ -n "${2:-}" ]] || { echo "release-macos.sh: --version needs a value" >&2; exit 2; }
            cli_version="$2"; shift 2 ;;
        --version=*) cli_version="${1#*=}"; shift ;;
        -h|--help) usage; exit 0 ;;
        *)
            echo "release-macos.sh: unknown argument: $1" >&2
            usage >&2
            exit 2 ;;
    esac
done

if [[ -n "$cli_version" ]]; then
    if [[ -n "$version" && "$version" != "$cli_version" ]]; then
        die "GIMBAL_VERSION is $version but --version requested $cli_version."
    fi
    version="$cli_version"
fi

identity="${GIMBAL_SIGN_IDENTITY:-}"
notary_profile="${GIMBAL_NOTARY_PROFILE:-gimbal-notary}"
build_number="${GIMBAL_BUILD:-1}"

# ---------------------------------------------------------------------------
# Preflight. Every one of these is checked before anything is built, because
# each failure has a specific remedy and finding out 10 minutes into a release
# build is worse than finding out now. Each message names the exact command.
# ---------------------------------------------------------------------------

step "Preflight"

[[ "$(uname -s)" == "Darwin" ]] || die "this builds a macOS .app; it must run on macOS."
[[ "$(uname -m)" == "arm64" ]] \
    || die "macOS releases must be built and promoted on Apple Silicon (arm64), not $(uname -m)."

source_sha="$(git rev-parse --verify HEAD 2>/dev/null)" \
    || die "could not identify the source commit."
worktree_status="$(git status --porcelain --untracked-files=all)"
[[ -z "$worktree_status" ]] || die "the worktree is dirty. A release must map to
      one committed source tree, but these paths differ from HEAD:
$(printf '%s\n' "$worktree_status" | sed 's/^/        /')

      Commit, remove, or stash those changes before releasing."

assert_source_unchanged() {
    current_sha="$(git rev-parse --verify HEAD 2>/dev/null)" \
        || die "the source commit can no longer be read."
    [[ "$current_sha" == "$source_sha" ]] \
        || die "HEAD changed during the release: started at $source_sha, now $current_sha."
    current_status="$(git status --porcelain --untracked-files=all)"
    [[ -z "$current_status" ]] || die "the source tree changed during the release:
$(printf '%s\n' "$current_status" | sed 's/^/        /')"
}

chm_version="$(awk '/^\[package\]/{p=1;next} /^\[/{p=0} p&&/^version *=/{gsub(/[",]/,"");print $3;exit}' chm/Cargo.toml)"
[[ -n "$chm_version" ]] || die "could not read the package version from chm/Cargo.toml."

if [[ "$mode" == "build" ]]; then
    [[ -n "$version" ]] || die "the release version is required.

  Set it explicitly:
      GIMBAL_VERSION=$chm_version scripts/release-macos.sh

  There is deliberately no fallback release version."
else
    [[ -f "$metadata_arg" && ! -L "$metadata_arg" ]] \
        || die "release metadata is not a regular, non-symlink file: $metadata_arg"
    metadata_dir="$(cd "$(dirname "$metadata_arg")" && pwd)"
    metadata="$metadata_dir/$(basename "$metadata_arg")"

    meta_format=""
    meta_artifact=""
    meta_sha256=""
    meta_source_sha=""
    meta_version=""
    meta_build=""
    meta_architecture=""
    meta_identity=""
    meta_codesign=""
    meta_stapler=""
    meta_gatekeeper=""
    while IFS='=' read -r key value remainder; do
        [[ -n "$key" && -n "$value" && -z "$remainder" ]] \
            || die "malformed release metadata line in $metadata."
        case "$key" in
            format)
                [[ -z "$meta_format" ]] || die "duplicate metadata key: format"
                meta_format="$value" ;;
            artifact)
                [[ -z "$meta_artifact" ]] || die "duplicate metadata key: artifact"
                meta_artifact="$value" ;;
            sha256)
                [[ -z "$meta_sha256" ]] || die "duplicate metadata key: sha256"
                meta_sha256="$value" ;;
            source_sha)
                [[ -z "$meta_source_sha" ]] || die "duplicate metadata key: source_sha"
                meta_source_sha="$value" ;;
            version)
                [[ -z "$meta_version" ]] || die "duplicate metadata key: version"
                meta_version="$value" ;;
            build)
                [[ -z "$meta_build" ]] || die "duplicate metadata key: build"
                meta_build="$value" ;;
            architecture)
                [[ -z "$meta_architecture" ]] || die "duplicate metadata key: architecture"
                meta_architecture="$value" ;;
            signing_identity)
                [[ -z "$meta_identity" ]] || die "duplicate metadata key: signing_identity"
                meta_identity="$value" ;;
            codesign)
                [[ -z "$meta_codesign" ]] || die "duplicate metadata key: codesign"
                meta_codesign="$value" ;;
            stapler)
                [[ -z "$meta_stapler" ]] || die "duplicate metadata key: stapler"
                meta_stapler="$value" ;;
            gatekeeper)
                [[ -z "$meta_gatekeeper" ]] || die "duplicate metadata key: gatekeeper"
                meta_gatekeeper="$value" ;;
            *) die "unknown release metadata key: $key" ;;
        esac
    done <"$metadata"

    [[ "$meta_format" == "1" ]] || die "unsupported release metadata format: $meta_format"
    [[ "$meta_sha256" =~ ^[0-9a-f]{64}$ ]] || die "metadata has an invalid SHA-256 digest."
    [[ "$meta_source_sha" =~ ^[0-9a-f]{40}$ ]] || die "metadata has an invalid source SHA."
    [[ "$meta_architecture" == "arm64" ]] || die "metadata architecture is not arm64."
    [[ "$meta_codesign" == "deep-strict-verified" ]] || die "metadata does not record a verified signature."
    [[ "$meta_stapler" == "validated" ]] || die "metadata does not record a validated staple."
    [[ "$meta_gatekeeper" == "accepted-notarized-developer-id" ]] \
        || die "metadata does not record notarized Developer ID Gatekeeper acceptance."
    [[ "$meta_identity" == "Developer ID Application:"* ]] \
        || die "metadata does not name a Developer ID Application identity."
    [[ "$meta_build" =~ ^[0-9]+(\.[0-9]+)*$ ]] || die "metadata has an invalid build number."
    [[ "$meta_source_sha" == "$source_sha" ]] \
        || die "metadata was built from $meta_source_sha, but this checkout is $source_sha."
    if [[ -n "$version" && "$version" != "$meta_version" ]]; then
        die "requested version $version does not match metadata version $meta_version."
    fi
    version="$meta_version"
    build_number="$meta_build"
    [[ "$(basename "$metadata")" == "GimbalLocal-$version.release-metadata" ]] \
        || die "metadata filename does not match version $version."
    [[ "$meta_artifact" == "GimbalLocal-$version.zip" ]] \
        || die "metadata artifact name does not match version $version."
    zip="$metadata_dir/$meta_artifact"
    [[ -f "$zip" && ! -L "$zip" ]] \
        || die "reviewed artifact is not a regular, non-symlink file: $zip"
fi

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$ ]] \
    || die "invalid release version \"$version\"."
[[ "$build_number" =~ ^[0-9]+(\.[0-9]+)*$ ]] \
    || die "invalid CFBundleVersion \"$build_number\"."
if [[ "$chm_version" != "$version" ]]; then
    die "chm/Cargo.toml says $chm_version but this release is $version, so the app
      and its bundled chm would not identify the same source version."
fi

if [[ -z "$identity" ]]; then
    die "GIMBAL_SIGN_IDENTITY is not set.

  Building and promoting both require the expected Developer ID Application
  identity. Promotion trusts this value independently of the unsigned metadata,
  then verifies that the reviewed ZIP and metadata name the same signer.

  List the identities you have:
      security find-identity -v -p codesigning

  Then, using the full string including the team ID in parentheses:
      export GIMBAL_SIGN_IDENTITY='Developer ID Application: Your Name (TEAMID)'"
fi

if [[ "$mode" == "promote" && "$meta_identity" != "$identity" ]]; then
    die "release metadata names a different signing identity:
      expected: $identity
      metadata: $meta_identity"
fi

if [[ "$mode" == "build" ]] \
    && ! security find-identity -v -p codesigning | grep -qF "$identity"; then
    die "no codesigning identity matches:
      $identity

  Available:
$(security find-identity -v -p codesigning | sed 's/^/      /')"
fi

if [[ "$mode" == "build" ]]; then
    case "$identity" in
        "Developer ID Application:"*) ;;
        *) die "\"$identity\" is not a Developer ID Application certificate.

  Apple Development and Mac Developer certificates work on your own machine but
  cannot be notarized, so the result would not run on anyone else's." ;;
    esac
fi

if [[ "$mode" == "promote" ]]; then
    command -v gh >/dev/null || die "gh is not installed, and --promote needs it to create the release."
    gh auth status >/dev/null 2>&1 || die "gh is not authenticated. Run: gh auth login"

    # The README tells people where to download this. If it names a different
    # repo than the one we are about to publish to, the very first thing a
    # downloader does -- click that link -- fails, and the artifact is perfect
    # and unreachable. This is not hypothetical: the first release was nearly
    # cut with README pointing at a repo that does not exist.
    target_repo="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"
    gh api "repos/$target_repo/commits/$source_sha" --silent >/dev/null \
        || die "source commit $source_sha is not available in $target_repo.
      Push the reviewed commit before promoting its artifact."
    if ! grep -q "github.com/$target_repo/releases" README.md; then
        die "README.md does not point at $target_repo/releases, so the download
      link people follow will not lead to this release.

      Found instead:
$(grep -n 'github.com/[^)]*/releases' README.md | sed 's/^/        /' || echo '        (no releases link at all)')"
    fi

    # The link can name the right repo and still be unfollowable: a release
    # asset on a private repo answers an unauthenticated fetch with nine bytes
    # reading "Not Found", which unzip reports as a corrupt archive. The
    # artifact is fine and the instructions are wrong.
    #
    # Publishing a private build is legitimate, so this does not refuse one --
    # it refuses a private build whose README claims a public download. What
    # makes that claim honest is admitting access is needed, so that is what is
    # checked, and only when the repo is actually private.
    if [[ "$(gh repo view --json isPrivate --jq .isPrivate)" == "true" ]] \
        && ! grep -qi "repository is private" README.md; then
        die "$target_repo is private, so the Releases link in README.md 404s for
      anyone without access to it -- they get a 9-byte file containing
      \"Not Found\", which fails to unzip with no useful error.

      Either make the repository public, or say so in README.md near the
      download instructions. The check looks for the phrase:
          This repository is private"
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
    remote_tag="$(git ls-remote --tags origin \
        "refs/tags/v$version" "refs/tags/v$version^{}")" \
        || die "could not inspect remote tag v$version."
    if [[ -n "$remote_tag" ]]; then
        remote_tag_target="$(echo "$remote_tag" \
            | awk '$2 ~ /\^\{\}$/ {print $1; found=1} !found {fallback=$1} END {if (!found) print fallback}' \
            | tail -n 1)"
        [[ "$remote_tag_target" == "$source_sha" ]] \
            || die "remote tag v$version targets $remote_tag_target, not reviewed source $source_sha."
    fi
    if gh release view "v$version" >/dev/null 2>&1; then
        die "release v$version already exists; refusing to replace or add assets to it."
    fi
fi

# Last, because it is the only preflight check that leaves this machine. Every
# check above is instant and local, and a preflight that spends an Apple round
# trip before noticing an unset variable is failing slower than it needs to.
#
# Ask Apple, rather than checking that a local file exists. A profile can be
# present and hold credentials that no longer authenticate; the only way to
# know is a round trip.
if [[ "$mode" == "build" ]] \
    && ! xcrun notarytool history --keychain-profile "$notary_profile" >/dev/null 2>&1; then
    die "the notary profile \"$notary_profile\" does not authenticate with Apple.

  Create it with an app-specific password from appleid.apple.com:
      xcrun notarytool store-credentials \"$notary_profile\" \\
          --apple-id you@example.com \\
          --team-id TEAMID \\
          --password xxxx-xxxx-xxxx-xxxx"
fi

echo "  mode            $mode"
echo "  source          $source_sha"
echo "  version         $version (build $build_number)"
if [[ "$mode" == "build" ]]; then
    echo "  identity        $identity"
    echo "  notary profile  $notary_profile"
else
    echo "  artifact        $zip"
fi

# Shared artifact checks are used both immediately after notarization and days
# later during promotion. Promotion therefore trusts neither a stale target/
# bundle nor metadata claims without measuring the ZIP again.
cleanup_paths=()
cleanup() {
    for cleanup_path in "${cleanup_paths[@]}"; do
        rm -rf "$cleanup_path"
    done
}
trap cleanup EXIT

verify_arm64_executable() {
    executable="$1"
    label="$2"
    [[ -x "$executable" ]] || die "$label is missing or not executable: $executable"
    executable_arches="$(lipo -archs "$executable" 2>/dev/null)" \
        || die "$label is not a Mach-O executable: $executable"
    [[ "$executable_arches" == "arm64" ]] \
        || die "$label must be an arm64-only Mach-O, but lipo reports: $executable_arches"
    executable_kind="$(file -b "$executable")"
    [[ "$executable_kind" == *"Mach-O 64-bit executable arm64"* ]] \
        || die "$label is not an arm64 Mach-O executable: $executable_kind"
}

verify_signature_identity() {
    signed_path="$1"
    signed_label="$2"
    signature_info="$(codesign -dv --verbose=4 "$signed_path" 2>&1)" \
        || die "could not inspect the $signed_label signature."
    echo "$signature_info" | grep -qxF "Authority=$identity" \
        || die "$signed_label is not signed by the reviewed identity:
      expected: $identity"
    echo "$signature_info" | grep -q 'flags=.*runtime' \
        || die "$signed_label does not have the hardened runtime enabled."
}

verify_bundle_payload() {
    checked_bundle="$1"
    verify_arm64_executable "$checked_bundle/Contents/MacOS/GimbalLocal" "packaged GimbalLocal"
    verify_arm64_executable "$checked_bundle/Contents/MacOS/chm" "packaged chm"

    plist_version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' \
        "$checked_bundle/Contents/Info.plist" 2>/dev/null)" \
        || die "could not read CFBundleShortVersionString from the packaged Info.plist."
    [[ "$plist_version" == "$version" ]] \
        || die "packaged Info.plist reports $plist_version; expected exactly $version."
    plist_build="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' \
        "$checked_bundle/Contents/Info.plist" 2>/dev/null)" \
        || die "could not read CFBundleVersion from the packaged Info.plist."
    [[ "$plist_build" == "$build_number" ]] \
        || die "packaged Info.plist build is $plist_build; expected $build_number."

    for legal_name in LICENSE NOTICE THIRD_PARTY_NOTICES.md CREDITS.md EULA.md; do
        [[ -f "$checked_bundle/Contents/Resources/$legal_name" ]] \
            || die "packaged legal material is missing: Resources/$legal_name"
    done
    [[ -d "$checked_bundle/Contents/Resources/LICENSES" ]] \
        && [[ -n "$(find "$checked_bundle/Contents/Resources/LICENSES" \
            -type f -print -quit 2>/dev/null)" ]] \
        || die "packaged legal material is missing: Resources/LICENSES/"

    codesign --verify --deep --strict "$checked_bundle" \
        || die "the packaged app's signature does not verify."
    verify_signature_identity "$checked_bundle" "app bundle"
    verify_signature_identity "$checked_bundle/Contents/MacOS/GimbalLocal" "app executable"
    verify_signature_identity "$checked_bundle/Contents/MacOS/chm" "chm executable"
}

verify_chm_version() {
    checked_bundle="$1"
    reported_chm_version="$("$checked_bundle/Contents/MacOS/chm" --version 2>&1)" \
        || die "packaged chm --version did not run."
    [[ "$reported_chm_version" == "chm $version" ]] \
        || die "packaged chm reports \"$reported_chm_version\"; expected exactly \"chm $version\"."
}

verify_notarized_bundle() {
    checked_bundle="$1"
    xcrun stapler validate "$checked_bundle" \
        || die "the packaged app's stapled ticket does not validate."
    gatekeeper_result="$(spctl --assess --type execute --verbose=4 "$checked_bundle" 2>&1 || true)"
    echo "$gatekeeper_result" | sed 's/^/  /'
    echo "$gatekeeper_result" | grep -q "accepted" \
        || die "Gatekeeper refuses the packaged app."
    echo "$gatekeeper_result" | grep -q "Notarized Developer ID" \
        || die "Gatekeeper did not assess the packaged app as Notarized Developer ID."
}

verify_archive() {
    checked_zip="$1"
    extract_check="$(mktemp -d)"
    cleanup_paths+=("$extract_check")
    ditto -x -k "$checked_zip" "$extract_check" \
        || die "the reviewed archive does not extract."
    extracted="$extract_check/GimbalLocal.app"
    [[ -d "$extracted" ]] || die "the archive does not contain GimbalLocal.app."
    strays="$(find "$extracted" -name '._*' | wc -l | tr -d ' ')"
    [[ "$strays" == "0" ]] \
        || die "$strays AppleDouble files landed inside the extracted bundle.
      They are not covered by the signature, so macOS will refuse to run it."
    verify_bundle_payload "$extracted"
    verify_notarized_bundle "$extracted"
    # Execute packaged code only after its signature, expected signer, staple,
    # and Gatekeeper assessment have all been verified independently.
    verify_chm_version "$extracted"
}

if [[ "$mode" == "build" ]]; then
    zip="$repo_root/target/GimbalLocal-$version.zip"
    metadata="$repo_root/target/GimbalLocal-$version.release-metadata"
    [[ ! -e "$zip" && ! -L "$zip" ]] \
        || die "$zip already exists. Refusing to overwrite a potentially reviewed artifact."
    [[ ! -e "$metadata" && ! -L "$metadata" ]] \
        || die "$metadata already exists. Refusing to overwrite release provenance."

    # The gate. See the header comment: the tests must run in the configuration
    # being shipped, or they are not evidence about the artifact.
    step "Tests, in the release configuration this ships"

    cargo test --locked -p hypervisor --release --no-default-features \
        --features hvf,kvm-snapshot --lib \
        || die "hypervisor tests failed in release configuration.

  Do not ship this. A failure here that does not reproduce in debug is exactly
  the class of bug this gate exists to catch — see the header of this script."
    assert_source_unchanged

    cargo test --locked -p gimbal-local --release \
        || die "chm tests failed in release configuration. Do not ship this."
    assert_source_unchanged

    swift test -c release --package-path app/GimbalLocal \
        || die "app tests failed in release configuration. Do not ship this."
    assert_source_unchanged

    step "Building and signing the app"

    GIMBAL_SIGN_IDENTITY="$identity" \
    GIMBAL_VERSION="$version" \
    GIMBAL_BUILD="$build_number" \
        scripts/build-gimbal-local-app.sh --release
    assert_source_unchanged

    bundle="$repo_root/target/GimbalLocal.app"
    [[ -d "$bundle" ]] || die "the release build did not produce GimbalLocal.app."
    # Architecture, exact versions and signatures are checked before any bytes
    # are sent to Apple, not merely after publication.
    verify_bundle_payload "$bundle"

    step "Notarizing (this uploads to Apple and waits)"

    notarization_dir="$(mktemp -d)"
    cleanup_paths+=("$notarization_dir")
    notarization_zip="$notarization_dir/GimbalLocal-$version.zip"
    # ditto, not `zip`: it preserves the bundle structure and extended
    # attributes notarization requires.
    ditto -c -k --keepParent "$bundle" "$notarization_zip"
    assert_source_unchanged

    xcrun notarytool submit "$notarization_zip" \
        --keychain-profile "$notary_profile" --wait \
        || die "notarization failed.

  For the detail Apple recorded:
      xcrun notarytool history --keychain-profile \"$notary_profile\"
      xcrun notarytool log <submission-id> --keychain-profile \"$notary_profile\""
    assert_source_unchanged

    step "Stapling and verifying"

    # The ticket must live inside the bundle a recipient gets so it validates
    # without contacting Apple.
    xcrun stapler staple "$bundle" || die "stapling failed."
    verify_notarized_bundle "$bundle"

    artifact_dir="$(mktemp -d)"
    cleanup_paths+=("$artifact_dir")
    artifact_tmp="$artifact_dir/GimbalLocal-$version.zip"
    ditto -c -k --keepParent "$bundle" "$artifact_tmp"

    step "Verifying the artifact a user receives"
    verify_archive "$artifact_tmp"
    artifact_sha256="$(shasum -a 256 "$artifact_tmp" | awk '{print $1}')"
    [[ "$artifact_sha256" =~ ^[0-9a-f]{64}$ ]] \
        || die "could not compute the artifact SHA-256 digest."
    assert_source_unchanged

    mv "$artifact_tmp" "$zip"
    metadata_tmp="$metadata.tmp.$$"
    cleanup_paths+=("$metadata_tmp")
    {
        printf 'format=1\n'
        printf 'artifact=%s\n' "$(basename "$zip")"
        printf 'sha256=%s\n' "$artifact_sha256"
        printf 'source_sha=%s\n' "$source_sha"
        printf 'version=%s\n' "$version"
        printf 'build=%s\n' "$build_number"
        printf 'architecture=arm64\n'
        printf 'signing_identity=%s\n' "$identity"
        printf 'codesign=deep-strict-verified\n'
        printf 'stapler=validated\n'
        printf 'gatekeeper=accepted-notarized-developer-id\n'
    } >"$metadata_tmp"
    mv "$metadata_tmp" "$metadata"
    final_sha256="$(shasum -a 256 "$zip" | awk '{print $1}')"
    [[ "$final_sha256" == "$artifact_sha256" ]] \
        || die "the durable artifact changed while recording its metadata."
    assert_source_unchanged

    step "Done"
    echo "  artifact  $zip"
    echo "  sha256    $artifact_sha256"
    echo "  metadata  $metadata"
    echo
    echo "  Not published. Install and review that ZIP, then promote those exact bytes:"
    echo "      scripts/release-macos.sh --promote $metadata"
    exit 0
fi

step "Re-verifying the reviewed artifact"
actual_sha256="$(shasum -a 256 "$zip" | awk '{print $1}')"
[[ "$actual_sha256" == "$meta_sha256" ]] \
    || die "artifact digest mismatch:
      metadata: $meta_sha256
      actual:   $actual_sha256"
verify_archive "$zip"
assert_source_unchanged

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
- No control plane or account. Guest execution is local and can run offline;
  pulling an image from a container registry requires network access.
- No Rust toolchain, no Xcode, no source checkout. \`chm\` ships inside the app.

The app is signed with a Developer ID certificate and notarized by Apple, so it
opens without a Gatekeeper warning and its ticket verifies offline.

The accompanying \`GimbalLocal-$version.release-metadata\` provenance asset
records the source commit, ZIP SHA-256, arm64 architecture, and signing identity
verified before this release was created.

### Install

1. Download \`GimbalLocal-$version.zip\` below.
2. Double-click it in Finder to unpack, then move **GimbalLocal.app** to
   /Applications. Finder shows it as **Gimbal Local**.
3. Open it. The engine starts itself.

If you unpack from a terminal, use \`ditto\`, not \`unzip\`:

\`\`\`
ditto -x -k GimbalLocal-$version.zip .
\`\`\`

\`unzip\` does not understand the extended attributes this archive carries, and
writes them into the app bundle as stray \`._*\` files. They are not covered by
the code signature, so macOS refuses to run the result. Finder and \`ditto\` both
unpack it correctly.

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
- a container reference plus an arm64 kernel — for example,
  \`chm image build alpine:3.20 --kernel /path/to/Image\`. The image may also
  need the matching module tree via \`--modules\`. Registry pulls use the
  network.

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

assert_source_unchanged
gh release create "v$version" "$zip" "$metadata" \
    --target "$source_sha" \
    --title "Gimbal Local $version" \
    --notes-file "$notes"

echo
echo "  Published: $(gh release view "v$version" --json url --jq .url)"
