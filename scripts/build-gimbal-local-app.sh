#!/usr/bin/env bash
# Copyright © 2024 Cloud Hypervisor contributors
#
# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

#
# Usage:
#   scripts/build-gimbal-local-app.sh [--release]
#
# Environment:
#   GIMBAL_SIGN_IDENTITY  codesign identity. Defaults to "-" (ad-hoc), which is
#                         what a developer wants and what CI can do. A release
#                         passes a "Developer ID Application: …" identity.
#   GIMBAL_VERSION        CFBundleShortVersionString. If unset, this is derived
#                         from chm/Cargo.toml.
#   GIMBAL_BUILD          CFBundleVersion (default 1).
#
# Debug and release differ in one behavioural way, and it is deliberate: a
# release bundles `chm` inside the .app, a debug build does not. The app treats
# a bundled `chm` as the signal that it is a shipped copy (see
# `resolveChmPath` in Models.swift), so *not* bundling it is what keeps a
# developer's own `target/debug/chm` in play automatically. There is no mode
# flag anywhere that could disagree with reality.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
app_pkg="$repo_root/app/GimbalLocal"
bundle="$repo_root/target/GimbalLocal.app"
contents="$bundle/Contents"
macos="$contents/MacOS"
resources="$contents/Resources"

configuration="debug"
if [[ "${1:-}" == "--release" ]]; then
    configuration="release"
elif [[ -n "${1:-}" ]]; then
    echo "build-gimbal-local-app.sh: unknown argument: $1" >&2
    echo "usage: build-gimbal-local-app.sh [--release]" >&2
    exit 2
fi
[[ $# -le 1 ]] || {
    echo "build-gimbal-local-app.sh: too many arguments" >&2
    echo "usage: build-gimbal-local-app.sh [--release]" >&2
    exit 2
}

identity="${GIMBAL_SIGN_IDENTITY:--}"
chm_version="$(awk '/^\[package\]/{p=1;next} /^\[/{p=0} p&&/^version *=/{gsub(/[",]/,"");print $3;exit}' "$repo_root/chm/Cargo.toml")"
if [[ -z "$chm_version" ]]; then
    echo "build-gimbal-local-app.sh: could not read chm/Cargo.toml package version" >&2
    exit 1
fi
version="${GIMBAL_VERSION:-$chm_version}"
build_number="${GIMBAL_BUILD:-1}"

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$ ]]; then
    echo "build-gimbal-local-app.sh: invalid version \"$version\"" >&2
    exit 1
fi
if [[ ! "$build_number" =~ ^[0-9]+(\.[0-9]+)*$ ]]; then
    echo "build-gimbal-local-app.sh: invalid CFBundleVersion \"$build_number\"" >&2
    exit 1
fi
if [[ "$configuration" == "release" && "$version" != "$chm_version" ]]; then
    echo "build-gimbal-local-app.sh: release version $version does not match chm/Cargo.toml ($chm_version)" >&2
    exit 1
fi

# A shipped bundle must carry the notices that apply to it. Check this before
# either compiler runs. Debug builds copy everything available but only warn,
# which keeps an incomplete developer checkout usable.
legal_files=(
    "LICENSE"
    "NOTICE"
    "THIRD_PARTY_NOTICES.md"
    "CREDITS.md"
    "app/GimbalLocal/EULA.md"
)
missing_legal=()
for legal_file in "${legal_files[@]}"; do
    [[ -f "$repo_root/$legal_file" ]] || missing_legal+=("$legal_file")
done
if [[ ! -d "$repo_root/LICENSES" ]] \
    || [[ -z "$(find "$repo_root/LICENSES" -type f -print -quit 2>/dev/null)" ]]; then
    missing_legal+=("LICENSES/ (with license texts)")
fi
if [[ ${#missing_legal[@]} -gt 0 ]]; then
    if [[ "$configuration" == "release" ]]; then
        printf 'build-gimbal-local-app.sh: release legal material is missing:\n' >&2
        printf '  %s\n' "${missing_legal[@]}" >&2
        exit 1
    fi
    printf 'build-gimbal-local-app.sh: warning: legal material is missing:\n' >&2
    printf '  %s\n' "${missing_legal[@]}" >&2
fi
draft_eula_marker="DRAFT — legal review required before public distribution"
if [[ "$configuration" == "release" ]] \
    && grep -qF "$draft_eula_marker" "$repo_root/app/GimbalLocal/EULA.md"; then
    echo "build-gimbal-local-app.sh: app/GimbalLocal/EULA.md is still marked:" >&2
    echo "  $draft_eula_marker" >&2
    echo "Legal review must remove that marker before a release build." >&2
    exit 1
fi

# One definition of "what entitlements does chm need". Deliberately the same
# file `scripts/build-chm.sh` has signed with since the port began — a second
# copy for release builds would be free to drift, and the drift would only
# surface as HV_DENIED on someone else's Mac.
entitlements="$repo_root/hypervisor/tests/data/hv.entitlements"

# `codesign` accepts --timestamp only against a real identity; an ad-hoc
# signature has nothing for Apple's timestamp server to countersign. Hardened
# Runtime is release-only so a debug build stays attachable to a debugger.
sign_common=(--force --sign "$identity")
if [[ "$configuration" == "release" ]]; then
    sign_common+=(--options runtime)
    if [[ "$identity" != "-" ]]; then
        sign_common+=(--timestamp)
    fi
fi

if [[ "$configuration" == "release" ]]; then
    chm_bin="$("$repo_root/scripts/build-chm.sh" --release)"
else
    "$repo_root/scripts/build-chm.sh" >/dev/null
fi
swift build --package-path "$app_pkg" -c "$configuration" --product GimbalLocal

rm -rf "$bundle"
mkdir -p "$macos" "$resources"
cp "$app_pkg/.build/$configuration/GimbalLocal" "$macos/GimbalLocal"

if [[ "$configuration" == "release" ]]; then
    cp "$repo_root/$chm_bin" "$macos/chm"
fi

# Keep the committed names so a recipient can identify each notice without
# needing source-tree context.
for legal_file in "${legal_files[@]}"; do
    if [[ -f "$repo_root/$legal_file" ]]; then
        cp "$repo_root/$legal_file" "$resources/$(basename "$legal_file")"
    fi
done
if [[ -d "$repo_root/LICENSES" ]]; then
    cp -R "$repo_root/LICENSES" "$resources/LICENSES"
fi

# Generate the app icon (.icns) from the committed 1024px master. iconutil and
# sips are part of macOS, so this needs no extra tooling. The intermediate
# .iconset is built in a temp dir and discarded.
icon_master="$app_pkg/Resources/AppIcon.png"
if [[ -f "$icon_master" ]]; then
    iconset="$(mktemp -d)/AppIcon.iconset"
    mkdir -p "$iconset"
    for spec in "16:16x16" "32:16x16@2x" "32:32x32" "64:32x32@2x" \
                "128:128x128" "256:128x128@2x" "256:256x256" "512:256x256@2x" \
                "512:512x512" "1024:512x512@2x"; do
        px="${spec%%:*}"
        name="${spec##*:}"
        sips -s format png -z "$px" "$px" "$icon_master" \
            --out "$iconset/icon_${name}.png" >/dev/null
    done
    iconutil -c icns "$iconset" -o "$resources/AppIcon.icns"
    rm -rf "$(dirname "$iconset")"
else
    echo "build-gimbal-local-app.sh: warning: $icon_master missing; no app icon" >&2
fi

cat >"$contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleExecutable</key>
  <string>GimbalLocal</string>
  <key>CFBundleIconFile</key>
  <string>AppIcon</string>
  <key>CFBundleIconName</key>
  <string>AppIcon</string>
  <key>CFBundleIdentifier</key>
  <string>dev.gimbal.local</string>
  <key>CFBundleInfoDictionaryVersion</key>
  <string>6.0</string>
  <key>CFBundleName</key>
  <string>Gimbal Local</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>${version}</string>
  <key>CFBundleVersion</key>
  <string>${build_number}</string>
  <key>LSMinimumSystemVersion</key>
  <string>14.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSAppleEventsUsageDescription</key>
  <string>Gimbal Local opens a Terminal window so you can use a sandbox's console.</string>
</dict>
</plist>
PLIST

# Sign inside out: nested code first, then the bundle that contains it. A
# bundle's signature covers its contents, so signing chm afterwards would
# invalidate the enclosing signature and notarization would reject it.
if [[ "$configuration" == "release" ]]; then
    codesign "${sign_common[@]}" --entitlements "$entitlements" "$macos/chm" >/dev/null
fi
codesign "${sign_common[@]}" "$bundle" >/dev/null

echo "$bundle"
