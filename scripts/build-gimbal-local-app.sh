#!/usr/bin/env bash
# Copyright © 2024 Cloud Hypervisor contributors
#
# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
app_pkg="$repo_root/app/GimbalLocal"
bundle="$repo_root/target/GimbalLocal.app"
contents="$bundle/Contents"
macos="$contents/MacOS"
resources="$contents/Resources"

"$repo_root/scripts/build-chm.sh" >/dev/null
swift build --package-path "$app_pkg" -c debug --product GimbalLocal

rm -rf "$bundle"
mkdir -p "$macos" "$resources"
cp "$app_pkg/.build/debug/GimbalLocal" "$macos/GimbalLocal"

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

cat >"$contents/Info.plist" <<'PLIST'
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
  <string>0.1.0</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>LSMinimumSystemVersion</key>
  <string>14.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
PLIST

codesign --force --sign - "$bundle" >/dev/null

echo "$bundle"
