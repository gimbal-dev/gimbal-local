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
