#!/bin/zsh
# Builds WirePath for macOS (Apple Silicon) from WirePath.xcodeproj and copies it to build/WirePath.app.
#   scripts/build-app.sh            Release: App Sandbox on, signed "Sign to Run Locally"
#   scripts/build-app.sh --debug    Debug: no sandbox, launch-environment hooks enabled
# Distribution builds (Mac App Store, Developer ID, TestFlight): scripts/release.sh, see docs/release.md.
set -euo pipefail
cd "$(dirname "$0")/.."
CONFIG=Release
[[ "${1:-}" == "--debug" ]] && CONFIG=Debug
xcodebuild -project WirePath.xcodeproj -scheme WirePathMac -configuration "$CONFIG" \
  -destination 'platform=macOS,arch=arm64' -derivedDataPath build/DerivedData$CONFIG -quiet build
rm -rf build/WirePath.app
cp -R "build/DerivedData$CONFIG/Build/Products/$CONFIG/WirePath.app" build/WirePath.app
echo "Built build/WirePath.app ($CONFIG, $(du -sh build/WirePath.app | cut -f1))"
