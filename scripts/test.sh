#!/bin/zsh
# Runs every WirePath test suite.
#   scripts/test.sh            core + UI packages (macOS), macOS and iPadOS UI tests
#   scripts/test.sh --quick    core + UI packages only
#   IPAD="iPad Air 11-inch (M4)" scripts/test.sh   pick the simulator
set -euo pipefail
cd "$(dirname "$0")/.."
# Full device name, e.g. "iPad Pro 13-inch (M5)" (the UDID and state that follow it are dropped).
IPAD=${IPAD:-$(xcrun simctl list devices available | grep -m1 -E '^ +iPad' | sed -E 's/^ +//; s/ \([0-9A-F-]{36}\).*$//')}

echo "▸ WirePathCore (macOS)"
(cd Packages/WirePathCore && swift test)
echo "▸ WirePathUI (macOS)"
(cd Packages/WirePathUI && swift test)
[[ "${1:-}" == "--quick" ]] && exit 0

echo "▸ WirePathCore on the iPadOS simulator ($IPAD)"
(cd Packages/WirePathCore && xcodebuild test -scheme WirePathCore-Package -destination "platform=iOS Simulator,name=$IPAD" \
  -derivedDataPath ../../build/DerivedDataCoreiOS -quiet)
echo "▸ WirePathUI on the iPadOS simulator ($IPAD)"
(cd Packages/WirePathUI && xcodebuild test -scheme WirePathUI -destination "platform=iOS Simulator,name=$IPAD" \
  -derivedDataPath ../../build/DerivedDataUIiOS -quiet)
echo "▸ macOS UI tests"
xcodebuild test -project WirePath.xcodeproj -scheme WirePathMac -destination 'platform=macOS,arch=arm64' \
  -derivedDataPath build/DerivedDataMacTests -quiet
echo "▸ iPadOS UI tests ($IPAD)"
xcodebuild test -project WirePath.xcodeproj -scheme WirePathiPad -destination "platform=iOS Simulator,name=$IPAD" \
  -derivedDataPath build/DerivedData -quiet
