#!/bin/zsh
# Developer tool: runs the iPad app in a simulator and saves a screenshot.
#   scripts/ipad-snapshot.sh <out.png> <capture> [route] [device] [dark|light] [portrait|landscape]
set -e
cd "$(dirname "$0")/.."
OUT=$1; CAPTURE=$2; ROUTE=${3:-overview}; DEV=${4:-"iPad Pro 13-inch (M5)"}; LOOK=${5:-dark}; ORIENT=${6:-portrait}
xcrun simctl boot "$DEV" 2>/dev/null || true
xcrun simctl bootstatus "$DEV" -b >/dev/null
APP=build/DerivedData/Build/Products/Debug-iphonesimulator/WirePath.app
[[ -d $APP ]] || xcodebuild -project WirePath.xcodeproj -scheme WirePathiPad -destination "platform=iOS Simulator,name=$DEV" -derivedDataPath build/DerivedData -quiet build
xcrun simctl install "$DEV" "$APP"
xcrun simctl ui "$DEV" appearance "$LOOK"
SIMCTL_CHILD_WIREPATH_LIBRARY_ROOT=$(mktemp -d) SIMCTL_CHILD_WIREPATH_IMPORT="$PWD/$CAPTURE" SIMCTL_CHILD_WIREPATH_ROUTE="$ROUTE" \
  xcrun simctl launch --terminate-running-process "$DEV" com.wirepath.WirePath >/dev/null
sleep ${WAIT:-9}
xcrun simctl io "$DEV" screenshot "$OUT" >/dev/null
