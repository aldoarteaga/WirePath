#!/bin/zsh
# Developer tool: renders WirePath for macOS screens to PNG using the in-app snapshot mode (Debug builds
# only; needs no screen-recording permission).
#   scripts/snapshot.sh <out-dir> <capture> [dark|light] [routes] [WIDTHxHEIGHT]      (WIREPATH_LANGUAGE=es for Spanish)
#   routes: comma-separated overview, calls, call:N, packets[:N], frame:N, sip, rtp, webrtc[:N], timeline, flows,
#           statistics, diagnostics, inspector, nosidebar
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=${1:?out dir}; CAPTURE=${2:?capture}; APPEARANCE=${3:-dark}; ROUTES=${4:-overview}; SIZE=${5:-1440x900}
APP=build/DerivedDataMacTests/Build/Products/Debug/WirePath.app
if [[ ! -d $APP || -n "${REBUILD:-}" ]]; then
  xcodebuild -project WirePath.xcodeproj -scheme WirePathMac -configuration Debug -destination 'platform=macOS,arch=arm64' \
    -derivedDataPath build/DerivedDataMacTests -quiet build
fi
# WIREPATH_LANGUAGE=es renders the Spanish interface.
LANGUAGE_ARGS=()
[[ -n "${WIREPATH_LANGUAGE:-}" ]] && LANGUAGE_ARGS=(-AppleLanguages "(${WIREPATH_LANGUAGE})" -AppleLocale "${WIREPATH_LANGUAGE}_MX")
LIB=$(mktemp -d)
mkdir -p "$OUT"
WIREPATH_LIBRARY_ROOT=$LIB WIREPATH_IMPORT=${CAPTURE:A} WIREPATH_APPEARANCE=$APPEARANCE \
WIREPATH_SNAPSHOT_DIR=${OUT:A} WIREPATH_SNAPSHOT_ROUTES=$ROUTES WIREPATH_SNAPSHOT_SIZE=$SIZE "$APP/Contents/MacOS/WirePath" $LANGUAGE_ARGS &
PID=$!
( sleep 120; kill $PID 2>/dev/null ) &
wait $PID 2>/dev/null || true
rm -rf "$LIB"
