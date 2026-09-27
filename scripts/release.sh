#!/bin/zsh
# Release builds of WirePath. See docs/release.md.
#
#   scripts/release.sh check                 Release builds (no team needed): verifies sandbox, entitlements,
#                                            privacy manifest, Info.plist keys and that no Debug hooks ship
#   scripts/release.sh mac-appstore          archive + export for the Mac App Store     (TEAM_ID)
#   scripts/release.sh mac-developer-id      archive + export + notarize + staple       (TEAM_ID, NOTARY_PROFILE)
#   scripts/release.sh ipad-appstore         archive + export for App Store / TestFlight (TEAM_ID)
#   UPLOAD=1 scripts/release.sh ipad-appstore   upload to App Store Connect instead of exporting (also mac-appstore)
#
# TEAM_ID         Apple Developer team identifier (10 characters)
# NOTARY_PROFILE  keychain profile made once with `xcrun notarytool store-credentials`
# BUILD_NUMBER    optional CFBundleVersion override (App Store Connect needs a new one per upload)
# Nothing secret is read from or written to the repository: signing uses the keychain and Xcode's accounts.
set -euo pipefail
cd "$(dirname "$0")/.."
MODE=${1:?"usage: scripts/release.sh check | mac-appstore | mac-developer-id | ipad-appstore"}
OUT=build/Release
mkdir -p "$OUT"

# The only entitlements a WirePath build may carry (macOS). No network, no capture, no temporary exceptions.
ALLOWED_ENTITLEMENTS=(com.apple.security.app-sandbox com.apple.security.files.user-selected.read-write
                      com.apple.security.files.bookmarks.app-scope
                      com.apple.application-identifier com.apple.developer.team-identifier)

fail() { print -u2 "✘ $1"; exit 1; }
ok() { print "✔ $1"; }

# Checks one built app bundle: entitlements, privacy manifest, Info.plist and Debug-only hooks.
verify_app() {
  local app=$1 platform=$2 binary info
  if [[ $platform == mac ]]; then
    binary="$app/Contents/MacOS/WirePath"; info="$app/Contents/Info.plist"
    [[ -f "$app/Contents/Resources/PrivacyInfo.xcprivacy" ]] || fail "privacy manifest missing from $app"
    codesign --verify --deep --strict "$app" || fail "code signature of $app does not verify"
    local entitlements=$(codesign -d --entitlements - --xml "$app" 2>/dev/null)
    local keys=(${(f)"$(print -r -- "$entitlements" | plutil -convert json -o - - | python3 -c 'import json,sys; [print(k) for k in json.load(sys.stdin)]')"})
    for key in $keys; do
      (( ${ALLOWED_ENTITLEMENTS[(Ie)$key]} )) || fail "unexpected entitlement $key"
    done
    print -r -- "$entitlements" | plutil -convert json -o - - \
      | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("com.apple.security.app-sandbox") is True else 1)' \
      || fail "App Sandbox is not enabled"
    [[ $(codesign -d --verbose=2 "$app" 2>&1) == *flags=*runtime* ]] || fail "hardened runtime is off"
    ok "entitlements: ${(j:, :)keys}"
  else
    binary="$app/WirePath"; info="$app/Info.plist"
    [[ -f "$app/PrivacyInfo.xcprivacy" ]] || fail "privacy manifest missing from $app"
    [[ $(plutil -extract LSSupportsOpeningDocumentsInPlace raw -o - "$info") == true ]] \
      || fail "LSSupportsOpeningDocumentsInPlace missing (App Store requires it with document types)"
  fi
  [[ $(plutil -extract ITSAppUsesNonExemptEncryption raw -o - "$info") == false ]] \
    || fail "ITSAppUsesNonExemptEncryption must be declared false"
  # Launch-environment hooks (library root, imports, snapshot mode) are compiled only into Debug builds. (Names
  # of 15 bytes or fewer are inlined by Swift and invisible to strings; these two are longer.)
  # Every executable next to the main one counts: Debug builds put the app's code in WirePath.debug.dylib.
  local file text
  for file in "$binary" "${binary:h}"/*.dylib(N); do
    text=$(strings - "$file")
    [[ $text == *WIREPATH_LIBRARY_ROOT* || $text == *WIREPATH_SNAPSHOT_DIR* ]] && fail "Debug launch hooks found in $file"
  done
  ok "$platform: privacy manifest, Info.plist, no Debug hooks ($(du -sh "$app" | cut -f1))"
}

export_options() {  # method destination -> plist path
  local plist="$OUT/ExportOptions-$1-$2.plist"
  cat > "$plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>method</key><string>$1</string>
	<key>destination</key><string>$2</string>
	<key>teamID</key><string>${TEAM_ID}</string>
	<key>signingStyle</key><string>automatic</string>
	<key>uploadSymbols</key><true/>
	<key>manageAppVersionAndBuildNumber</key><false/>
</dict>
</plist>
PLIST
  print -r -- "$plist"
}

archive() {  # scheme destination name
  local archive="$OUT/$3.xcarchive" extra=()
  [[ -n "${BUILD_NUMBER:-}" ]] && extra+=(CURRENT_PROJECT_VERSION="$BUILD_NUMBER")
  rm -rf "$archive"
  xcodebuild archive -project WirePath.xcodeproj -scheme "$1" -configuration Release -destination "$2" \
    -archivePath "$archive" -derivedDataPath build/DerivedDataArchive -allowProvisioningUpdates -quiet \
    DEVELOPMENT_TEAM="$TEAM_ID" CODE_SIGN_STYLE=Automatic CODE_SIGN_IDENTITY="Apple Development" $extra
  print -r -- "$archive"
}

export_archive() {  # archive method name [destination: export (default) or upload]
  local destination=${4:-export}
  rm -rf "$OUT/$3"
  xcodebuild -exportArchive -archivePath "$1" -exportPath "$OUT/$3" -allowProvisioningUpdates -quiet \
    -exportOptionsPlist "$(export_options "$2" "$destination")"
  [[ $destination == upload ]] && ok "uploaded $3 to App Store Connect"
  print -r -- "$OUT/$3"
}

case $MODE in
  check)
    xcodebuild build -project WirePath.xcodeproj -scheme WirePathMac -configuration Release \
      -destination 'platform=macOS,arch=arm64' -derivedDataPath build/DerivedDataRelease -quiet
    verify_app build/DerivedDataRelease/Build/Products/Release/WirePath.app mac
    xcodebuild build -project WirePath.xcodeproj -scheme WirePathiPad -configuration Release \
      -destination 'generic/platform=iOS' -derivedDataPath build/DerivedDataRelease -quiet CODE_SIGNING_ALLOWED=NO
    verify_app build/DerivedDataRelease/Build/Products/Release-iphoneos/WirePath.app ipad
    ;;
  mac-appstore)
    : ${TEAM_ID:?set TEAM_ID}
    archive=$(archive WirePathMac 'generic/platform=macOS' WirePath-mac-appstore | tail -1)
    verify_app "$archive/Products/Applications/WirePath.app" mac
    exported=$(export_archive "$archive" app-store-connect WirePath-mac-appstore ${UPLOAD:+upload} | tail -1)
    ok "Mac App Store package: $exported"
    ;;
  mac-developer-id)
    : ${TEAM_ID:?set TEAM_ID} ${NOTARY_PROFILE:?set NOTARY_PROFILE (xcrun notarytool store-credentials)}
    archive=$(archive WirePathMac 'generic/platform=macOS' WirePath-mac-developer-id | tail -1)
    exported=$(export_archive "$archive" developer-id WirePath-mac-developer-id export | tail -1)
    app="$exported/WirePath.app"
    verify_app "$app" mac
    zip="$OUT/WirePath-notarize.zip"
    ditto -c -k --keepParent "$app" "$zip"
    xcrun notarytool submit "$zip" --keychain-profile "$NOTARY_PROFILE" --wait
    xcrun stapler staple "$app"
    spctl --assess --type execute --verbose "$app"
    version=$(plutil -extract CFBundleShortVersionString raw -o - "$app/Contents/Info.plist")
    ditto -c -k --keepParent "$app" "$OUT/WirePath-$version.zip"
    rm -f "$zip"
    ok "notarized and stapled: $OUT/WirePath-$version.zip"
    ;;
  ipad-appstore)
    : ${TEAM_ID:?set TEAM_ID}
    archive=$(archive WirePathiPad 'generic/platform=iOS' WirePath-ipad-appstore | tail -1)
    verify_app "$archive/Products/Applications/WirePath.app" ipad
    exported=$(export_archive "$archive" app-store-connect WirePath-ipad-appstore ${UPLOAD:+upload} | tail -1)
    ok "iPadOS App Store / TestFlight package: $exported"
    ;;
  *) fail "unknown mode $MODE" ;;
esac
