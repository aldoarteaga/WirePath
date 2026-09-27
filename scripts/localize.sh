#!/bin/zsh
# Extracts every localizable string from the sources and syncs the two string catalogs:
#   Packages/WirePathCore/Sources/WirePathCore/Resources/Localizable.xcstrings   diagnostics, call states, errors (package bundle)
#   Localization/Localizable.xcstrings                                            the interface (both apps' main bundle)
# New keys are added, keys no longer in the code are marked stale, and translations are kept. Then
# scripts/check-localization.py reports anything without a Spanish translation.
set -euo pipefail
cd "$(dirname "$0")/.."
BUILD=${TMPDIR:-/tmp}/wirepath-localize
(cd Packages/WirePathUI && swift build --scratch-path "$BUILD" -Xswiftc -emit-localized-strings >/dev/null)
core=(${(f)"$(find "$BUILD" -path '*WirePathCore.build*' -name '*.stringsdata')"})
ui=(${(f)"$(find "$BUILD" -path '*WirePathUI.build*' -name '*.stringsdata')"})
xcrun xcstringstool sync Packages/WirePathCore/Sources/WirePathCore/Resources/Localizable.xcstrings --stringsdata $core
xcrun xcstringstool sync Localization/Localizable.xcstrings --stringsdata $ui
python3 scripts/check-localization.py Packages/WirePathCore/Sources/WirePathCore/Resources/Localizable.xcstrings Localization/Localizable.xcstrings
