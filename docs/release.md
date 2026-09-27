# Release

How WirePath is built, signed and distributed: the Mac App Store and Developer ID (notarized) on macOS, and App Store
and TestFlight on iPadOS. Everything is driven by `scripts/release.sh`. Credentials come from the keychain and
Xcode's accounts and are never stored in the repository.

## Targets and versions

| | macOS | iPadOS |
| --- | --- | --- |
| Scheme | `WirePathMac` | `WirePathiPad` |
| Minimum OS | macOS 15, Apple Silicon (arm64 only) | iPadOS 18, iPad only |
| Bundle ID | `com.wirepath.WirePath` | `com.wirepath.WirePath` |
| Category | Developer Tools | Developer Tools |

`VERSION` (CFBundleShortVersionString) and `BUILD` (CFBundleVersion) are set in `scripts/generate-xcodeproj.py`;
re-run it after changing them. `BUILD_NUMBER=… scripts/release.sh …` overrides the build number for a single
archive, because App Store Connect needs a new one for every upload. The bundle ID must be registered to your team.
If you use another one, change `BUNDLE_ID` in the generator.

## Configurations

| | Debug | Release |
| --- | --- | --- |
| App Sandbox (macOS) | off: UI tests and snapshots read fixtures from the repository | on |
| Entitlements (macOS) | `WirePathMac.Debug.entitlements` (none) | `WirePathMac.entitlements` |
| Launch-environment hooks (`WIREPATH_IMPORT`, `WIREPATH_LIBRARY_ROOT`, snapshot mode) | compiled in | compiled out (`#if DEBUG`) |
| Optimization | `-Onone` | `-O`, whole module, dSYMs |
| Hardened runtime (macOS) | on | on, with no exceptions |

## Entitlements

WirePath analyzes files offline. It never captures traffic and never opens a network connection, so it has no network,
Network Extension, packet-tunnel or VPN entitlement. On macOS the sandbox grants exactly these:

| Entitlement | Why |
| --- | --- |
| `com.apple.security.app-sandbox` | Required for the Mac App Store; used for Developer ID too. |
| `com.apple.security.files.user-selected.read-write` | Read captures the user opens (panels, Finder, drag and drop). Write the exports the user saves (filtered pcap, HTML report, WAV). Move a capture to the Trash when the user asks while deleting an analysis. |
| `com.apple.security.files.bookmarks.app-scope` | Security-scoped bookmarks, so the original capture is found again after relaunch without copying it into the library. |

iPadOS apps are always sandboxed and need no entitlement. Captures opened from Files stay where they are
(`LSSupportsOpeningDocumentsInPlace`) and are reached through security-scoped bookmarks, just as on macOS.
`scripts/release.sh` fails a build that carries any other entitlement.

## Privacy

- `Privacy/PrivacyInfo.xcprivacy` ships in both apps. It declares no tracking, no tracking domains and no collected
  data, plus the reasons for the required-reason APIs WirePath uses: UserDefaults (recent captures), file metadata
  (`fstat` on opened captures and on the packet index), free disk space (checked before expanding a `.pcap.gz`), and
  `mach_absolute_time` (audio scheduling).
- App Store Connect privacy questionnaire: **Data Not Collected**.
- Logs never contain capture contents or credentials. Stored SIP texts are redacted (ICE passwords, SRTP keys,
  Digest responses); see `docs/architecture.md`.

## Export compliance

WirePath contains no encryption. It computes CRC32 checksums only and does not decrypt SRTP or DTLS. Both
Info.plists declare `ITSAppUsesNonExemptEncryption = NO`, so App Store Connect and TestFlight ask no export questions.

## Commands

```bash
scripts/release.sh check                               # no team needed: Release builds + all checks below
TEAM_ID=ABCDE12345 scripts/release.sh mac-appstore     # .pkg for the Mac App Store (UPLOAD=1 to upload)
TEAM_ID=ABCDE12345 NOTARY_PROFILE=wirepath scripts/release.sh mac-developer-id
TEAM_ID=ABCDE12345 UPLOAD=1 BUILD_NUMBER=7 scripts/release.sh ipad-appstore   # to TestFlight
```

Every mode verifies the built app:

- The code signature verifies (`codesign --verify --deep --strict`), and the hardened runtime is on.
- Only the entitlements above are present, and the App Sandbox is enabled.
- The privacy manifest is in the bundle.
- `ITSAppUsesNonExemptEncryption` is false. On iPadOS, `LSSupportsOpeningDocumentsInPlace` is set.
- None of the Debug launch hooks are in the binary.

### Mac App Store

1. Create the app record in App Store Connect with bundle ID `com.wirepath.WirePath`.
2. Run `TEAM_ID=… UPLOAD=1 scripts/release.sh mac-appstore`. Xcode's automatic signing creates the Apple Distribution
   certificate and the Mac App Store provisioning profile when needed (`-allowProvisioningUpdates`).
3. In App Store Connect, pick the build and complete the metadata.

### Developer ID (outside the App Store)

1. One-time setup: `xcrun notarytool store-credentials wirepath --apple-id … --team-id …`. It asks for an
   app-specific password, which is stored in the keychain.
2. Run `TEAM_ID=… NOTARY_PROFILE=wirepath scripts/release.sh mac-developer-id`. It archives, exports with Developer ID
   Application, submits to the notary service, staples the ticket, checks Gatekeeper (`spctl`) and writes
   `build/Release/WirePath-<version>.zip`.

The Developer ID build is sandboxed too, so it behaves exactly like the App Store build.

### iPadOS: TestFlight and App Store

1. Create the iPad app record (same bundle ID, or a separate one if the Mac and iPad apps are sold separately).
2. Run `TEAM_ID=… UPLOAD=1 BUILD_NUMBER=<next> scripts/release.sh ipad-appstore`.
3. Once processing finishes, the build appears in TestFlight for internal testers. External testing needs a Beta App
   Review.

## Before a release

1. Run `scripts/test.sh`: core and UI packages on macOS and on the iPad simulator, then the macOS and iPadOS UI
   tests. The macOS UI tests need an unlocked screen.
2. Run `scripts/check-localization.py …`, which must report no missing Spanish strings (see `scripts/localize.sh`).
3. Run `scripts/release.sh check`.
4. Bump `VERSION` / `BUILD` in `scripts/generate-xcodeproj.py` and regenerate the project.
5. Review `docs/dependencies.md`. WirePath uses Apple frameworks only, and no licence-restricted codec is included.
6. Take screenshots with `scripts/snapshot.sh` (macOS) and `scripts/ipad-snapshot.sh` (iPad) at the store sizes, in
   English and Spanish (`WIREPATH_LANGUAGE=es`).

App Review notes worth including: WirePath analyzes capture files the user already has, it does not capture network
traffic, and it needs no account or network access. `Fixtures/sip-call.pcap` makes a good sample capture for the
reviewer.
