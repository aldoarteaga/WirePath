# Dependencies

WirePath has **no third-party dependencies**. Everything it uses ships with Apple's SDKs, so there is nothing to
license, vendor or update beyond Xcode itself.

| Framework | Where | Why |
|---|---|---|
| Foundation | everywhere | files, data, URLs, bookmarks, JSON |
| Compression | WirePathCore, WirePathFixtures | gzip (DEFLATE) expansion of `.pcap.gz`; writing gzip test fixtures |
| OSLog | WirePathCore | logging categories `wirepath.*` |
| SwiftUI, Observation | WirePathUI, app targets | user interface and view models |
| Charts (Swift Charts) | WirePathUI | statistics charts (traffic over time, protocol distribution, packet sizes), with built-in chart accessibility |
| UniformTypeIdentifiers | WirePathUI, app targets | `.pcap` / `.pcapng` document types, pickers, drag & drop |
| AppKit | macOS target, WirePathUI (`#if os(macOS)`) | window chrome, `NSTableView` packet list, alerts, Finder integration |
| UIKit | iPadOS target, WirePathUI (`#if os(iOS)`) | `UITableView` packet list, clipboard |
| AVFAudio (AVFoundation) | WirePathCore (`Audio/`), WirePathUI | AVAudioEngine playback; the system Opus and iLBC decoders through `AVAudioConverter`; the audio session on iPadOS |
| ImageIO | WirePathUI | PNG encoding for snapshot and export |
| XCTest, Swift Testing | test targets only | UI tests, unit tests |

The repository scripts use Python 3 only at development time (`scripts/generate-xcodeproj.py`). It is not part of
the product.

## Policy for adding a dependency

A dependency can be added only after:

1. checking whether an Apple API already covers the need;
2. evaluating the license (it must allow closed-source commercial distribution on the App Store and with a
   Developer ID, which rules out GPL/LGPL/AGPL for linked code) and its redistribution requirements (notices,
   attribution);
3. recording it in this file: name, version, license, reason, and where it is used.

## Audio codecs

| Codec | Decoder | Licence |
|---|---|---|
| G.711 µ-law / A-law | built in (Swift) | ITU-T, royalty-free |
| G.722 | built in (Swift, bit-exact with the ITU algorithm; checked against ffmpeg) | ITU-T, royalty-free (patents expired) |
| L16 | built in | RFC 3551, no licence |
| Comfort noise (RFC 3389), DTMF events (RFC 4733) | built in | IETF, no licence |
| Opus | system decoder (AudioToolbox) | BSD, royalty-free |
| iLBC | system decoder (AudioToolbox) | royalty-free (RFC 3951 licence) |

Licence-restricted codecs (G.729, G.723.1, AMR, AMR-WB, G.722.1) are not included without a confirmed license, even
where the system could decode them. Their streams are analyzed (loss, jitter, MOS estimate) and the audio screens say
why they cannot be played. G.726, GSM and Speex are licence-free but not implemented yet; the registry
(`AudioCodecRegistry.register`) is the extension point for adding them. SRTP payloads are never decoded: the keys are
not in the capture, and SDES keys found in SDP are redacted from WirePath's stored copy of the SIP messages.
