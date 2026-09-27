# Architecture

WirePath analyzes packet captures offline on macOS (Apple Silicon) and iPadOS. One analysis engine serves both
platforms. The only platform-specific code is what each OS needs for windows, documents and input.

## Layers

```
┌────────────── WirePathMac ─────────────┐ ┌──────────── WirePathiPad ───────────┐
│ App, window chrome, menus, Finder/Dock │ │ App, NavigationSplitView root,      │
│ open events, snapshot tool (Debug)     │ │ Files / Open In (onOpenURL)         │
└──────────────────┬─────────────────────┘ └──────────────────┬───────────────────┘
                   └──────────────┬──────────────────────────┘
                     ┌────────────▼────────────┐
                     │ WirePathUI (SwiftUI)    │  screens, components, theme,
                     │ View → ViewModel        │  view models (@Observable, @MainActor)
                     └────────────┬────────────┘
                     ┌────────────▼────────────┐
                     │ WirePathCore            │  Foundation + Compression + OSLog only:
                     │ engine, models, stores  │  no SwiftUI, AppKit or UIKit
                     └─────────────────────────┘
```

- **WirePathCore** (`Packages/WirePathCore/Sources/WirePathCore`) holds all analysis logic and models. It builds for
  macOS and iOS, and its 70-odd tests run on both (`swift test`, and `xcodebuild test -scheme WirePathCore-Package`
  on an iPad simulator).
- **WirePathUI** (`Packages/WirePathUI`) holds every screen and view model, shared by both apps. Platform
  differences are small `#if os(...)` islands: the table view backing the packet list, clipboard, keyboard
  shortcuts. Screens adapt to the measured width (`LayoutWidth`), not to the device model.
- **WirePathMac / WirePathiPad** are thin app targets.
- **WirePathFixtures** (test support, not shipped) is a deterministic SIP/RTP network simulator plus pcap/pcapng
  writers used by tests, `wpsamplegen` and the fixture catalog.

Views never parse captures. They call view models, which call the core: `View → ViewModel → WirePathCore`.

## Core modules (folders of WirePathCore)

| Folder | Responsibility |
|---|---|
| `FileIO` | Memory-mapped capture files, security-scoped access and bookmarks, gzip expansion |
| `PCAP`, `PCAPNG` | Validating readers producing `CapturedFrame`s (see pcap-engine.md) |
| `Packets` | Hot-path header decoder, IP/TCP reassembly, the packet index, `PacketStore` (random access), packet model |
| `Protocols` | Dissector registry: one type per protocol (link, network, transport, application), protocol tree |
| `Flows` | Flow table (every IP packet gets a bidirectional 5-tuple flow), TCP analyzer, IP conversations and endpoints |
| `Search` | Packet search: IP, port, packet number, Call-ID/SIP URI, SSRC, protocol, payload text |
| `Statistics` | `CaptureStatistics`: traffic per time bin (by protocol), packet sizes, peak and mean rates; transport totals |
| `SIP`, `SDP` | SIP parser/framer/transactions/sessions, SDP parser |
| `RTP` | RTP header, per-SSRC analyzers (RFC 3550): loss, jitter, reordering, duplicates, packet rate, payload and wire bitrate; codec catalog |
| `RTCP` | Sender/Receiver Reports, report blocks, SDES CNAME, XR VoIP metrics (RFC 3611); round trip from matched SR/RR (LSR/DLSR); per-stream RTCP summaries and RTCP diagnostics |
| `Metrics` | ITU-T G.107 E-model |
| `Sessions` | Call correlation (SIP sessions → calls, B2BUA legs, SDP ↔ RTP), summaries |
| `Diagnostics` | Findings backed by measurements, each with its protocol, packet references and a display filter: call outcomes and media quality (`FindingDetector`), SIP signalling (`SIPDiagnostics`: timeouts, missing ACKs, authentication and registration failures, error responses, retransmissions) and TCP (`TCPDiagnostics`) |
| `Filters` | Display-filter lexer/parser/evaluator |
| `Analysis` | Pipeline orchestration and the persisted `AnalysisResult` |
| `Persistence` | Analysis library on disk |
| `Logging` | OSLog categories `wirepath.core/pcap/protocol/sip/rtp/webrtc/ui` |
| `STUN` | STUN/TURN message parser (RFC 8489/8656 attributes used by ICE and TURN), DTLS record detection |
| `WebRTC` | `WebRTCTracker` (STUN transactions by ID, ICE sessions by ufrag pair, candidate pairs, TURN allocations, relayed checks, DTLS), the persisted `WebRTCAnalysis` and `WebRTCDiagnostics` |
| `Audio` | `AudioDecoder` protocol and `AudioCodecRegistry` (extensible); G.711, G.722, L16 decoders in Swift, Opus and iLBC through the system codecs; `AudioReconstructor` (RTP order, timestamp placement, loss concealment, comfort noise, DTMF tones); `AudioEngine` (AVAudioEngine playback, one panned player per stream, chunked scheduling, offline rendering); WAV export |

## Data flow

```
File ──mmap──▶ CaptureReader ──frames──▶ FrameDecoding (parallel, stateless)
                                            │ DecodedFrame (headers, SIP/UDP message, RTP header)
                                            ▼
                                   CaptureAnalyzer (sequential, stateful)
             IP defragmentation · TCP → SIP framing · SIP transactions · RTP analyzers · flow table
                                            │
            packets.idx (64 B/packet) ◀─────┤────▶ CallCorrelator → FindingDetector → AnalysisResult
                                            ▼
                               AnalysisLibrary (result.wpresult, flows.json, addresses.json, sip-messages.json)
                                            │
             PacketStore (index + capture mmap) ◀── Packet Inspector, audio, exports
```

Relationships between objects are explicit indices, so the engine can navigate
Packet → Flow → SIP message → dialog/session → call → SDP announcement → RTP stream:
`PacketIndexRecord.flowIndex/callIndex/streamIndex/aux`, `CallRecord.sessionIndices/messageIndices/streamIndices`,
`RTPStreamRecord.callIndex`, and `PacketStore.flow(of:)`, `call(of:)`, `stream(of:)`, `sipMessage(of:)`.
Saved results are checked on load (`AnalysisResult.isStructurallyValid`) before any screen indexes them.

## Security model

- WirePath captures no traffic and has no network entitlements. It reads only files the user opens.
- Every capture is untrusted. Readers and parsers check lengths against the bytes actually present, clamp
  file-declared values, use overflow-safe arithmetic for timestamps, and keep file-driven state bounded (flows,
  streams, fragments, TCP framers, SDP sections, comments, interfaces). The byte helpers return 0 outside their
  buffer rather than reading out of bounds. Seeded mutation fuzzing runs in the test suite (see pcap-engine.md).
- Logs never include packet contents or file paths. They carry counts, versions and error codes.
- macOS Release builds run in the App Sandbox with `files.user-selected.read-write` and `files.bookmarks.app-scope`
  only, with the hardened runtime and no `get-task-allow`. Debug builds are unsandboxed so UI tests and the snapshot
  tool can read fixtures. The `WIREPATH_*` launch-environment hooks are compiled into Debug builds only (not even
  their names ship). Both apps carry a privacy manifest (no tracking, no data collected). `scripts/release.sh check`
  verifies all of this on the built products; see release.md.

## Decision records

### ADR-1: An analysis library instead of `DocumentGroup`

Captures open as *analyses* in the design's sidebar, not as `DocumentGroup` windows.
- `FileDocument`/`ReferenceFileDocument` read through `FileWrapper`, which loads the file into memory. That
  contradicts the large-file requirement.
- On iPadOS, `DocumentGroup` puts the system document browser in front of the app, replacing WirePath's design.
- Captures are read-only inputs. What the user keeps is the derived analysis (index, results).

The document requirements are still met. `.pcap`/`.pcapng` are registered through UTTypes (Finder, Files, Open In).
Opening works through Open…, drag & drop, Open Recent (bookmarks), the Dock and `onOpenURL`, and multiple windows
are supported on both platforms. Each analysis has independent state (document, filters, selection, inspector
models), and nothing is shared between captures.

### ADR-2: Memory mapping and a fixed-size packet index

Captures are memory-mapped and never copied, except for gzip, which must be expanded for random access. A 64-byte
record per packet is written once during analysis and memory-mapped by the Packet Inspector, so listing, filtering
and scrolling millions of packets never decodes payloads (see memory-management.md).

### ADR-3: Parallel stateless decode, sequential stateful ingest

Header decoding and SIP/RTP detection run in parallel over 32K-frame batches. Everything that depends on order
(reassembly, transactions, jitter) runs in one sequential pass. This keeps the analysis deterministic while using
every core (see concurrency.md).

### ADR-4: No third-party dependencies

Everything needed exists in Apple's SDKs or is small enough to implement and test here (see dependencies.md).

## Phases

| Phase | Scope | Status |
|---|---|---|
| 0 | Project foundation: Xcode project, macOS + iPadOS targets, packages, tests, CI | Done |
| 1 | Document system: UTTypes, pickers, Finder/Files, drag & drop, bookmarks, sandbox | Done |
| 2 | Packet engine: hardened readers, index with flows, lazy loading, list, details, hex | Done |
| 3 | Core protocols: modular dissector registry; link, network, transport, DNS/DHCP/NTP/HTTP/TLS/STUN/TURN/RTCP detail | Done |
| 4 | Flows & filters: TCP stream analysis, UDP flows/conversations, search | Done |
| 5 | Statistics: traffic graphs, protocol distribution, endpoints, rates (Swift Charts) | Done |
| 6 | SIP: dialogs, missing ACK, timeouts, auth problems, diagnostics with packet references | Done |
| 7 | RTP/RTCP: bitrate, pps, RTCP SR/RR and RTT | Done |
| 8 | WebRTC: STUN/TURN/ICE, candidate pairs, session reconstruction | Done |
| 9 | Audio: extensible decoders, stream reconstruction, AVAudioEngine playback | Done |
| 10 | Performance: large-capture benchmarks, memory, rendering | Done ([performance.md](performance.md)) |
| 11 | UX polish: accessibility, English/Spanish localization, states | Done |
| 12 | Release: signing, entitlements, privacy manifest, App Store/Developer ID/TestFlight (`docs/release.md`) | Done |
