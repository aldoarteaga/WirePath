# WirePath

WirePath is a native, offline analyzer for packet captures (`.pcap`, `.pcapng`, `.cap`, `.pcap.gz`). It runs on **macOS (Apple Silicon)** and **iPadOS**, is written in Swift and SwiftUI with Apple frameworks only, and focuses on VoIP: it rebuilds SIP calls, links them to their SDP and RTP media, measures quality, and lets you inspect every packet.

WirePath **never captures traffic**. It has no packet capture, VPN, packet tunnel or Network Extension code and no network entitlements. It only reads files the user opens.

![Overview of a capture: calls, quality metrics and problems that need attention](docs/screenshots/overview.png)

| Call investigation | Packets |
| --- | --- |
| ![SIP ladder and RTP analysis of one call](docs/screenshots/call-investigation.png) | ![Packet list, protocol tree and bytes](docs/screenshots/packets.png) |
| **WebRTC** | **Light appearance** |
| ![ICE session with its selected candidate pair, DTLS and media](docs/screenshots/webrtc.png) | ![Overview in the light appearance](docs/screenshots/overview-light.png) |

The screenshots are rendered by the app itself (`scripts/snapshot.sh`) from simulated captures, so every address and name in them is fictional.

## Try it

WirePath is in early testing, and feedback from people who work with VoIP captures is very welcome.

**macOS (Apple Silicon, macOS 15 or later)**

1. Download `WirePath-<version>-macOS.zip` from the [latest release](https://github.com/aldoarteaga/WirePath/releases/latest).
2. Unzip it and move `WirePath.app` to /Applications.
3. The build is ad-hoc signed and not notarized, so macOS blocks the first launch. Open System Settings ▸ Privacy & Security and click **Open Anyway**, or clear the quarantine flag:

   ```bash
   xattr -dr com.apple.quarantine /Applications/WirePath.app
   ```

**iPadOS 18:** there is no public build yet. You can build the `WirePathiPad` scheme from source with Xcode (see [Build, run, test](#build-run-test)).

**No capture at hand?** The small captures in [`Fixtures/`](Fixtures) are simulated and open in the app: `sip-problems.pcap` (failed calls and SIP errors), `rtp-call.pcap` (a call with audio), `webrtc-session.pcap` (ICE, TURN and DTLS).

**Your captures stay on your Mac.** The app runs in the App Sandbox with no network access, so nothing you open is uploaded anywhere.

**Reporting a problem:** [open an issue](https://github.com/aldoarteaga/WirePath/issues/new) with what you did and what you expected. For a crash, attach the report from `~/Library/Logs/DiagnosticReports/WirePath-*.ips`. A capture that reproduces the problem helps most, but only share one you are allowed to, with any private addresses, numbers or credentials removed.

## Build, run, test

Requirements: Xcode 27 (Swift 6.4 toolchain) on an Apple Silicon Mac. Deployment targets: macOS 15 (arm64) and iPadOS 18.

```bash
python3 scripts/generate-xcodeproj.py         # creates WirePath.xcodeproj (generated, not committed)
open WirePath.xcodeproj                      # schemes: WirePathMac, WirePathiPad
scripts/build-app.sh                         # → build/WirePath.app (Release, sandboxed, arm64)
scripts/test.sh                              # every suite: packages (macOS + iPad simulator) and UI tests
scripts/test.sh --quick                      # packages only
scripts/release.sh check                     # Release builds + sandbox/entitlement/privacy checks (docs/release.md)
```

Distribution (Mac App Store, Developer ID with notarization, iPadOS App Store and TestFlight) goes through `scripts/release.sh` with your team ID; see `docs/release.md`.

The project file is generated: edit `scripts/generate-xcodeproj.py` and re-run it, not `project.pbxproj`. Source folders are synchronized, so adding a Swift file needs no project change.

Developer tools (from `Packages/WirePathCore`):

```bash
swift run -c release wpsamplegen ../../Samples               # realistic simulated office/trunk captures
swift run wpsamplegen --fixtures ../../Fixtures             # regenerate the test fixtures
swift run -c release wpcli capture.pcap --calls --streams --findings --filter "rtp.seq_gap"
swift run -c release wpbench all /tmp/bench --packets 1000000,5000000   # engine benchmarks (docs/performance.md)
scripts/snapshot.sh out/ Fixtures/rtp-call.pcap dark "overview,frame:2"      # render macOS screens to PNG
scripts/ipad-snapshot.sh out.png Fixtures/rtp-call.pcap overview "iPad mini (A17 Pro)"
```

## Repository layout

```
WirePath.xcodeproj            generated (scripts/generate-xcodeproj.py)
Packages/
  WirePathCore/               all analysis logic — no SwiftUI, no platform APIs; tests, fixtures, CLI tools
  WirePathUI/                 SwiftUI screens, view models and components shared by macOS and iPadOS
WirePathMac/                  macOS app target (window chrome, menus, Finder/Dock integration)
WirePathiPad/                 iPadOS app target (NavigationSplitView root, Files / Open In)
WirePathTests/                XCUITest suites for macOS and iPadOS
Fixtures/                     small purposeful captures used by tests (see Fixtures/README.md)
design/                       the visual source of truth (design canvas); see below
docs/                         architecture and engine documentation
scripts/                      project generator, build/test/snapshot helpers
```

## Design

The UI implements the canvas in `design/` (`Main`, `Investigation`, `Packets` and `Interactions` boards, dark and light). `WirePath — macOS VoIP PCAP Analyzer.html` is a bundled export of that same canvas. Design tokens (colours for both appearances, type, spacing, icons) live in `Packages/WirePathUI/Sources/WirePathUI/Theme`. iPadOS keeps the same identity and adapts layouts to the width actually available (iPad mini portrait through iPad Pro landscape, Split View, Stage Manager).

## Status

Implemented and tested:

- **Documents.** Open from Finder, Open…, drag & drop, Open Recent and the Dock on macOS; from Files, iCloud Drive, USB storage, AirDrop and Open In on iPadOS. Security-scoped bookmarks keep captures readable after relaunch (sandboxed Release builds included). Each capture is an independent analysis with its own state, persisted in the analysis library.
- **Packet engine.** Memory-mapped pcap/pcapng readers with full validation (interfaces, statistics, comments, snapshot length, damaged blocks), a 64-byte-per-packet index with flow IDs, lazy decoding, a virtualized packet list, protocol tree and hex/bits view. Hardened against untrusted input with seeded fuzzing.
- **Performance.** Measured with `wpbench` on an M4 Pro: a 2.6 GB, 12-million-packet capture indexes in 6–9 s (1.4–1.9 M packets/s) with a 340–380 MB memory peak. Display filters scan 30–100 M packets/s, and a list row decodes in under 3 µs. While a capture is analyzed, its packets, flows, protocols, SIP messages and RTP streams are counted live. Methods, results and the fixes the benchmarks drove are in [docs/performance.md](docs/performance.md).
- **Protocols.** A modular dissector registry: Ethernet/802.3, 802.1Q/QinQ, MPLS, PPPoE, Linux SLL/SLL2, loopback, LLDP, ARP, IPv4/IPv6 (extension headers, fragment reassembly), ICMP/ICMPv6 (neighbor discovery), UDP, TCP (options; stream reassembly for SIP), DNS/mDNS (SRV, NAPTR…), DHCP (VoIP provisioning options), NTP, HTTP/1.x, TLS handshake metadata (SNI, ALPN, versions, cipher suites; no decryption), STUN/ICE, TURN (incl. ChannelData), RTCP compound packets.
- **Diagnostics.** A Diagnostics screen lists every problem with its protocol, severity and packets: failed calls, one-way audio and no media, poor quality, loss bursts, jitter spikes, SIP transaction timeouts (Timer B/F), missing ACKs, authentication and registration failures, 4xx/5xx/6xx responses, SIP retransmissions, and unanswered, retransmitting or reset TCP connections. "Show Packets" opens exactly the packets involved.
- **VoIP.** SIP (UDP and TCP, compact headers, transactions, dialogs, B2BUA leg merging), SDP, RTP (RFC 3550 loss, jitter, reordering, duplicates, loss bursts, SSRC changes, packet rate, payload and wire bitrate), ITU-T G.107 E-model MOS estimates, findings, call investigation with SIP ladder and charts.
- **Audio.** Streams are reconstructed from RTP (ordered by sequence number, placed by timestamp, losses concealed, silence suppression filled with the comfort noise the sender announced, DTMF keys rendered as tones) and played with AVAudioEngine, the caller on the left and the callee on the right, with seek and per-stream mute. Calls and streams export to WAV. Decoders: G.711, G.722 and L16 built in; Opus and iLBC through the system codecs. Licence-restricted codecs (G.729, AMR…) and encrypted SRTP are clearly reported as not playable.
- **Flows & TCP.** Every IP packet belongs to a bidirectional flow (5-tuple). TCP stream analysis flags retransmissions, out-of-order data, segments missing from the capture, duplicate ACKs, zero windows, keep-alives and resets, and records handshake, initial RTT and termination per connection. The Flows screen lists them. "Follow Flow" in the packet details shows one flow's packets.
- **Statistics.** Traffic over time by protocol (packets or bits per second), protocol distribution, packet sizes, peak and mean rates, top endpoints and conversations, and TCP/UDP totals. The figures match `tshark -z io,stat` and `-z plen,tree`.
- **Search.** Find packets by IP, port, packet number, Call-ID/SIP URI, SSRC, protocol or payload text, off the main thread, with match navigation.
- **Filters.** Wireshark-style display filters (see below). Exports: filtered pcap and an HTML analysis report.

- **RTCP.** Sender and Receiver Reports linked to their RTP streams: receiver-reported loss and jitter, round-trip time from matched SR/RR pairs, SDES CNAMEs, and endpoint-reported quality from RTCP XR (MOS-LQ, R factor), with diagnostics for long round trips and low reported MOS.
- **WebRTC.** ICE sessions rebuilt from STUN connectivity checks (grouped by ufrag pair): every candidate pair with its checks, answers, RTT, nomination and state; the selected pair; candidates per peer typed Host / Server Reflexive / Peer Reflexive / Relay (from SDP, STUN servers, TURN allocations and the checks themselves); STUN server bindings; TURN allocations (challenges, permissions, channels, ChannelData and Send/Data relaying, including checks and DTLS relayed inside them); the DTLS-SRTP handshake and the RTP carried on the selected pair. The WebRTC screen shows Peer A → candidate pair → Peer B, then ICE → DTLS → Media. Diagnostics cover failed ICE, failing candidate pairs, STUN errors and unreachable STUN servers, TURN allocation failures, relayed media, and DTLS or media missing after ICE.

- **Languages.** English and Spanish, with plural agreement, following the system language. Findings, headlines and call states are written into the analysis in the language it was made in; opening an analysis after changing language re-analyzes it when the capture is still reachable. Packet detail trees keep protocol field names in English, as Wireshark does.

Not implemented yet (planned phases, see `docs/architecture.md`): CSV/JSON export. The UI does not show these features until they exist.

## Display filter

- **Protocol names:** `sip`, `sdp`, `rtp`, `rtcp`, `udp`, `tcp`, `ip`, `ipv6`, `arp`, `icmp`, `icmpv6`, `dns`, `dhcp`, `ntp`, `stun` (includes TURN), `turn`, `http`, `tls`, `dtls`.
- **WebRTC:** `webrtc` (STUN, TURN, DTLS and every packet on an ICE session's flows, media included) and `webrtc.session == N` (as numbered in the WebRTC screen).
- **Addresses:** `ip.addr`, `ip.src` and `ip.dst`, with IPv4 CIDR support.
- **Ports:** `udp.port`, `tcp.port` and `port`.
- **Frame:** `frame.number`, `frame.len` and `frame.time_relative`.
- **SIP:** `sip.status`, `sip.method`, `sip.call_id` and `sip.error`.
- **RTP:** `rtp.ssrc`, `rtp.pt`, `rtp.seq_gap`, `rtp.duplicate`, `rtp.out_of_order` and `rtp.ssrc_change`.
- **TCP analysis:** `tcp.analysis.flags`, `tcp.analysis.retransmission`, `.out_of_order`, `.lost_segment`, `.duplicate_ack`, `.zero_window`, `.keep_alive`, `.window_update`, `.ack_lost_segment`; flags `tcp.flags.syn/ack/fin/reset/push`.
- **Sets:** `frame.number in {3 4 9}` (any comparable field).
- **Grouping:** `call == N`, `stream == N`, `flow == N` (as numbered in the app), `tcp.stream == N` / `udp.stream == N` (0-based per transport, as in Wireshark), and `issues`.
- **Operators:** `and`, `or`, `not` and parentheses, e.g. `rtp.seq_gap or sip.status >= 400`. Filters are limited to 1,000 tokens and 64 nesting levels.

## Accuracy rules

- Every number is computed from the packets in the capture; nothing is estimated without saying so.
- Jitter follows RFC 3550 in arrival order; on streams without reordering it matches `tshark -z rtp,streams`.
- Loss is expected minus unique packets received, so duplicates never hide loss.
- MOS is an E-model estimate from the codec and measured loss/burstiness; one-way delay cannot be observed from a single capture point, so Id is 0. Codecs without published E-model parameters (Opus, G.722) show "—".

## Dependencies

None beyond Apple's SDKs — see `docs/dependencies.md`.

## License

MIT — see `LICENSE`.
