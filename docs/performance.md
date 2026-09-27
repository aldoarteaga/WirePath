# Performance

WirePath is built for captures of millions of packets and several gigabytes: a memory-mapped reader, a 64-byte packet
index, parallel frame decoding, one sequential analysis pass with bounded state, lazily decoded packets and virtualized
lists. This page records the measurements behind that claim. There are no promises without a benchmark (spec §59).

## Running the benchmarks

`wpbench` (in `Packages/WirePathCore`) generates realistic captures and measures the stages the spec lists.

```bash
cd Packages/WirePathCore && swift build -c release
.build/release/wpbench generate /tmp/bench-5m.pcap --packets 5000000
.build/release/wpbench generate /tmp/sip-heavy.pcap --packets 1000000 --calls 3000 --call-seconds 0.3
.build/release/wpbench run /tmp/bench-5m.pcap --json results.json
.build/release/wpbench all /tmp/bench --packets 1000000,5000000,12000000
```

- **Generated traffic.** 200 concurrent G.711 calls (SIP signalling, RTP both ways, RTCP every 5 s, 0.2 % loss).
  Short HTTP-like TCP connections with handshake and teardown. DNS lookups. One-off UDP datagrams on new flows.
  The SIP-heavy variant has thousands of 0.3 s calls. That is about 170,000 SIP messages per million packets, like
  a SIP load test or a busy SBC.
- **Indexing** is the complete analysis the app runs on import: index, flows, TCP analysis, SIP, RTP, RTCP, WebRTC,
  statistics, correlation and diagnostics.
- **Stage rows** time each stage on its own over the same capture. The frames are decoded outside the timer.
- **Result save/load** is the analysis written to and read from the library, as the app does after import and
  when an analysis is opened.
- **Peak memory** is the process's physical footprint (what jetsam counts), sampled every 20 ms.
- Debug builds are 10–50× slower and are not representative. Results vary by about ±20 % between runs on a busy
  machine.

## Results

Apple M4 Pro, 12 cores, 24 GB, macOS 27, release build, 2026-09-27.

| Capture | Packets | Size | Indexing | Throughput | Peak memory | Result save / load |
|---|---:|---:|---:|---:|---:|---:|
| Mixed traffic | 1.0 M | 218 MB | 0.45–0.70 s | 1.4–2.2 M pkt/s | 48–56 MB | 0.06 s / 0.05 s |
| Mixed traffic | 5.0 M | 1.1 GB | 3.6–3.9 s | 1.3–1.4 M pkt/s | 150–194 MB | 0.23 s / 0.22 s |
| Mixed traffic | 12.0 M | 2.6 GB | 6.3–8.8 s | 1.4–1.9 M pkt/s | 337–379 MB | 0.56 s / 0.54 s |
| SIP-heavy (29,110 calls, 58,219 streams) | 1.0 M | 248 MB | 5.0–5.4 s | 185–206 k pkt/s | 697–710 MB | 3.5 s / 3.8 s |

Stages on the 12 M-packet capture (2.6 GB):

| Stage | Time | Throughput |
|---|---:|---:|
| Read + decode (parallel) | 0.84 s | 14.2 M packets/s (3.2 GB/s) |
| Flow reconstruction | 0.58 s | 20.7 M packets/s |
| SIP reconstruction | 0.18 s | 45 k messages/s |
| RTP analysis | 1.03 s | 11.4 M packets/s |
| Packet lookup, list row | 2.8 µs | per row decoded while scrolling |
| Packet lookup, details and protocol tree | 71 µs | per selected packet |
| Flows load (58,607 flows) | 0.36 s | 163 k flows/s |
| Filter `sip` | 0.15 s | 79 M packets/s |
| Filter `rtp.seq_gap` | 0.12 s | 98 M packets/s |
| Filter `ip.addr == …` | 0.31 s | 39 M packets/s |
| Filter `frame.len > 200 and (dns or tcp)` | 0.43 s | 28 M packets/s |

Memory for mixed traffic grows with flows and calls, not with packets. The per-packet state is the index on disk
and the memory-mapped capture, which the system pages in and out. Memory for SIP-heavy captures is about 20 KB per
call: SIP message records, the RTP streams and their series, the calls and the dialogs.

## What the benchmarks found and fixed

| Problem | Before | After |
|---|---:|---:|
| RTP streams were matched against every call (O(streams × calls)); they now use an index of announced SDP endpoints | 230 s | 9.5 s |
| B2BUA leg grouping scanned every INVITE of the last 5 s; it now uses an index of (called, calling, next hop) | — | −1.1 s |
| SIP header lookup and secret redaction used Foundation string comparison and search; they now use ASCII byte scans | 9.5 s | 6.6 s |
| SDP was parsed in the sequential pass; it is now parsed with the SIP message in parallel decoding. The SIP texts writer copies unescaped runs | 6.3 s | 5.0 s |
| Stored SIP message texts were kept in memory until the end; they are now streamed to `sip-messages.json` | 897 MB peak | 703 MB peak |
| Repeated SIP strings (Call-ID, URIs, tags, user agents) are interned per capture | 839 k strings | — |
| RTP jitter/loss bins were dictionaries of 40–80 bytes per bin; they are now dense arrays of 4–8 bytes (sparse only for out-of-range bins from crafted timestamps) | 377 MB | 337 MB (12 M) |
| Decoded batches were concatenated into another copy | 8.3 s | 6.4 s (12 M) |
| Results were saved as one `JSONEncoder` document, whose intermediate tree is about 10× the JSON; they are now saved as a chunked archive (`ResultArchive`) | 2.57 GB save, 2.37 GB load | 480 MB, 706 MB |
| The capture timeline drew every call in one canvas (≈750,000 pt tall for 29 k calls) and a label per call; it now uses lazy rows | — | constant |

## Where the time goes

- **Mixed traffic.** Most of the time is the sequential pass: index writing, flow table, TCP analysis, RTP and
  statistics. Parallel decoding is not the limit (3.2 GB/s).
- **SIP-heavy.** SIP parsing is the main cost: about 23 µs per message, spread over the decoding cores. The
  sequential SIP tracker, correlation and diagnostics follow. Saving and loading a 260 MB result takes 3.5 s each way.

## Limits that keep memory bounded

These limits are documented where they are enforced:
- 2 M flows, 500 k TCP connections, 100 k RTP streams.
- 100 k RTCP reports; 100 k STUN transactions and 10 k ICE sessions.
- 3,600 statistics bins; 20,000 series bins per stream.
- 64 MB of reconstructed audio per stream.

A warning is added to the capture summary when a limit is reached.
