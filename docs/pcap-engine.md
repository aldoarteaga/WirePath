# PCAP engine

Code: `Packages/WirePathCore/Sources/WirePathCore/{FileIO,PCAP,PCAPNG,Packets,Flows}`.

## Reading a file

`CaptureFile` memory-maps the capture read-only (`mmap`, `MADV_SEQUENTIAL` while indexing, `MADV_RANDOM` for the
inspector). It holds security-scoped access to its URL for as long as the mapping lives. `CaptureFileFormat.detect`
recognizes pcap (µs/ns, both byte orders), pcapng and gzip. It rejects zstd/xz with a clear message.

gzip captures (`.pcap.gz`, multi-member) are expanded once into the analysis folder with the Compression framework.
DEFLATE cannot be read at random offsets, and the inspector needs random access.

## pcap

- The header gives the magic (byte order, µs/ns), version, snapshot length and link type. The link-type field's
  FCS bits (bit 28, and the length in bits 29–31) are reported as `fcsLength`.
- Records are validated against the bytes remaining. A record longer than 64 MiB, or one that runs past the end of
  the file, ends reading. The remaining packets are kept and the damage is reported (`truncatedAtEnd`, plus a
  warning).
- Damage before the first packet throws `CaptureError.corrupt`. There is nothing to analyze.
- A packet longer than the snapshot length produces a warning (once).

## pcapng

Supported blocks: Section Header (byte order, version, `shb_hardware/os/userappl`, comments), Interface Description
(link type, snapshot length, `if_name`, `if_description`, `if_tsresol` decimal/binary, `if_tsoffset`), Enhanced
Packet (with `opt_comment`), Simple Packet, Obsolete Packet and Interface Statistics (`isb_ifrecv`, `isb_ifdrop`,
`isb_osdrop`). Other blocks (name resolution, decryption secrets, custom) are skipped by length.

Validation for every block:
- The block length is ≥ 12, a multiple of 4, and ≤ the bytes remaining.
- The trailing length field must equal the leading one.
- Options are walked within the block. Each value must fit before the trailer, and walking stops at
  `opt_endofopt` or at the first malformed option.
- The EPB captured length must fit inside its block.
- Multiple sections reset the per-section interface table. Interface IDs in frames are global across sections.

Untrusted values are bounded:
- `if_tsresol` exponents are clamped (decimal ≤ 127, binary ≤ 63). Timestamps and `if_tsoffset` use wrapping
  arithmetic, so no value in the file can make the reader trap.
- At most 4,096 interfaces, 10,000 packet comments, 64 section comments, 4 KiB per text value and 100 warnings are
  kept.

## Packet index

`packets.idx` = 16-byte header (`"WPIDX004"`, record count) + one 64-byte `PacketIndexRecord` per packet:

| Field | Meaning |
|---|---|
| fileOffset, capturedLength, originalLength | where the bytes are in the capture |
| timestampNanos, linkType, interfaceID | frame metadata |
| sourceAddress, destinationAddress | indices into the address table (`addresses.json`) |
| sourcePort, destinationPort | transport ports (0 when none) |
| protocolRaw, flagsRaw | classification and per-packet flags (RTP gap/duplicate/reorder, SIP error, malformed…) |
| callIndex, streamIndex | links to `AnalysisResult.calls/streams` (−1 = none) |
| sipCode, aux | SIP status/method; SIP message index or RTP packets lost before this one |
| flowIndex | bidirectional flow (−1 = none) |
| analysisFlagsRaw | TCP analysis flags: retransmission, out-of-order, previous segment not captured, dup ACK, zero window, keep-alive, ACKed unseen segment, window update, reset |
| ipProtocolRaw, tcpFlags | IP protocol number and TCP header flags (exact `udp`/`tcp`/`tcp.flags.*` filters) |

The magic changes whenever the layout does, and analyses from an older engine are re-analyzed automatically
(`AnalysisEngine.version`). When the index is mapped again:
- the stored count is clamped to what the file holds;
- positions outside the index read as empty records;
- `PacketStore` drops call/stream links that point outside the result and clamps file offsets to the capture.

## Packet model

`PacketStore` keeps the three parts of a packet apart:

- `packet(at:)` returns metadata only, from the index (`Packet`, `PacketMetadata`).
- `packetBytes(at:)` returns the captured bytes, read from the mapped capture on demand.
- `decodedProtocols(at:)` returns the protocol tree for one packet (at most the first 256 KiB).

Decode problems (`DecodeProblem`: link header, IPv4/IPv6 header or length, UDP/TCP header) are carried to the
inspector, which shows "Packet #N could not be fully decoded. Reason: … The remaining capture can still be analyzed."

## Flows

`FlowTable` assigns every IP packet to a direction-free 5-tuple flow (protocols without ports use one flow per
address pair). It records the initiator (first sender seen), per-direction packets and bytes, the time span and the
most specific protocol seen. Non-first IP fragments have no ports and are left out. The table stops creating flows
after 2,000,000, with a warning. Flows are saved to `flows.json` and loaded only when needed.

## TCP analysis

`TCPAnalyzer` follows each TCP flow's sequence and acknowledgment numbers during the sequential pass, using the
same heuristics as Wireshark:
- A sequence jump flags "previous segment not captured" and records the gap (at most 16 per direction).
- Data filling a gap within max(3 ms, initial RTT) of the latest segment is "out-of-order"; later is a
  retransmission. Data repeating bytes that were never missing is a retransmission, and so is a repeated SYN.
- A pure ACK repeating the previous ACK and window is a "duplicate ACK"; with a new window it is a "window update".
- Also flagged: zero windows, keep-alives, ACKs of unseen data and resets.

Per connection, `TCPConnectionStats` records the handshake (complete, SYN/ACK only, unanswered, before the
capture), the initial RTT, the termination (FIN both ways, one way, reset by either side, open), ISNs (for relative
sequence numbers in the inspector), payload bytes and the counters. At most 500,000 connections are followed.
`ipv4-tcp.pcap` is flagged packet for packet as tshark flags it.

## Conversations and search

- `Conversations.ip(flows)` and `Conversations.endpoints(flows)` aggregate flows into IP conversations and per-address
  traffic without reading packets again.
- `PacketSearch` interprets a query in every way that fits: packet number, port, IP address, SSRC (decimal or `0x…`),
  protocol name, SIP Call-ID/URI/user, and payload text (ASCII, case-insensitive, first 16 KiB of each packet). It
  scans the mapped index off the main actor, can be cancelled, reports progress, and returns each hit with the reason
  it matched (at most 100,000 hits).

## Robustness testing

- `UntrustedCaptureTests` covers crafted timestamp parameters, mismatched block lengths, oversized declared lengths,
  interface floods, truncated headers, random garbage, and seeded mutation fuzzing of reader + decoder + dissector
  (plus the full pipeline on a sample). The fuzzer runs in debug builds, where every buffer access is
  bounds-checked, so an out-of-range read fails the test.
- Longer campaigns: `WIREPATH_FUZZ_ITERATIONS=2000 WIREPATH_FUZZ_SEED=7 swift test --filter mutatedCapturesNeverCrash`.
- `CraftedProtocolTests` and `BoundedStateTests` pin every issue found by the parser audits: negative
  Content-Length, NaN ptime, the TCP Int32.min negation, RTP timestamps near the Int64 limits, quadratic SIP/TCP
  framing, filter nesting, fragment floods, damaged index and result files.
- Fixtures (`Fixtures/`) are cross-checked with tshark.

## Removable, network and iCloud storage

A memory-mapped file that disappears (a USB drive unplugged, a network share dropped, an iCloud file evicted) turns
the next page fault into SIGBUS, which no Swift code can recover from. `LocalCopy.isNeeded(for:)` detects captures on
non-internal, removable/ejectable, non-local or ubiquitous volumes. The engine first copies them into the analysis
folder in 4 MiB `read(2)` chunks, which fail with an ordinary error if the volume goes away, and then maps the copy
(the "Copying" progress phase). If there is not enough free space, it logs this and reads the file in place.
`AnalysisEngine.analyze(localCopy:)` accepts `.automatic` (default), `.always` or `.never`.
