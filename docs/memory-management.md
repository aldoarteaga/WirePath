# Memory management

WirePath must handle captures far larger than RAM on an iPad mini, so no full capture is ever loaded into memory.

## What stays on disk

| Data | Storage | In memory |
|---|---|---|
| Capture bytes | the original file (or a local copy for gzip / removable storage), memory-mapped | pages the kernel brings in on demand |
| Packet index | `packets.idx`, 64 B per packet, memory-mapped | pages of visible or filtered rows |
| Flows | `flows.json` | loaded when first asked for |
| SIP message texts | `sip-messages.json`, written as messages are parsed (secrets redacted) | loaded by the SIP views |
| Results | `result.wpresult`, a chunked archive (`ResultArchive`: a JSON head and JSON chunks of 4,096 records) | calls, streams, SIP records, findings (compact summaries) |

Rough sizes for 5 million packets: a 320 MB index file on disk, mapped lazily. During indexing, memory holds one
32K-frame batch plus the stateful analyzers. Measured peaks are in [performance.md](performance.md): 150–194 MB
for a 1.1 GB capture, 337–379 MB for 2.6 GB, and about 20 KB per call for SIP-heavy captures.

Results are saved and read in chunks because a single `JSONEncoder` document builds an intermediate tree about ten
times its size. For 170,000 SIP messages that is 2.5 GB, which an iPad would not survive. Chunked, memory stays near the
size of the result itself. Repeated SIP strings (Call-ID, URIs, tags, user agents) are interned while the capture is
read.

## Bounded state

Everything whose size a capture controls is capped:

| State | Bound |
|---|---|
| Flows | 2,000,000 (warning beyond) |
| TCP connections analyzed | 500,000 (warning beyond); 16 open sequence gaps per direction |
| Search hits | 100,000; payload text scanned in the first 16 KiB of each packet |
| Traffic statistics | 200,000 distinct seconds kept during ingest; persisted as at most 3,600 bins (wider bins for long captures) |
| RTP streams | 100,000 (warning beyond); SSRCs per flow: 16 without SDP, 256 with |
| RTP series | dense arrays during ingest (4 bytes per jitter bin, 8 per loss bin) grown only while the bin index stays below the packets seen; bins beyond (crafted timestamps) are kept sparsely; persisted as at most 20,000 bins, and at most 8× the occupied bins (wider bins for long streams) |
| Reconstructed audio | 32 M samples (64 MB) per stream |
| IP fragments | 1,024 incomplete datagrams (oldest evicted), 1,024 pieces, 64 KiB per datagram, 30 s timeout |
| SIP over TCP | 4,096 concurrent connections, 256 KiB per connection buffer, released on FIN/RST |
| SIP dialog tags | 64 per Call-ID |
| SDP | 32 media sections, 64 formats per section |
| pcapng metadata | 4,096 interfaces, 10,000 packet comments, 4 KiB per text |
| Packet details | first 256 KiB of a frame |
| Display filter | 1,000 tokens, 64 nesting levels |

## UI

- The packet list is a virtualized table: `NSTableView` on macOS, `UITableView` on iPadOS, with a shared
  Core Graphics row renderer. It never creates millions of SwiftUI views.
- Rows decode on demand, and selecting a packet decodes only that packet.
- Per-capture state (`AnalysisDocument`, inspector models) is released when an analysis is deleted.

## Planned (Phase 10)

- Benchmarks (`wpbench`) for indexing, packet lookup, filtering, flows, SIP and RTP, with numbers recorded here.
  Until then, no timing is promised.
- Memory measurements on iPad mini class hardware with multi-GB captures.
