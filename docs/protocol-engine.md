# Protocol engine

Code: `Packages/WirePathCore/Sources/WirePathCore/{Packets,Protocols,SIP,SDP,RTP,Analysis}`.

Protocols are handled in three places, each with a different cost profile.

## 1. Hot-path decoder (`PacketDecoder`)

It runs once per packet during indexing, in parallel, and allocates nothing. It extracts only what indexing and
flows need:

- **Link layer:** Ethernet II, 802.1Q/802.1ad/QinQ tags, MPLS label stacks, PPPoE sessions, Linux SLL/SLL2, BSD
  and OpenBSD loopback, raw IPv4/IPv6.
- **Network layer:** IPv4 (options, fragments, TSO zero length), IPv6 (hop-by-hop, routing, destination options,
  AH, fragment headers; at most 8 extension headers), ARP (classified only).
- **Transport layer:** UDP and TCP ports, sequence, flags, and payload bounds.

Every offset is checked against the captured bytes. The first problem found is recorded as a `DecodeProblem`, and
the headers decoded before it stay usable.

## 2. Stateless application detection (`FrameDecoding`)

Per packet, in parallel:
- SIP over UDP is detected and parsed.
- RTP and RTCP headers are recognized, excluding well-known non-RTP ports.
- DNS, DHCP and NTP are classified by port; STUN/TURN (magic cookie, or ChannelData on the TURN ports), DTLS
  (RFC 7983 record header) and TLS by content, so they are found on the random ports WebRTC uses.

The output (`DecodedFrame`) is handed to the sequential stage.

## 3. Stateful ingest (`CaptureAnalyzer`)

A single pass, in capture order:
- IPv4/IPv6 defragmentation (`IPFragmentReassembler`, bounded);
- TCP stream reassembly for SIP (`TCPStreamAssembler` + `SIPStreamFramer`, linear and bounded);
- SIP transactions and sessions (`SIPTracker`);
- SDP announcements;
- per-SSRC RTP analysis (`RTPTracker` / `RTPStreamAnalyzer`, RFC 3550);
- STUN transactions, ICE connectivity checks, TURN allocations and DTLS handshakes (`WebRTCTracker`);
- flow assignment (`FlowTable`).

Correlation into calls and findings runs once, after the pass.

### WebRTC reconstruction

- **Transactions.** STUN requests and responses are matched by the 96-bit transaction ID. Retransmissions extend the
  request (RTT is then not measured, per Karn's rule). A request is "no response" only when the capture ran on for
  2 s after the first copy and 1 s after the last; otherwise it is pending.
- **Sessions.** A Binding request whose USERNAME is `remote:local` is an ICE check. Checks are grouped into a session
  by the unordered ufrag pair. Peer A is the side that sent the first check. Each (sender, receiver) 5-tuple is a
  candidate pair: succeeded on any success response, failed when every check timed out or was refused. The selected
  pair is the latest nominated (USE-CANDIDATE) success. Without nomination it is the pair with the most successes.
  A session with no successful pair is failed once its pairs have all failed or it has been quiet for 5 s.
- **Candidate types.** Relay if the address is a TURN relayed address; otherwise the SDP `a=candidate` type, when
  unencrypted SIP carried the offer/answer; otherwise Server Reflexive if a STUN server or TURN server reported it
  as a mapped address; otherwise Host.
- **TURN.** An Allocate answered 401 without credentials (or 438) is a challenge; a 401 to an authenticated request
  means the credentials were rejected. CreatePermission, ChannelBind, Refresh (lifetime 0 = released), ChannelData
  and Send/Data indications are counted. STUN and DTLS carried inside ChannelData or a DATA attribute are analyzed
  as if sent from the relayed address to the peer.
- **DTLS and media.** DTLS on the selected pair is complete when both sides sent Change Cipher Spec or epoch-1
  records. RTP streams whose 5-tuple is the selected pair belong to the session.
- **Limits.** 100,000 transactions, 10,000 sessions (64 pairs each), 10,000 allocations and 10,000 DTLS flows.
  Only UDP is analyzed. Integrity values, nonces, TURN usernames and ICE passwords are never stored.

## 4. Dissector registry (`Protocols/`)

The Packet Inspector's protocol tree and the Info column for application protocols come from a registry of
independent dissectors. Each dissector conforms to one protocol:

```swift
public protocol ProtocolDissector: Sendable {
    var name: String { get }                       // "eth", "ip", "dns", "tls", also the tree's protocol name
    func accepts(_ layer: NextLayer, payload: UnsafeRawBufferPointer, context: DissectionContext) -> Bool
    func dissect(_ frame: UnsafeRawBufferPointer, range: Range<Int>, context: inout DissectionContext,
                 tree: inout ProtocolTreeBuilder) -> DissectionStep
}
```

`DissectorRegistry.dissect` starts at `.link(linkType)` and repeatedly asks for the first dissector that accepts the
next layer: `.etherType`, `.ipProtocol` or `.transportPayload(udp/tcp)`. Each dissector adds its layer and fields
with byte ranges and returns the next layer plus its range. Lower layers record what they learned in
`DissectionContext` (addresses, IP protocol, ports, a one-line summary). Bytes no dissector claims become a "Data"
layer. The walk is bounded at 24 layers, and trees at 2,000 fields. A dissector may only move forward within the
frame.

| Layer | Dissectors (`name`) |
|---|---|
| Link | Ethernet II / 802.3 + LLC (`eth`), 802.1Q/802.1ad (`vlan`), MPLS (`mpls`), PPPoE (`pppoe`), Linux SLL/SLL2 (`sll`), loopback (`null`), raw IP (`raw`), LLDP (`lldp`) |
| Network | ARP (`arp`, gratuitous detection), IPv4 (`ip`, checksum verification, options, fragments), IPv6 (`ipv6`, extension headers, fragments), ICMP (`icmp`, quoted datagrams), ICMPv6 (`icmpv6`, neighbor discovery options) |
| Transport | UDP (`udp`), TCP (`tcp`, MSS/WS/SACK/timestamp options) |
| Application | SIP + SDP (`sip`, `sdp`), STUN/ICE (`stun`), TURN incl. ChannelData (`turn`), DNS/mDNS/LLMNR (`dns`: compression, A/AAAA/CNAME/NS/PTR/MX/TXT/SRV/NAPTR/SOA/OPT), DHCP (`dhcp`: options incl. TFTP/SIP servers), NTP (`ntp`), HTTP/1.x (`http`), TLS metadata (`tls`: records, Client/Server Hello, SNI, ALPN, supported versions, cipher suites; never decrypted), RTCP compound packets (`rtcp`: SR/RR report blocks, SDES, BYE, feedback, XR), RTP (`rtp`: CSRCs, header extensions) |

Order matters for application protocols. Content-validated protocols (SIP, the STUN magic cookie) come first,
port-based ones next, and RTP, the loosest heuristic, last.

Adding a protocol means writing one type and listing it in `DissectorRegistry.standard`. Tests can also build a
registry with extra dissectors (`DissectorRegistry(dissectors:)`, see `DissectorTests.registryIsExtensible`).

Index-time classification (`FrameDecoding`) recognizes the same application protocols cheaply, so the packet list,
filters and flows see them: TLS records, HTTP start lines and STUN on any TCP/UDP port, TURN by method or
ChannelData, and DNS/DHCP/NTP by port. The index stores the IP protocol, so `udp`/`tcp` filters are exact.

Room is left for HTTP/2, QUIC, MQTT, WebSocket, Diameter, SCTP, GTP, IAX2, MGCP and H.323 as further dissectors.

Before a parser is written here, the rule from the spec applies: use an Apple API if one fits, otherwise evaluate a
license-compatible open-source implementation, and only then implement it internally. So far every parser is
internal because none of these protocols has an Apple parsing API. See dependencies.md.

## Verification

`Fixtures/application-protocols.pcap` holds one or more packets of every dissected protocol, all well-formed (valid
checksums and STUN fingerprints). `DissectorTests` pins WirePath's decode of each packet to tshark's. The fuzzer
mutates this fixture and every other one.

## Adding metrics and findings

- New codecs go in `CodecCatalog`, and their E-model parameters in `EModel.impairment`. Codecs without published
  parameters return nil, and the UI shows "—".
- New findings go in `FindingDetector`. A finding must quote measured evidence (counts, times, streams, calls).
