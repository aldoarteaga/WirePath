import Foundation

/// A packet of an analysis, built from its packet-index record.
///
/// The three parts of a packet are kept apart so listing millions of packets never touches payloads:
/// `Packet` (metadata, from the memory-mapped index), `PacketBytes` (read from the capture file on demand) and
/// `DecodedProtocols` (the protocol tree, decoded on demand for the selected packet).
public struct Packet: Sendable, Hashable, Identifiable {
    /// 1-based frame number.
    public var number: Int
    public var timestamp: Timestamp
    public var capturedLength: Int
    public var originalLength: Int
    public var linkType: LinkType
    public var interfaceID: Int
    public var metadata: PacketMetadata

    public var id: Int { number }
    /// Fewer bytes were captured than were on the wire (snapshot length).
    public var isSliced: Bool { capturedLength < originalLength }
}

/// What the analysis learned about a packet, and its links to the objects built from it
/// (Packet → Flow → SIP message / call → RTP stream).
public struct PacketMetadata: Sendable, Hashable {
    public var protocolKind: PacketProtocol
    public var source: IPAddress?
    public var destination: IPAddress?
    public var sourcePort: UInt16?
    public var destinationPort: UInt16?
    public var flags: PacketFlags
    public var flowIndex: Int?
    public var callIndex: Int?
    public var streamIndex: Int?
    /// Index into `AnalysisResult.sipMessages` for SIP packets.
    public var sipMessageIndex: Int?
}

/// The captured bytes of one packet.
public struct PacketBytes: Sendable, Hashable {
    public var number: Int
    public var data: Data
}

/// The protocol tree of one packet.
public typealias DecodedProtocols = DissectedPacket
