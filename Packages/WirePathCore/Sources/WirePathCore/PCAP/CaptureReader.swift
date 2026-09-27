import Foundation

/// Link-layer header type (tcpdump.org LINKTYPE_* values).
public struct LinkType: RawRepresentable, Hashable, Sendable, CustomStringConvertible {
    public var rawValue: UInt32
    public init(rawValue: UInt32) { self.rawValue = rawValue }

    public static let null = LinkType(rawValue: 0)
    public static let ethernet = LinkType(rawValue: 1)
    public static let rawAlt = LinkType(rawValue: 12)
    public static let rawAlt2 = LinkType(rawValue: 14)
    public static let raw = LinkType(rawValue: 101)
    public static let loop = LinkType(rawValue: 108)
    public static let linuxSLL = LinkType(rawValue: 113)
    public static let ipv4 = LinkType(rawValue: 228)
    public static let ipv6 = LinkType(rawValue: 229)
    public static let linuxSLL2 = LinkType(rawValue: 276)

    public var description: String {
        switch self {
        case .null: return "BSD loopback"
        case .ethernet: return "Ethernet"
        case .raw, .rawAlt, .rawAlt2: return "Raw IP"
        case .loop: return "OpenBSD loopback"
        case .linuxSLL: return "Linux cooked (SLL)"
        case .ipv4: return "Raw IPv4"
        case .ipv6: return "Raw IPv6"
        case .linuxSLL2: return "Linux cooked (SLL2)"
        default: return "Link type \(rawValue)"
        }
    }
}

public enum CaptureFileFormat: Sendable, Equatable {
    case pcap(nanosecond: Bool, bigEndian: Bool)
    case pcapng
    case gzip

    /// Sniffs the first bytes of a file.
    public static func detect(_ bytes: UnsafeRawBufferPointer) throws -> CaptureFileFormat {
        guard bytes.count >= 4 else { throw bytes.isEmpty ? CaptureError.empty : CaptureError.corrupt(reason: String(localized: "file too short", bundle: CoreLocalization.bundle), offset: 0) }
        if bytes[0] == 0x1F && bytes[1] == 0x8B { return .gzip }
        let magic = bytes.u32le(0)
        switch magic {
        case 0xA1B2_C3D4: return .pcap(nanosecond: false, bigEndian: false)
        case 0xA1B2_3C4D: return .pcap(nanosecond: true, bigEndian: false)
        case 0xD4C3_B2A1: return .pcap(nanosecond: false, bigEndian: true)
        case 0x4D3C_B2A1: return .pcap(nanosecond: true, bigEndian: true)
        case 0x0A0D_0D0A: return .pcapng
        default:
            if bytes[0] == 0x28 && bytes[1] == 0xB5 && bytes[2] == 0x2F && bytes[3] == 0xFD {
                throw CaptureError.compressedNotSupported  // zstd
            }
            if bytes[0] == 0xFD && bytes[1] == 0x37 && bytes[2] == 0x7A && bytes[3] == 0x58 {
                throw CaptureError.compressedNotSupported  // xz
            }
            throw CaptureError.unsupportedFormat(magic: bytes.u32be(0))
        }
    }
}

/// One captured packet, referencing its bytes inside the capture file.
public struct CapturedFrame: Sendable {
    /// 1-based frame number.
    public var number: Int
    public var timestampNanos: Int64
    public var linkType: LinkType
    public var interfaceID: Int
    /// Offset of the packet data in the capture file.
    public var dataOffset: Int
    public var capturedLength: Int
    public var originalLength: Int

    public init(number: Int, timestampNanos: Int64, linkType: LinkType, interfaceID: Int, dataOffset: Int,
                capturedLength: Int, originalLength: Int) {
        self.number = number
        self.timestampNanos = timestampNanos
        self.linkType = linkType
        self.interfaceID = interfaceID
        self.dataOffset = dataOffset
        self.capturedLength = capturedLength
        self.originalLength = originalLength
    }
}

/// A capture interface (pcapng Interface Description Block, or the single link of a pcap file).
public struct CaptureInterfaceInfo: Codable, Sendable, Hashable {
    public var id: Int
    public var linkType: UInt32
    public var linkTypeName: String
    /// Maximum bytes captured per packet (0 = unlimited).
    public var snapLength: Int
    public var name: String?
    public var interfaceDescription: String?
    /// e.g. "µs", "ns", "2^-20 s".
    public var timestampResolution: String
    /// Bytes of Ethernet FCS present at the end of each frame (pcap link-type field), when declared.
    public var fcsLength: Int?
    /// From the last Interface Statistics Block, when the capture tool wrote one.
    public var packetsReceived: UInt64?
    public var packetsDroppedByInterface: UInt64?
    public var packetsDroppedByOS: UInt64?
    /// Packets in this file captured on the interface.
    public var packetCount: Int
}

/// Section Header Block metadata (pcapng only).
public struct CaptureSectionInfo: Codable, Sendable, Hashable {
    public var hardware: String?
    public var operatingSystem: String?
    public var application: String?
    public var comments: [String]
}

/// A comment attached to a packet (pcapng opt_comment).
public struct PacketComment: Codable, Sendable, Hashable {
    public var frameNumber: Int
    public var text: String
}

/// Sequential reader over a memory-mapped pcap or pcapng file.
///
/// The file is untrusted: every length is checked against the bytes actually present, and values that
/// would overflow (timestamps, resolutions, offsets) are clamped or computed with wrapping arithmetic.
/// Damage at the end of a file (a common result of an interrupted capture) ends iteration gracefully and is
/// reported through `truncatedAtEnd`; damage before any packet was read throws.
public struct CaptureReader: Sendable {
    /// Bounds on metadata kept from a file, so a crafted capture cannot exhaust memory.
    public enum Limits {
        public static let maxRecordLength = 0x0400_0000        // 64 MiB per packet
        public static let maxInterfaces = 4_096
        public static let maxPacketComments = 10_000
        public static let maxSectionComments = 64
        public static let maxTextLength = 4_096
        public static let maxWarnings = 100
    }

    public let file: CaptureFile
    public let format: CaptureFileFormat
    public internal(set) var offset: Int
    public internal(set) var framesRead = 0
    public internal(set) var truncatedAtEnd = false
    public internal(set) var warnings: [String] = []
    /// Link types of every interface seen so far.
    public internal(set) var linkTypes: [LinkType] = []
    /// Every interface of the file (pcapng: across all sections).
    public internal(set) var interfaceInfos: [CaptureInterfaceInfo] = []
    public internal(set) var sectionInfo: CaptureSectionInfo?
    public internal(set) var packetComments: [PacketComment] = []
    /// pcap: file format version, e.g. "2.4"; pcapng: section version, e.g. "1.0".
    public internal(set) var formatVersion = ""

    // pcap state
    var pcapLinkType = LinkType.ethernet
    var pcapBigEndian = false
    var pcapNanosecond = false
    var pcapSnapLength = 0
    var warnedAboutSnapLength = false

    // pcapng state
    struct Interface: Sendable {
        var linkType: LinkType
        var snapLength: Int
        /// Timestamp units per second expressed as (base, exponent): 10^n or 2^n.
        var tsDecimal: Bool
        var tsExponent: Int
        var tsOffsetSeconds: Int64
        /// Position in `interfaceInfos`.
        var globalID: Int
    }
    var sectionBigEndian = false
    var interfaces: [Interface] = []

    public init(file: CaptureFile) throws {
        self.file = file
        let head = file.bytes(offset: 0, length: 64)
        format = try CaptureFileFormat.detect(head)
        switch format {
        case .gzip:
            throw CaptureError.compressedNotSupported
        case .pcap(let nanosecond, let bigEndian):
            guard file.size >= 24 else { throw CaptureError.corrupt(reason: String(localized: "pcap header is incomplete", bundle: CoreLocalization.bundle), offset: 0) }
            pcapNanosecond = nanosecond
            pcapBigEndian = bigEndian
            formatVersion = "\(head.u16(4, bigEndian: bigEndian)).\(head.u16(6, bigEndian: bigEndian))"
            pcapSnapLength = Int(head.u32(16, bigEndian: bigEndian))
            // LinkType field: low 16 bits are the link type; bit 28 flags an FCS whose length (in 16-bit words)
            // is in bits 29-31.
            let field = head.u32(20, bigEndian: bigEndian)
            pcapLinkType = LinkType(rawValue: field & 0xFFFF)
            linkTypes = [pcapLinkType]
            interfaceInfos = [CaptureInterfaceInfo(
                id: 0, linkType: pcapLinkType.rawValue, linkTypeName: pcapLinkType.description, snapLength: pcapSnapLength,
                timestampResolution: nanosecond ? "ns" : "µs", fcsLength: field & 0x1000_0000 != 0 ? Int(field >> 29) * 2 : nil,
                packetCount: 0)]
            offset = 24
        case .pcapng:
            offset = 0
        }
    }

    public var fractionRead: Double {
        file.size > 0 ? Double(offset) / Double(file.size) : 1
    }

    /// Returns the next frame, or nil at the end of the file.
    public mutating func next() throws -> CapturedFrame? {
        switch format {
        case .pcap:
            let frame = nextPCAP()
            if frame == nil, framesRead == 0, truncatedAtEnd {
                // Damage before the first packet: nothing in the file can be analyzed.
                throw CaptureError.corrupt(reason: warnings.last ?? String(localized: "the first packet record is damaged", bundle: CoreLocalization.bundle), offset: 24)
            }
            return frame
        case .pcapng: return try nextPCAPNG()
        case .gzip: return nil
        }
    }

    /// Reads up to `maxCount` frames into `frames` (cleared first). Returns false at end of file.
    public mutating func readBatch(into frames: inout [CapturedFrame], maxCount: Int) throws -> Bool {
        frames.removeAll(keepingCapacity: true)
        while frames.count < maxCount {
            guard let frame = try next() else { return !frames.isEmpty }
            frames.append(frame)
        }
        return true
    }

    // MARK: pcap

    mutating func nextPCAP() -> CapturedFrame? {
        let remaining = file.size - offset
        guard remaining > 0 else { return nil }
        guard remaining >= 16 else {
            markTruncated(String(localized: "Capture ends inside a record header", bundle: CoreLocalization.bundle))
            return nil
        }
        let header = file.bytes(offset: offset, length: 16)
        let seconds = Int64(header.u32(0, bigEndian: pcapBigEndian))
        let fraction = Int64(header.u32(4, bigEndian: pcapBigEndian))
        let capLen = Int(header.u32(8, bigEndian: pcapBigEndian))
        let origLen = Int(header.u32(12, bigEndian: pcapBigEndian))
        guard capLen <= Limits.maxRecordLength else {
            markTruncated(String(localized: "Invalid record length \(capLen) at byte \(offset)", bundle: CoreLocalization.bundle))
            return nil
        }
        guard remaining - 16 >= capLen else {
            markTruncated(String(localized: "Capture ends inside packet \(framesRead + 1)", bundle: CoreLocalization.bundle))
            return nil
        }
        if pcapSnapLength > 0, capLen > pcapSnapLength, !warnedAboutSnapLength {
            warnedAboutSnapLength = true
            warn(String(localized: "Packet \(framesRead + 1) is longer than the snapshot length (\(capLen) > \(pcapSnapLength) bytes)", bundle: CoreLocalization.bundle))
        }
        // Seconds and fraction are 32-bit, so this cannot overflow Int64.
        let nanos = seconds * 1_000_000_000 + (pcapNanosecond ? fraction : fraction * 1_000)
        framesRead += 1
        interfaceInfos[0].packetCount += 1
        let frame = CapturedFrame(number: framesRead, timestampNanos: nanos, linkType: pcapLinkType, interfaceID: 0,
                                  dataOffset: offset + 16, capturedLength: capLen, originalLength: max(origLen, capLen))
        offset += 16 + capLen
        return frame
    }

    mutating func markTruncated(_ message: String) {
        truncatedAtEnd = true
        warn(message)
        offset = file.size
    }

    mutating func warn(_ message: String) {
        if warnings.count < Limits.maxWarnings { warnings.append(message) }
    }

}
