import Foundation

/// Writes pcapng files block by block (little-endian). Used for fixtures that need pcapng metadata — several
/// interfaces, comments, statistics — and by tests that hand-craft malformed blocks.
public struct PCAPNGBlockWriter {
    public var data = Data()

    public init() {}

    public static func option(_ code: UInt16, _ value: [UInt8]) -> [UInt8] {
        var bytes = le16(code) + le16(UInt16(value.count)) + value
        while bytes.count % 4 != 0 { bytes.append(0) }
        return bytes
    }

    public static func option(_ code: UInt16, _ text: String) -> [UInt8] { option(code, Array(text.utf8)) }
    public static let endOfOptions: [UInt8] = [0, 0, 0, 0]

    public static func le16(_ v: UInt16) -> [UInt8] { withUnsafeBytes(of: v.littleEndian, Array.init) }
    public static func le32(_ v: UInt32) -> [UInt8] { withUnsafeBytes(of: v.littleEndian, Array.init) }
    public static func le64(_ v: UInt64) -> [UInt8] { withUnsafeBytes(of: v.littleEndian, Array.init) }

    /// Appends a block; `trailingLength` overrides the repeated length field (to craft damaged blocks).
    public mutating func block(_ type: UInt32, _ body: [UInt8], trailingLength: UInt32? = nil) {
        var body = body
        while body.count % 4 != 0 { body.append(0) }
        let length = UInt32(12 + body.count)
        data.append(contentsOf: Self.le32(type) + Self.le32(length) + body + Self.le32(trailingLength ?? length))
    }

    public mutating func sectionHeader(options: [UInt8] = []) {
        block(0x0A0D_0D0A, Self.le32(0x1A2B_3C4D) + Self.le16(1) + Self.le16(0) + Self.le64(UInt64.max) + options)
    }

    public mutating func interface(linkType: UInt16 = 1, snapLength: UInt32 = 65_535, options: [UInt8] = []) {
        block(1, Self.le16(linkType) + Self.le16(0) + Self.le32(snapLength) + options)
    }

    /// Enhanced Packet Block. `originalLength` defaults to the captured length.
    public mutating func enhancedPacket(interface: UInt32 = 0, timestamp: UInt64, packet: [UInt8], originalLength: Int? = nil,
                                        options: [UInt8] = []) {
        var body = Self.le32(interface) + Self.le32(UInt32(timestamp >> 32)) + Self.le32(UInt32(timestamp & 0xFFFF_FFFF))
            + Self.le32(UInt32(packet.count)) + Self.le32(UInt32(originalLength ?? packet.count)) + packet
        while body.count % 4 != 0 { body.append(0) }
        block(6, body + options)
    }

    public mutating func simplePacket(_ packet: [UInt8]) {
        block(3, Self.le32(UInt32(packet.count)) + packet)
    }

    public mutating func interfaceStatistics(interface: UInt32 = 0, options: [UInt8]) {
        block(5, Self.le32(interface) + Self.le32(0) + Self.le32(0) + options)
    }
}
