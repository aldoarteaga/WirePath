import Foundation

/// An IPv4 or IPv6 address stored inline (no heap allocation), cheap to hash and compare.
public enum IPAddress: Hashable, Sendable {
    case v4(UInt32)
    case v6(hi: UInt64, lo: UInt64)

    public var isV4: Bool {
        if case .v4 = self { return true }
        return false
    }

    /// RFC 1918 / RFC 4193 / loopback / link-local ranges.
    public var isPrivate: Bool {
        switch self {
        case .v4(let a):
            let o1 = a >> 24, o2 = (a >> 16) & 0xFF
            return o1 == 10 || (o1 == 172 && (16...31).contains(o2)) || (o1 == 192 && o2 == 168)
                || o1 == 127 || (o1 == 169 && o2 == 254) || (o1 == 100 && (64...127).contains(o2))
        case .v6(let hi, let lo):
            let top = hi >> 56
            if hi == 0 && lo == 1 { return true }            // ::1
            if top == 0xFC || top == 0xFD { return true }    // fc00::/7
            if hi >> 54 == 0x3FA { return true }             // fe80::/10
            return false
        }
    }

    // MARK: Parsing

    public init?(_ string: String) {
        if let v4 = IPAddress.parseV4(Substring(string)) {
            self = .v4(v4)
        } else if let v6 = IPAddress.parseV6(string) {
            self = v6
        } else {
            return nil
        }
    }

    private static func parseV4(_ s: Substring) -> UInt32? {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var value: UInt32 = 0
        for part in parts {
            guard !part.isEmpty, part.count <= 3, let octet = UInt32(part), octet <= 255 else { return nil }
            value = value << 8 | octet
        }
        return value
    }

    private static func parseV6(_ string: String) -> IPAddress? {
        var s = Substring(string)
        if s.hasPrefix("[") && s.hasSuffix("]") { s = s.dropFirst().dropLast() }
        if let pct = s.firstIndex(of: "%") { s = s[..<pct] }
        guard s.contains(":") else { return nil }

        var groups: [UInt16] = []
        var tail: [UInt16] = []
        var seenDoubleColon = false
        let halves = s.components(separatedBy: "::")
        guard halves.count <= 2 else { return nil }
        if halves.count == 2 { seenDoubleColon = true }

        func parseGroups(_ part: String, into array: inout [UInt16]) -> Bool {
            if part.isEmpty { return true }
            let items = part.split(separator: ":", omittingEmptySubsequences: false)
            for (index, item) in items.enumerated() {
                if item.contains("."), index == items.count - 1, let v4 = parseV4(item) {
                    array.append(UInt16(v4 >> 16))
                    array.append(UInt16(v4 & 0xFFFF))
                } else {
                    guard !item.isEmpty, item.count <= 4, let g = UInt16(item, radix: 16) else { return false }
                    array.append(g)
                }
            }
            return true
        }

        guard parseGroups(halves[0], into: &groups) else { return nil }
        if seenDoubleColon {
            guard parseGroups(halves[1], into: &tail) else { return nil }
            let missing = 8 - groups.count - tail.count
            guard missing >= 1 else { return nil }
            groups += Array(repeating: 0, count: missing) + tail
        }
        guard groups.count == 8 else { return nil }
        var hi: UInt64 = 0, lo: UInt64 = 0
        for i in 0..<4 { hi = hi << 16 | UInt64(groups[i]) }
        for i in 4..<8 { lo = lo << 16 | UInt64(groups[i]) }
        return .v6(hi: hi, lo: lo)
    }

    /// Builds an address from raw network-order bytes (4 or 16 bytes).
    public init?(bytes: UnsafeRawBufferPointer) {
        switch bytes.count {
        case 4:
            self = .v4(UInt32(bytes[0]) << 24 | UInt32(bytes[1]) << 16 | UInt32(bytes[2]) << 8 | UInt32(bytes[3]))
        case 16:
            var hi: UInt64 = 0, lo: UInt64 = 0
            for i in 0..<8 { hi = hi << 8 | UInt64(bytes[i]) }
            for i in 8..<16 { lo = lo << 8 | UInt64(bytes[i]) }
            self = .v6(hi: hi, lo: lo)
        default:
            return nil
        }
    }
}

extension IPAddress: CustomStringConvertible {
    public var description: String {
        switch self {
        case .v4(let a):
            return "\(a >> 24).\((a >> 16) & 0xFF).\((a >> 8) & 0xFF).\(a & 0xFF)"
        case .v6(let hi, let lo):
            var groups = [UInt16](repeating: 0, count: 8)
            for i in 0..<4 { groups[i] = UInt16(truncatingIfNeeded: hi >> UInt64(48 - i * 16)) }
            for i in 0..<4 { groups[4 + i] = UInt16(truncatingIfNeeded: lo >> UInt64(48 - i * 16)) }
            // RFC 5952: compress the longest run (>= 2) of zero groups.
            var bestStart = -1, bestLen = 0, runStart = -1
            for i in 0...8 {
                if i < 8 && groups[i] == 0 {
                    if runStart < 0 { runStart = i }
                } else if runStart >= 0 {
                    let len = i - runStart
                    if len > bestLen && len >= 2 { bestStart = runStart; bestLen = len }
                    runStart = -1
                }
            }
            func hex(_ range: Range<Int>) -> String {
                range.map { String(groups[$0], radix: 16) }.joined(separator: ":")
            }
            if bestStart < 0 { return hex(0..<8) }
            return hex(0..<bestStart) + "::" + hex((bestStart + bestLen)..<8)
        }
    }
}

extension IPAddress: Comparable {
    public static func < (lhs: IPAddress, rhs: IPAddress) -> Bool {
        switch (lhs, rhs) {
        case (.v4(let a), .v4(let b)): return a < b
        case (.v4, .v6): return true
        case (.v6, .v4): return false
        case (.v6(let ah, let al), .v6(let bh, let bl)): return ah != bh ? ah < bh : al < bl
        }
    }
}

extension IPAddress: Codable {
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let string = try container.decode(String.self)
        guard let address = IPAddress(string) else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid IP address \(string)")
        }
        self = address
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
}
