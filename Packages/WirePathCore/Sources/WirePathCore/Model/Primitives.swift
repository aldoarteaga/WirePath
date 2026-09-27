import Foundation

/// Absolute capture time with nanosecond resolution (nanoseconds since the Unix epoch).
///
/// Capture timestamps are untrusted (a pcapng file can place packets anywhere in the Int64 range), so the
/// arithmetic here never traps: differences fall back to floating point and sums saturate.
public struct Timestamp: Hashable, Comparable, Codable, Sendable {
    public var nanoseconds: Int64

    public init(nanoseconds: Int64) { self.nanoseconds = nanoseconds }
    public init(seconds: Double) { self.nanoseconds = Self.clampedNanoseconds(seconds * 1e9) }

    public var seconds: Double { Double(nanoseconds) / 1e9 }
    public var date: Date { Date(timeIntervalSince1970: seconds) }

    /// Seconds elapsed from `other` to `self`.
    public func seconds(since other: Timestamp) -> Double {
        let (difference, overflow) = nanoseconds.subtractingReportingOverflow(other.nanoseconds)
        return overflow ? (Double(nanoseconds) - Double(other.nanoseconds)) / 1e9 : Double(difference) / 1e9
    }

    public func adding(seconds: Double) -> Timestamp {
        let delta = Self.clampedNanoseconds(seconds * 1e9)
        let (sum, overflow) = nanoseconds.addingReportingOverflow(delta)
        return Timestamp(nanoseconds: overflow ? (delta > 0 ? .max : .min) : sum)
    }

    /// Nanoseconds from nanosecond values that may be non-finite or out of range.
    static func clampedNanoseconds(_ value: Double) -> Int64 {
        guard value.isFinite else { return value.isNaN ? 0 : (value > 0 ? .max : .min) }
        if value >= 9.2e18 { return .max }
        if value <= -9.2e18 { return .min }
        return Int64(value.rounded())
    }

    public static func < (lhs: Timestamp, rhs: Timestamp) -> Bool { lhs.nanoseconds < rhs.nanoseconds }

    public init(from decoder: Decoder) throws {
        nanoseconds = try decoder.singleValueContainer().decode(Int64.self)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(nanoseconds)
    }
}

public enum TransportKind: String, Codable, Sendable {
    case udp, tcp, sctp, other
}

/// An IP address + transport port.
public struct Endpoint: Hashable, Codable, Sendable, Comparable, CustomStringConvertible {
    public var address: IPAddress
    public var port: UInt16

    public init(address: IPAddress, port: UInt16) {
        self.address = address
        self.port = port
    }

    public var description: String {
        address.isV4 ? "\(address):\(port)" : "[\(address)]:\(port)"
    }

    public static func < (lhs: Endpoint, rhs: Endpoint) -> Bool {
        lhs.address != rhs.address ? lhs.address < rhs.address : lhs.port < rhs.port
    }
}

/// Severity levels used throughout the UI (Good / Warning / Error in the design legend).
public enum Severity: Int, Codable, Sendable, Comparable {
    case ok = 0
    case info = 1
    case warning = 2
    case error = 3

    public static func < (lhs: Severity, rhs: Severity) -> Bool { lhs.rawValue < rhs.rawValue }
}
