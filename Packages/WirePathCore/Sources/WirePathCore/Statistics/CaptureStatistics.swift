import Foundation

/// Capture-wide statistics collected during the analysis pass (traffic over time, packet sizes, peak rates).
/// Per-flow aggregations (endpoints, conversations, TCP/UDP totals) are derived from `FlowRecord`s on demand.
public struct CaptureStatistics: Codable, Sendable, Hashable {
    /// Traffic per time bin, relative to `origin`.
    public var traffic: TrafficSeries
    /// Packet counts per length bucket (Wireshark's "Packet Lengths" buckets).
    public var packetSizes: [PacketSizeBucket]
    /// Busiest single second.
    public var peakPacketsPerSecond: Int
    public var peakBitsPerSecond: Double
    public var peakSecond: Timestamp?
    /// Mean over the capture's span (nil for single-instant captures).
    public var meanPacketsPerSecond: Double?
    public var meanBitsPerSecond: Double?
}

public struct TrafficSeries: Codable, Sendable, Hashable {
    public var origin: Timestamp
    public var binSeconds: Double
    public var packets: [Int]
    public var bytes: [Int64]
    /// Packets per bin for the busiest protocols (the rest are included in `packets` only).
    public var protocolPackets: [ProtocolSeries]

    public struct ProtocolSeries: Codable, Sendable, Hashable {
        public var protocolKind: PacketProtocol
        public var packets: [Int]
    }
}

public struct PacketSizeBucket: Codable, Sendable, Hashable {
    public var lowerBound: Int
    /// Inclusive upper bound; nil for the last, open-ended bucket.
    public var upperBound: Int?
    public var packets: Int

    public var label: String { upperBound.map { "\(lowerBound)–\($0)" } ?? "\(lowerBound)+" }
}

/// Accumulates statistics packet by packet. State is sparse (per occupied second) and bounded, so a capture
/// whose timestamps span years costs no more than one whose packets are close together.
struct StatisticsCollector {
    static let maxSeriesBins = 3_600
    /// Distinct seconds kept (about 55 hours of traffic); packets in later seconds count in the totals only.
    static let maxSeconds = 200_000
    static let trackedProtocols = 6
    static let sizeBounds = [19, 39, 79, 159, 319, 639, 1279, 2559, 5119]

    private struct Second {
        var packets = 0
        var bytes: Int64 = 0
        var protocols: [UInt8: Int] = [:]
    }

    private var origin: Int64?
    private var seconds: [Int64: Second] = [:]
    private var overflow = Second()
    private var sizes = [Int](repeating: 0, count: sizeBounds.count + 1)
    private var first: Int64?
    private var last: Int64?
    private var totalPackets = 0
    private var totalBytes: Int64 = 0

    mutating func add(timeNanos: Int64, length: Int, protocolKind: PacketProtocol) {
        totalPackets += 1
        totalBytes += Int64(length)
        first = min(first ?? timeNanos, timeNanos)
        last = max(last ?? timeNanos, timeNanos)
        let base = origin ?? timeNanos
        origin = base
        // Seconds since the first packet (earlier packets land in second 0).
        let second = max(0, Int64(Timestamp(nanoseconds: timeNanos).seconds(since: Timestamp(nanoseconds: base)).rounded(.down)))
        if seconds[second] == nil, seconds.count >= Self.maxSeconds {
            overflow.packets += 1
            overflow.bytes += Int64(length)
        } else {
            seconds[second, default: Second()].packets += 1
            seconds[second, default: Second()].bytes += Int64(length)
            seconds[second, default: Second()].protocols[protocolKind.rawValue, default: 0] += 1
        }
        let bucket = Self.sizeBounds.firstIndex { length <= $0 } ?? Self.sizeBounds.count
        sizes[bucket] += 1
    }

    func finish(protocolTotals: [PacketProtocol: Int]) -> CaptureStatistics {
        let originTime = Timestamp(nanoseconds: origin ?? 0)
        var span = 0.0
        if let first, let last {
            span = Timestamp(nanoseconds: last).seconds(since: Timestamp(nanoseconds: first))
        }

        // Dense series with bins widened so there are at most `maxSeriesBins`.
        let lastSecond = seconds.keys.max() ?? -1
        let secondsCount = Int(min(Int64(Int.max / 2), lastSecond + 1))
        let factor = max(1, (secondsCount + Self.maxSeriesBins - 1) / Self.maxSeriesBins)
        let binCount = secondsCount == 0 ? 0 : (secondsCount + factor - 1) / factor
        var packets = [Int](repeating: 0, count: binCount)
        var bytes = [Int64](repeating: 0, count: binCount)
        // Busiest first; ties by protocol so the chart is the same on every run.
        let tracked = protocolTotals.filter { $0.key != .unknown }
            .sorted { $0.value != $1.value ? $0.value > $1.value : $0.key.rawValue < $1.key.rawValue }
            .prefix(Self.trackedProtocols).map(\.key)
        var perProtocol = [UInt8: [Int]](uniqueKeysWithValues: tracked.map { ($0.rawValue, [Int](repeating: 0, count: binCount)) })
        var peakPackets = 0, peakBytes: Int64 = 0
        var peakAt: Int64?
        for (second, value) in seconds {
            let bin = Int(second) / factor
            guard bin < binCount else { continue }
            packets[bin] += value.packets
            bytes[bin] += value.bytes
            for (raw, count) in value.protocols where perProtocol[raw] != nil { perProtocol[raw]?[bin] += count }
            if value.packets > peakPackets || (value.packets == peakPackets && value.bytes > peakBytes) {
                peakPackets = value.packets
                peakBytes = value.bytes
                peakAt = second
            }
        }
        var buckets: [PacketSizeBucket] = []
        var lower = 0
        for (index, count) in sizes.enumerated() {
            let upper = index < Self.sizeBounds.count ? Self.sizeBounds[index] : nil
            buckets.append(PacketSizeBucket(lowerBound: lower, upperBound: upper, packets: count))
            lower = (upper ?? lower) + 1
        }
        let series = TrafficSeries(origin: originTime, binSeconds: Double(factor), packets: packets, bytes: bytes,
                                   protocolPackets: tracked.compactMap { kind in
                                       perProtocol[kind.rawValue].map { TrafficSeries.ProtocolSeries(protocolKind: kind, packets: $0) }
                                   })
        return CaptureStatistics(
            traffic: series, packetSizes: buckets, peakPacketsPerSecond: peakPackets, peakBitsPerSecond: Double(peakBytes) * 8,
            peakSecond: peakAt.map { originTime.adding(seconds: Double($0)) },
            meanPacketsPerSecond: span > 0 ? Double(totalPackets) / span : nil,
            meanBitsPerSecond: span > 0 ? Double(totalBytes) * 8 / span : nil)
    }
}

/// Totals by transport, derived from flows.
public struct TransportSummary: Sendable, Hashable {
    public var flows: Int
    public var packets: Int
    public var bytes: Int64

    public static func of(_ flows: [FlowRecord], transport: TransportKind) -> TransportSummary {
        let matching = flows.filter { $0.transport == transport }
        return TransportSummary(flows: matching.count, packets: matching.reduce(0) { $0 + $1.packets },
                                bytes: matching.reduce(0) { $0 + $1.bytes })
    }
}
