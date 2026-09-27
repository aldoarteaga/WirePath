import Foundation

/// One RTCP report block: what a receiver says about one source (RFC 3550 §6.4.1).
public struct RTCPReportBlock: Codable, Sendable, Hashable {
    /// The source (RTP stream) the block is about.
    public var ssrc: UInt32
    /// Fraction of packets lost since the previous report, 0…1.
    public var fractionLost: Double
    /// Packets lost since the beginning of reception (signed 24-bit; duplicates can make it negative).
    public var cumulativeLost: Int
    public var extendedHighestSequence: UInt32
    /// Interarrival jitter in RTP timestamp units.
    public var jitter: UInt32
    /// Middle 32 bits of the NTP timestamp of the last SR received from the source (0 = none).
    public var lastSR: UInt32
    /// Delay since that SR, in units of 1/65536 s.
    public var delaySinceLastSR: UInt32
    /// Round trip measured at the capture point: (this report's time − the matched SR's time) − DLSR.
    public var roundTripMs: Double?
}

/// RFC 3611 §4.7 VoIP Metrics, as reported by an endpoint (not computed by WirePath).
public struct RTCPVoIPMetrics: Codable, Sendable, Hashable {
    public var ssrc: UInt32
    public var lossRate: Double
    public var discardRate: Double
    public var roundTripDelayMs: Int?
    public var endSystemDelayMs: Int?
    public var rFactor: Int?
    public var mosLQ: Double?
    public var mosCQ: Double?
    public var jitterBufferNominalMs: Int?
    public var jitterBufferMaxMs: Int?
}

/// One RTCP packet of a compound packet that WirePath reads: SR, RR or XR (SDES/BYE/APP/feedback are only named).
public struct RTCPReportRecord: Codable, Sendable, Hashable, Identifiable {
    public enum Kind: String, Codable, Sendable { case senderReport, receiverReport, extendedReport }

    public var id: Int
    public var frameNumber: Int
    public var time: Timestamp
    public var source: Endpoint
    public var destination: Endpoint
    public var kind: Kind
    public var senderSSRC: UInt32
    /// Sender Reports only.
    public var ntpTimestamp: UInt64?
    public var rtpTimestamp: UInt32?
    public var senderPacketCount: UInt32?
    public var senderOctetCount: UInt32?
    public var blocks: [RTCPReportBlock]
    public var voipMetrics: [RTCPVoIPMetrics]
    /// SDES CNAME of the sender, when the compound packet carries one.
    public var cname: String?
}

/// What RTCP says about one RTP stream: its sender's reports and what its receiver reported back.
public struct RTCPStreamSummary: Codable, Sendable, Hashable {
    public var senderReports: Int
    public var receiverReports: Int
    /// From the stream's last Sender Report.
    public var lastSenderPacketCount: UInt32?
    public var lastSenderOctetCount: UInt32?
    /// Receiver-reported loss for the stream.
    public var maxFractionLostPercent: Double?
    public var lastCumulativeLost: Int?
    /// Receiver-reported jitter, converted with the stream's clock rate when known.
    public var maxReportedJitterMs: Double?
    public var roundTripMs: RoundTrip?
    /// Endpoint-reported VoIP metrics (RTCP XR), most recent.
    public var voipMetrics: RTCPVoIPMetrics?
    public var cname: String?

    public struct RoundTrip: Codable, Sendable, Hashable {
        public var min: Double
        public var mean: Double
        public var max: Double
        public var samples: Int
    }
}

/// Parses RTCP compound packets during the sequential pass and matches Receiver Reports to the Sender Reports they
/// acknowledge (by LSR) for round-trip times. Bounded: at most `maxReports` reports are kept.
struct RTCPTracker {
    static let maxReports = 100_000

    private(set) var reports: [RTCPReportRecord] = []
    /// Capture time of each Sender Report, keyed by (sender SSRC, middle 32 bits of its NTP timestamp).
    private var senderReportTimes: [SRKey: Timestamp] = [:]
    private(set) var limitReached = false

    struct SRKey: Hashable {
        var ssrc: UInt32
        var ntpMiddle: UInt32
    }

    mutating func ingest(_ payload: UnsafeRawBufferPointer, frameNumber: Int, time: Timestamp, source: Endpoint, destination: Endpoint) {
        var p = 0
        var packets = 0
        var cname: String?
        var produced: [Int] = []
        while p + 8 <= payload.count, packets < 16 {
            packets += 1
            let first = payload[p]
            guard first >> 6 == 2 else { break }
            let count = Int(first & 0x1F)
            let type = payload[p + 1]
            let length = (Int(payload.u16be(p + 2)) + 1) * 4
            let end = min(payload.count, p + length)
            let ssrc = payload.u32be(p + 4)
            switch type {
            case 200 where end - p >= 28:
                let ntp = payload.u64(p + 8, bigEndian: true)
                if senderReportTimes.count < Self.maxReports {
                    senderReportTimes[SRKey(ssrc: ssrc, ntpMiddle: UInt32(truncatingIfNeeded: ntp >> 16))] = time
                }
                append(RTCPReportRecord(id: 0, frameNumber: frameNumber, time: time, source: source, destination: destination,
                                        kind: .senderReport, senderSSRC: ssrc, ntpTimestamp: ntp,
                                        rtpTimestamp: payload.u32be(p + 16), senderPacketCount: payload.u32be(p + 20),
                                        senderOctetCount: payload.u32be(p + 24),
                                        blocks: blocks(payload, from: p + 28, count: count, end: end, time: time),
                                        voipMetrics: []), into: &produced)
            case 201:
                append(RTCPReportRecord(id: 0, frameNumber: frameNumber, time: time, source: source, destination: destination,
                                        kind: .receiverReport, senderSSRC: ssrc,
                                        blocks: blocks(payload, from: p + 8, count: count, end: end, time: time),
                                        voipMetrics: []), into: &produced)
            case 202:
                cname = cname ?? Self.cname(payload, from: p + 4, end: end)
            case 207:
                let metrics = Self.voipMetrics(payload, from: p + 8, end: end)
                if !metrics.isEmpty {
                    append(RTCPReportRecord(id: 0, frameNumber: frameNumber, time: time, source: source, destination: destination,
                                            kind: .extendedReport, senderSSRC: ssrc, blocks: [], voipMetrics: metrics), into: &produced)
                }
            default:
                break
            }
            guard length > 0 else { break }
            p += length
        }
        if let cname { for index in produced { reports[index].cname = cname } }
    }

    private mutating func append(_ report: RTCPReportRecord, into produced: inout [Int]) {
        guard reports.count < Self.maxReports else {
            limitReached = true
            return
        }
        var report = report
        report.id = reports.count
        produced.append(reports.count)
        reports.append(report)
    }

    private func blocks(_ payload: UnsafeRawBufferPointer, from start: Int, count: Int, end: Int, time: Timestamp) -> [RTCPReportBlock] {
        var result: [RTCPReportBlock] = []
        var q = start
        for _ in 0..<count where q + 24 <= end {
            let ssrc = payload.u32be(q)
            let lastSR = payload.u32be(q + 16), dlsr = payload.u32be(q + 20)
            var rtt: Double?
            if lastSR != 0, let srTime = senderReportTimes[SRKey(ssrc: ssrc, ntpMiddle: lastSR)] {
                let value = time.seconds(since: srTime) * 1_000 - Double(dlsr) / 65_536 * 1_000
                if value >= 0, value < 60_000 { rtt = value }
            }
            result.append(RTCPReportBlock(ssrc: ssrc, fractionLost: Double(payload[q + 4]) / 256,
                                          cumulativeLost: Int(Int32(bitPattern: payload.u32be(q + 4) << 8) >> 8),
                                          extendedHighestSequence: payload.u32be(q + 8), jitter: payload.u32be(q + 12),
                                          lastSR: lastSR, delaySinceLastSR: dlsr, roundTripMs: rtt))
            q += 24
        }
        return result
    }

    static func cname(_ payload: UnsafeRawBufferPointer, from start: Int, end: Int) -> String? {
        var q = start + 4  // first chunk's SSRC
        var items = 0
        while q + 2 <= end, payload[q] != 0, items < 16 {
            items += 1
            let length = Int(payload[q + 1])
            if payload[q] == 1 {
                let text = String(decoding: payload.slice(q + 2, min(length, end - q - 2)), as: UTF8.self)
                return String(text.prefix(256))
            }
            q += 2 + length
        }
        return nil
    }

    /// XR blocks of type 7 (VoIP Metrics, 36 bytes). Layout (RFC 3611 §4.7), offsets from the block start:
    /// 4 SSRC · 8 loss rate · 9 discard rate · 16 round trip delay · 18 end system delay · 24 R factor ·
    /// 26 MOS-LQ · 27 MOS-CQ · 30 JB nominal · 32 JB maximum. 127 means "unavailable" for R and MOS.
    static func voipMetrics(_ payload: UnsafeRawBufferPointer, from start: Int, end: Int) -> [RTCPVoIPMetrics] {
        var result: [RTCPVoIPMetrics] = []
        var q = start
        var blocks = 0
        while q + 4 <= end, blocks < 16 {
            blocks += 1
            let blockType = payload[q]
            let length = (Int(payload.u16be(q + 2)) + 1) * 4
            if blockType == 7, q + 36 <= end {
                func optional(_ value: Int, unavailable: Int) -> Int? { value == unavailable ? nil : value }
                let r = Int(payload[q + 24]), mosLQ = Int(payload[q + 26]), mosCQ = Int(payload[q + 27])
                result.append(RTCPVoIPMetrics(
                    ssrc: payload.u32be(q + 4), lossRate: Double(payload[q + 8]) / 256, discardRate: Double(payload[q + 9]) / 256,
                    roundTripDelayMs: optional(Int(payload.u16be(q + 16)), unavailable: 0),
                    endSystemDelayMs: optional(Int(payload.u16be(q + 18)), unavailable: 0),
                    rFactor: optional(r, unavailable: 127), mosLQ: mosLQ == 127 ? nil : Double(mosLQ) / 10,
                    mosCQ: mosCQ == 127 ? nil : Double(mosCQ) / 10,
                    jitterBufferNominalMs: optional(Int(payload.u16be(q + 30)), unavailable: 0),
                    jitterBufferMaxMs: optional(Int(payload.u16be(q + 32)), unavailable: 0)))
            }
            guard length > 0 else { break }
            q += length
        }
        return result
    }

    /// Summaries per stream: the stream's own SRs (sender SSRC and address) and the blocks about it from its receiver.
    static func summaries(reports: [RTCPReportRecord], streams: [RTPStreamRecord]) -> [RTCPStreamSummary?] {
        var bySender: [UInt32: [RTCPReportRecord]] = [:]
        var aboutSource: [UInt32: [(report: RTCPReportRecord, block: RTCPReportBlock)]] = [:]
        var metricsAbout: [UInt32: [(report: RTCPReportRecord, metrics: RTCPVoIPMetrics)]] = [:]
        for report in reports {
            if report.kind == .senderReport { bySender[report.senderSSRC, default: []].append(report) }
            for block in report.blocks { aboutSource[block.ssrc, default: []].append((report, block)) }
            for metrics in report.voipMetrics { metricsAbout[metrics.ssrc, default: []].append((report, metrics)) }
        }
        return streams.map { stream in
            let own = (bySender[stream.ssrc] ?? []).filter { $0.source.address == stream.source.address }
            let received = (aboutSource[stream.ssrc] ?? []).filter { $0.report.source.address == stream.destination.address }
            let metrics = (metricsAbout[stream.ssrc] ?? []).filter { $0.report.source.address == stream.destination.address }
            guard !own.isEmpty || !received.isEmpty || !metrics.isEmpty else { return nil }
            let clock = stream.codec?.clockRate.map(Double.init)
            let rtts = received.compactMap(\.block.roundTripMs)
            return RTCPStreamSummary(
                senderReports: own.count, receiverReports: received.count,
                lastSenderPacketCount: own.last?.senderPacketCount, lastSenderOctetCount: own.last?.senderOctetCount,
                maxFractionLostPercent: received.map { $0.block.fractionLost * 100 }.max(),
                lastCumulativeLost: received.last?.block.cumulativeLost,
                maxReportedJitterMs: clock.flatMap { rate in received.map { Double($0.block.jitter) / rate * 1_000 }.max() },
                roundTripMs: rtts.isEmpty ? nil : RTCPStreamSummary.RoundTrip(
                    min: rtts.min() ?? 0, mean: rtts.reduce(0, +) / Double(rtts.count), max: rtts.max() ?? 0, samples: rtts.count),
                voipMetrics: metrics.last?.metrics,
                cname: own.last?.cname)
        }
    }
}

/// Problems RTCP reveals: long round trips (from matched SR/RR pairs) and endpoint-reported quality (XR VoIP metrics).
enum RTCPDiagnostics {
    /// ITU-T G.114: one-way delay above 150 ms degrades conversation, so a round trip above 300 ms is worth reporting.
    static let roundTripWarningMs = 300.0

    static func findings(streams: [RTPStreamRecord], firstID: Int) -> [Finding] {
        var result: [Finding] = []
        for stream in streams {
            guard let rtcp = stream.rtcp else { continue }
            let route = "\(stream.source) → \(stream.destination)"
            if let rtt = rtcp.roundTripMs, rtt.max > roundTripWarningMs {
                result.append(Finding(id: firstID + result.count, severity: .warning, kind: .highRoundTrip,
                                      title: String(localized: "High round-trip time", bundle: CoreLocalization.bundle),
                                      detail: String(localized: "\(route) · RTCP round trip up to \(Int(rtt.max.rounded())) ms (mean \(Int(rtt.mean.rounded())) ms over \(rtt.samples) reports)", bundle: CoreLocalization.bundle),
                                      callIndex: stream.callIndex, streamIndex: stream.id, time: stream.firstTime,
                                      packetFilter: "rtcp and ip.addr == \(stream.destination.address)"))
            }
            if let metrics = rtcp.voipMetrics, let mos = metrics.mosLQ, mos < QualityThresholds.mosWarning {
                result.append(Finding(id: firstID + result.count, severity: mos < QualityThresholds.mosError ? .error : .warning,
                                      kind: .reportedQuality, title: String(localized: "Endpoint reports low quality", bundle: CoreLocalization.bundle),
                                      detail: String(localized: "\(route) · receiver's RTCP XR: MOS-LQ \(String(format: "%.1f", mos))\(metrics.rFactor.map { ", R \($0)" } ?? ""), loss \(String(format: "%.1f", metrics.lossRate * 100))%", bundle: CoreLocalization.bundle),
                                      callIndex: stream.callIndex, streamIndex: stream.id, time: stream.firstTime,
                                      packetFilter: "rtcp and ip.src == \(stream.destination.address)"))
            }
        }
        return result
    }
}
