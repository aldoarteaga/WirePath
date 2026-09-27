import Foundation

/// Result of feeding one packet to a stream analyzer; used to flag packets in the index.
public struct RTPPacketVerdict: Sendable {
    public var sequenceGap: Bool
    /// Packets missing immediately before this one (when `sequenceGap`).
    public var lostBefore: Int
    public var duplicate: Bool
    public var outOfOrder: Bool
}

/// Incremental statistics for one RTP stream (one SSRC on one 5-tuple).
///
/// Loss, duplicates and reordering follow RFC 3550 Appendix A.1 (extended sequence numbers);
/// interarrival jitter follows RFC 3550 §6.4.1 / A.8 — every packet in arrival order, including late and
/// duplicated ones — and needs the RTP clock rate. Lost = expected − unique packets received, so duplicates
/// never hide real loss (RFC 3550's cumulative counter would subtract them).
public struct RTPStreamAnalyzer: Sendable {
    public let ssrc: UInt32
    public let source: Endpoint
    public let destination: Endpoint

    public var codecs: [UInt8: CodecDescriptor]
    public var ptimeMs: Int?
    public var negotiatedInSDP: Bool
    /// Negotiated as SRTP (or carried on a WebRTC session): payloads are encrypted.
    public var secure = false
    public var replacesSSRC: UInt32?

    public private(set) var firstArrival: Int64 = 0
    public private(set) var lastArrival: Int64 = 0
    public private(set) var packets = 0
    public private(set) var payloadBytes: Int64 = 0

    // Sequence state
    private var started = false
    private var baseExtended: Int64 = 0
    private var maxExtended: Int64 = 0
    private var maxSequence: UInt16 = 0
    private var uniqueReceived = 0
    public private(set) var duplicates = 0
    public private(set) var outOfOrder = 0
    public private(set) var sequenceGaps = 0
    private var history = [UInt64](repeating: 0, count: 64)  // last 4096 extended sequence numbers
    private var restarts = 0

    // Payload type bookkeeping
    private var payloadTypeCounts: [UInt8: Int] = [:]
    private var previousPayloadType: UInt8?
    public private(set) var payloadTypeChanges = 0
    public private(set) var markers = 0
    private var primaryPayloadType: UInt8?

    // Jitter (RFC 3550): tracked in RTP timestamp units.
    private var clockRate: Double?
    private var lastTransit: Double?
    private var jitter: Double = 0
    private var jitterSum: Double = 0
    private var jitterSamples = 0
    private var maxJitter: Double = 0
    private var maxJitterArrival: Int64 = 0
    private var timestampBase: UInt32 = 0
    private var timestampExtended: Int64 = 0
    private var lastTimestamp: UInt32 = 0

    // Inter-arrival deltas
    private var deltaSum: Double = 0
    private var deltaCount = 0
    private var maxDelta: Double = 0

    // Gilbert model transitions for BurstR.
    private var transitionsRR = 0, transitionsRL = 0, transitionsLL = 0, transitionsLR = 0

    // Series (0.5 s jitter bins, 1 s loss bins, relative to the first packet). Stored sparsely: memory follows
    // the packets, not the time span, which a crafted capture can make arbitrarily long.
    public static let jitterBin = 0.5
    public static let lossBin = 1.0
    /// Longest series persisted per stream; longer streams are summarised with proportionally wider bins.
    public static let maxSeriesBins = 20_000
    struct LossBin {
        var lost = 0
        var received = 0
        var firstLossTime = Int64.max
        var lastLossTime = Int64.min
    }
    private var jitterBins = JitterBins()
    private var lossBins = LossBins()
    /// Bins are stored densely (4–8 bytes each) while their index stays below the packets seen, which honest
    /// streams always do; bins that crafted timestamps push further out go to a small sparse map.
    private var denseLimit: Int { min(Self.maxDenseBins, packets + 64) }
    static let maxDenseBins = 1 << 22

    public init(ssrc: UInt32, source: Endpoint, destination: Endpoint, codecs: [UInt8: CodecDescriptor],
                ptimeMs: Int?, negotiatedInSDP: Bool) {
        self.ssrc = ssrc
        self.source = source
        self.destination = destination
        self.codecs = codecs
        self.ptimeMs = ptimeMs
        self.negotiatedInSDP = negotiatedInSDP
    }

    public var lastSequence: UInt16 { maxSequence }
    public var expected: Int { started ? Int(maxExtended - baseExtended + 1) : 0 }
    public var lost: Int { expected - uniqueReceived }

    /// Codec of the dominant payload type.
    public var dominantPayloadType: UInt8 {
        payloadTypeCounts.max { a, b in a.value != b.value ? a.value < b.value : a.key > b.key }?.key ?? 0
    }

    public func codec(for payloadType: UInt8) -> CodecDescriptor? {
        codecs[payloadType] ?? CodecCatalog.descriptor(payloadType: payloadType)
    }

    /// Descriptors of every payload type the stream carried (voice, DTMF events, comfort noise), by payload type.
    var payloadFormats: [CodecDescriptor] {
        payloadTypeCounts.keys.sorted().compactMap { codec(for: $0) }
    }

    /// Fraction of packets that were in sequence — used to accept heuristically detected streams.
    public var sequentialRatio: Double {
        packets > 1 ? Double(transitionsRR + transitionsRL) / Double(packets - 1) : 0
    }

    // MARK: Ingest

    public mutating func ingest(_ header: RTPHeader, arrivalNanos: Int64) -> RTPPacketVerdict {
        var verdict = RTPPacketVerdict(sequenceGap: false, lostBefore: 0, duplicate: false, outOfOrder: false)
        let seq = header.sequenceNumber
        packets += 1
        payloadBytes += Int64(header.payloadLength)
        if header.marker { markers += 1 }
        payloadTypeCounts[header.payloadType, default: 0] += 1
        if let previous = previousPayloadType, previous != header.payloadType { payloadTypeChanges += 1 }
        previousPayloadType = header.payloadType

        if !started {
            started = true
            firstArrival = arrivalNanos
            lastArrival = arrivalNanos
            baseExtended = Int64(seq)
            maxExtended = Int64(seq)
            maxSequence = seq
            uniqueReceived = 1
            markHistory(Int64(seq))
            addReceived(at: arrivalNanos)
            updateJitter(header, arrivalNanos: arrivalNanos)
            return verdict
        }

        // Inter-arrival delta (arrival order).
        let deltaMs = Double(arrivalNanos &- lastArrival) / 1e6
        if deltaMs >= 0 {
            deltaSum += deltaMs
            deltaCount += 1
            if deltaMs > maxDelta { maxDelta = deltaMs }
        }
        let previousArrival = lastArrival
        lastArrival = max(lastArrival, arrivalNanos)

        let delta = Int(Int16(bitPattern: seq &- maxSequence))
        if delta > 0 {
            if delta < 3000 {
                let gap = delta - 1
                if gap > 0 {
                    verdict.sequenceGap = true
                    verdict.lostBefore = gap
                    sequenceGaps += 1
                    transitionsRL += 1
                    transitionsLL += gap - 1
                    transitionsLR += 1
                    distributeLoss(gap, from: previousArrival, to: arrivalNanos)
                } else {
                    transitionsRR += 1
                }
                maxExtended += Int64(delta)
            } else {
                // Large jump: sender restarted its sequence space; do not count it as loss.
                restarts += 1
                maxExtended += Int64(delta)
                baseExtended += Int64(delta - 1)
                transitionsRR += 1
            }
            maxSequence = seq
            uniqueReceived += 1
            markHistory(maxExtended)
            addReceived(at: arrivalNanos)
            updateJitter(header, arrivalNanos: arrivalNanos)
        } else if delta == 0 {
            duplicates += 1
            verdict.duplicate = true
            updateJitter(header, arrivalNanos: arrivalNanos)
        } else {
            let extended = maxExtended + Int64(delta)
            if maxExtended - extended >= 4096 {
                // Older than the duplicate-detection window: a stale replay, not a packet filling a gap. Counting
                // it as received would hide real loss.
                outOfOrder += 1
                verdict.outOfOrder = true
            } else if isInHistory(extended) {
                duplicates += 1
                verdict.duplicate = true
                updateJitter(header, arrivalNanos: arrivalNanos)
            } else {
                outOfOrder += 1
                verdict.outOfOrder = true
                if extended < baseExtended { baseExtended = extended } else { removeOneLoss(near: arrivalNanos) }
                uniqueReceived += 1
                markHistory(extended)
                addReceived(at: arrivalNanos)
                updateJitter(header, arrivalNanos: arrivalNanos)
            }
        }
        return verdict
    }

    private mutating func markHistory(_ extended: Int64) {
        let slot = Int(extended & 4095)
        history[slot >> 6] |= 1 << UInt64(slot & 63)
        // Clear the slot that is about to be reused 2048 numbers ahead.
        let clear = Int((extended + 2048) & 4095)
        history[clear >> 6] &= ~(1 << UInt64(clear & 63))
    }

    private func isInHistory(_ extended: Int64) -> Bool {
        let slot = Int(extended & 4095)
        return history[slot >> 6] & (1 << UInt64(slot & 63)) != 0
    }

    private mutating func updateJitter(_ header: RTPHeader, arrivalNanos: Int64) {
        // Only the primary voice payload type participates (skip DTMF events and comfort noise).
        let codec = codec(for: header.payloadType)
        if primaryPayloadType == nil {
            if let kind = codec?.kind, kind == .telephoneEvent || kind == .comfortNoise { return }
            primaryPayloadType = header.payloadType
            if let rate = codec?.clockRate, rate > 0 { clockRate = Double(rate) }
            timestampBase = header.timestamp
            timestampExtended = 0
            lastTimestamp = header.timestamp
        }
        guard header.payloadType == primaryPayloadType, let clockRate else { return }
        timestampExtended += Int64(Int32(bitPattern: header.timestamp &- lastTimestamp))
        lastTimestamp = header.timestamp
        let arrivalUnits = Double(arrivalNanos &- firstArrival) / 1e9 * clockRate
        let transit = arrivalUnits - Double(timestampExtended)
        if let lastTransit {
            let d = abs(transit - lastTransit)
            jitter += (d - jitter) / 16
            jitterSum += jitter
            jitterSamples += 1
            if jitter > maxJitter {
                maxJitter = jitter
                maxJitterArrival = arrivalNanos
            }
            let bin = Self.bin(for: arrivalNanos, origin: firstArrival, width: Self.jitterBin)
            let ms = jitter / clockRate * 1000
            jitterBins.record(ms, bin: bin, limit: denseLimit)
        }
        lastTransit = transit
    }

    // MARK: Series helpers

    /// Bin of `time` relative to `origin`; capture timestamps are untrusted, so the difference wraps instead of
    /// trapping and packets earlier than the first one land in bin 0.
    static func bin(for time: Int64, origin: Int64, width: Double) -> Int {
        let seconds = Double(time &- origin) / 1e9
        guard seconds > 0 else { return 0 }
        return Int(seconds / width)  // ≤ 9.3e9 / width: always representable
    }

    private func lossBin(for arrival: Int64) -> Int {
        Self.bin(for: arrival, origin: firstArrival, width: Self.lossBin)
    }

    private mutating func addReceived(at arrival: Int64) {
        lossBins.addReceived(bin: lossBin(for: arrival), limit: denseLimit)
    }

    /// Places `count` lost packets evenly between the two surrounding arrivals. A gap spanning many bins (a long
    /// silence, or timestamps a crafted capture chose) is charged to the arrival's bin so one packet can never
    /// create thousands of bins.
    private mutating func distributeLoss(_ count: Int, from start: Int64, to end: Int64) {
        guard count > 0 else { return }
        if lossBin(for: end) - lossBin(for: start) > 8 {
            lossBins.addLoss(count, bin: lossBin(for: end), at: end, limit: denseLimit)
            return
        }
        let span = Double(max(0, end &- start))
        for k in 1...count {
            let t = start &+ Int64(span * (Double(k) / Double(count + 1)))
            lossBins.addLoss(1, bin: lossBin(for: t), at: t, limit: denseLimit)
        }
    }

    /// A late packet filled a gap: take one loss back from the closest preceding bin that has one.
    private mutating func removeOneLoss(near arrival: Int64) {
        var bin = lossBin(for: arrival)
        var steps = 0
        while bin >= 0 && steps < 5 {
            if lossBins.removeOneLoss(bin: bin) { return }
            bin -= 1
            steps += 1
        }
    }

    /// Dense series for persistence, merging `factor` bins into one when the stream is longer than
    /// `maxSeriesBins` bins.
    private func denseSeries() -> (jitterWidth: Double, jitter: [Double?], lossWidth: Double, lost: [Int], received: [Int]) {
        // Dense arrays grow with the time span, so they are also limited by how many bins hold data: a stream of a
        // few packets spread over years gets a handful of wide bins, not thousands of empty ones.
        func limit(_ occupied: Int) -> Int { min(Self.maxSeriesBins, max(256, occupied * 8)) }
        let jitterCount = (jitterBins.maxBin ?? -1) + 1
        let jitterLimit = limit(jitterBins.occupied)
        let jitterFactor = max(1, (jitterCount + jitterLimit - 1) / jitterLimit)
        var jitter = [Double?](repeating: nil, count: (jitterCount + jitterFactor - 1) / jitterFactor)
        jitterBins.forEach { bin, value in
            let merged = bin / jitterFactor
            jitter[merged] = max(jitter[merged] ?? value, value)
        }
        let occupiedLoss = lossBins.sortedBins()
        let lossCount = (occupiedLoss.last ?? -1) + 1
        let lossLimit = limit(occupiedLoss.count)
        let lossFactor = max(1, (lossCount + lossLimit - 1) / lossLimit)
        let size = (lossCount + lossFactor - 1) / lossFactor
        var lost = [Int](repeating: 0, count: size)
        var received = [Int](repeating: 0, count: size)
        for bin in occupiedLoss {
            let entry = lossBins.entry(bin)
            lost[bin / lossFactor] += entry.lost
            received[bin / lossFactor] += entry.received
        }
        return (Self.jitterBin * Double(jitterFactor), jitter, Self.lossBin * Double(lossFactor), lost, received)
    }

    // MARK: Finalisation

    /// Produces the persisted record. `id` and call linkage are assigned by the caller.
    public func makeRecord(id: Int) -> RTPStreamRecord {
        let pt = dominantPayloadType
        let codec = codec(for: pt)
        let rate = clockRate
        let meanJitter = rate.flatMap { r in jitterSamples > 0 ? jitterSum / Double(jitterSamples) / r * 1000 : nil }
        let maxJitterMs = rate.map { maxJitter / $0 * 1000 }
        let p = transitionsRR + transitionsRL > 0 ? Double(transitionsRL) / Double(transitionsRR + transitionsRL) : 0
        let q = transitionsLL + transitionsLR > 0 ? Double(transitionsLR) / Double(transitionsLL + transitionsLR) : 1
        let burstRatio = p + q > 0 && transitionsRL > 0 ? max(1, 1 / (p + q)) : 1
        let origin = Timestamp(nanoseconds: firstArrival)
        let dense = denseSeries()
        let series = StreamSeries(origin: origin, jitterBinSeconds: dense.jitterWidth, jitterMs: dense.jitter,
                                  lossBinSeconds: dense.lossWidth, lost: dense.lost, received: dense.received)
        let observedPtime: Double? = ptimeMs.map(Double.init) ?? {
            guard deltaCount > 0, duplicates + outOfOrder < packets / 2 else { return nil }
            let mean = deltaSum / Double(deltaCount)
            // Snap to the usual packetisation intervals when the arrival spacing is close to one.
            return [10.0, 20, 30, 40, 60].first { abs($0 - mean) < 2.5 }
        }()
        return RTPStreamRecord(
            id: id, ssrc: ssrc, source: source, destination: destination, payloadType: pt, codec: codec,
            ptimeMs: observedPtime,
            firstTime: origin, lastTime: Timestamp(nanoseconds: lastArrival), packetCount: packets,
            payloadBytes: payloadBytes, expectedPackets: expected, lostPackets: lost, duplicatePackets: duplicates,
            outOfOrderPackets: outOfOrder, sequenceGaps: sequenceGaps, markerPackets: markers,
            payloadTypeChanges: payloadTypeChanges, meanJitterMs: meanJitter, maxJitterMs: maxJitterMs,
            maxJitterTime: maxJitterMs != nil && maxJitter > 0 ? Timestamp(nanoseconds: maxJitterArrival) : nil,
            meanDeltaMs: deltaCount > 0 ? deltaSum / Double(deltaCount) : 0, maxDeltaMs: maxDelta,
            burstRatio: burstRatio, lossBursts: lossBursts(), series: series, negotiatedInSDP: negotiatedInSDP,
            replacesSSRC: replacesSSRC, payloadFormats: payloadFormats, secure: secure)
            .withSequenceRange(first: UInt16(truncatingIfNeeded: baseExtended), last: maxSequence,
                               cycles: Int((maxExtended >> 16) - (baseExtended >> 16)))
    }

    /// Periods where loss concentrates well above the stream's baseline: consecutive 1 s bins with ≥ 3 lost
    /// packets and a loss ratio ≥ max(10 %, 3 × overall loss), totalling at least 5 packets.
    func lossBursts() -> [LossBurst] {
        let baseline = expected > 0 ? Double(max(0, lost)) / Double(expected) : 0
        let threshold = max(0.10, 3 * baseline)
        var bursts: [LossBurst] = []
        var current: LossBurst?
        func close() {
            if let finished = current, finished.lostPackets >= 5 { bursts.append(finished) }
            current = nil
        }
        var previousBin = Int.min
        for bin in lossBins.sortedBins() {
            let entry = lossBins.entry(bin)
            if bin != previousBin &+ 1 { close() }  // an empty bin in between ends the burst
            previousBin = bin
            let total = entry.lost + entry.received
            let qualifies = entry.lost >= 3 && total > 0 && Double(entry.lost) / Double(total) >= threshold
            if qualifies, entry.firstLossTime != Int64.max {
                if var burst = current {
                    burst.end = Timestamp(nanoseconds: entry.lastLossTime)
                    burst.lostPackets += entry.lost
                    current = burst
                } else {
                    current = LossBurst(start: Timestamp(nanoseconds: entry.firstLossTime),
                                        end: Timestamp(nanoseconds: entry.lastLossTime), lostPackets: entry.lost)
                }
            } else {
                close()
            }
        }
        close()
        return bursts
    }
}

extension RTPStreamRecord {
    func withSequenceRange(first: UInt16, last: UInt16, cycles: Int) -> RTPStreamRecord {
        var copy = self
        copy.firstSequence = first
        copy.lastSequence = last
        copy.sequenceCycles = cycles
        return copy
    }
}

/// Maximum jitter (ms) per time bin: dense below the limit, sparse beyond it (see `RTPStreamAnalyzer.denseLimit`).
struct JitterBins: Sendable {
    /// −1 marks an empty bin.
    private var dense: [Float] = []
    /// Bins at or beyond `dense.count` (kept that way: growing `dense` moves them in).
    private var sparse: [Int: Double] = [:]
    private(set) var occupied = 0

    mutating func record(_ ms: Double, bin: Int, limit: Int) {
        if bin >= dense.count, bin < limit {
            dense.append(contentsOf: repeatElement(-1, count: bin + 1 - dense.count))
            for (key, value) in sparse where key < dense.count {
                dense[key] = Float(value)
                sparse[key] = nil
            }
        }
        if bin < dense.count {
            if dense[bin] < 0 { occupied += 1 }
            dense[bin] = max(dense[bin], Float(ms))
        } else {
            if sparse[bin] == nil { occupied += 1 }
            sparse[bin] = max(sparse[bin] ?? ms, ms)
        }
    }

    var maxBin: Int? {
        if let key = sparse.keys.max() { return key }
        return dense.lastIndex { $0 >= 0 }
    }

    func forEach(_ body: (Int, Double) -> Void) {
        for (bin, value) in dense.enumerated() where value >= 0 { body(bin, Double(value)) }
        for (bin, value) in sparse { body(bin, value) }
    }
}

/// Packets received and lost per time bin, with the time span of the losses (bins with loss only).
struct LossBins: Sendable {
    private var lost: [Int32] = []
    private var received: [Int32] = []
    private var lossTimes: [Int: (first: Int64, last: Int64)] = [:]
    private var sparse: [Int: (lost: Int, received: Int)] = [:]

    private mutating func grow(to bin: Int, limit: Int) {
        guard bin >= lost.count, bin < limit else { return }
        let extra = bin + 1 - lost.count
        lost.append(contentsOf: repeatElement(0, count: extra))
        received.append(contentsOf: repeatElement(0, count: extra))
        for (key, value) in sparse where key < lost.count {
            lost[key] = Int32(clamping: value.lost)
            received[key] = Int32(clamping: value.received)
            sparse[key] = nil
        }
    }

    mutating func addReceived(bin: Int, limit: Int) {
        grow(to: bin, limit: limit)
        if bin < received.count {
            received[bin] = received[bin] &+ 1
        } else {
            sparse[bin, default: (0, 0)].received += 1
        }
    }

    mutating func addLoss(_ count: Int, bin: Int, at time: Int64, limit: Int) {
        grow(to: bin, limit: limit)
        if bin < lost.count {
            lost[bin] = Int32(clamping: Int(lost[bin]) + count)
        } else {
            sparse[bin, default: (0, 0)].lost += count
        }
        let span = lossTimes[bin] ?? (Int64.max, Int64.min)
        lossTimes[bin] = (min(span.first, time), max(span.last, time))
    }

    /// Takes one loss back from `bin`; false when it has none.
    mutating func removeOneLoss(bin: Int) -> Bool {
        if bin < lost.count {
            guard lost[bin] > 0 else { return false }
            lost[bin] -= 1
            return true
        }
        guard let entry = sparse[bin], entry.lost > 0 else { return false }
        sparse[bin]?.lost -= 1
        return true
    }

    func entry(_ bin: Int) -> RTPStreamAnalyzer.LossBin {
        let times = lossTimes[bin] ?? (Int64.max, Int64.min)
        if bin < lost.count {
            return RTPStreamAnalyzer.LossBin(lost: Int(lost[bin]), received: Int(received[bin]), firstLossTime: times.first,
                                             lastLossTime: times.last)
        }
        let entry = sparse[bin] ?? (0, 0)
        return RTPStreamAnalyzer.LossBin(lost: entry.lost, received: entry.received, firstLossTime: times.first, lastLossTime: times.last)
    }

    /// Bins holding any packet or loss, ascending (dense ones all precede the sparse ones).
    func sortedBins() -> [Int] {
        var bins = lost.indices.filter { lost[$0] != 0 || received[$0] != 0 || lossTimes[$0] != nil }
        bins += sparse.keys.sorted()
        return bins
    }
}
