import Darwin
import Foundation

/// Stage measurements for `wpbench` (spec §59: indexing, packet lookup, filtering, flow reconstruction, SIP
/// reconstruction, RTP analysis). Each stage runs the production code on a real capture; decoding of the frames a
/// stage needs happens outside its timer, so the figure is the stage's own cost.
public enum EngineBenchmark {
    public struct Measurement: Codable, Sendable {
        public var stage: String
        public var seconds: Double
        /// Items processed (packets, messages, lookups…), described by `unit`.
        public var items: Int
        public var unit: String
        public var notes: String?

        public var perSecond: Double { seconds > 0 ? Double(items) / seconds : 0 }

        public init(stage: String, seconds: Double, items: Int, unit: String, notes: String? = nil) {
            self.stage = stage
            self.seconds = seconds
            self.items = items
            self.unit = unit
            self.notes = notes
        }
    }

    /// Physical memory attributed to this process (what Activity Monitor and jetsam count), in bytes.
    public static func memoryFootprint() -> UInt64 {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<natural_t>.size)
        let status = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        return status == KERN_SUCCESS ? info.phys_footprint : 0
    }

    static func seconds(_ duration: Duration) -> Double {
        Double(duration.components.seconds) + Double(duration.components.attoseconds) / 1e18
    }

    /// Visits every frame of the capture in batches, decoded in parallel as the engine does.
    static func forEachBatch(_ url: URL, _ body: ([DecodedFrame], CaptureFile) throws -> Void) async throws {
        let file = try CaptureFile(url: url)
        var reader = try CaptureReader(file: file)
        var frames: [CapturedFrame] = []
        frames.reserveCapacity(32_768)
        while try reader.readBatch(into: &frames, maxCount: 32_768) {
            try body(await FrameDecoding.decodeBatch(frames, file: file).flatMap { $0 }, file)
        }
    }

    /// Reading and decoding every frame (headers, application detection): the ceiling for any analysis.
    public static func decode(_ url: URL) async throws -> Measurement {
        let clock = ContinuousClock()
        var packets = 0
        let elapsed = try await clock.measure {
            try await forEachBatch(url) { batch, _ in packets += batch.count }
        }
        let size = (try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? Int64) ?? 0
        return Measurement(stage: "Read + decode", seconds: seconds(elapsed), items: packets, unit: "packets",
                           notes: String(format: "%.0f MB/s", Double(size) / 1e6 / max(seconds(elapsed), 1e-9)))
    }

    /// Bidirectional 5-tuple flows (`FlowTable`) for every packet.
    public static func flows(_ url: URL) async throws -> Measurement {
        let clock = ContinuousClock()
        var table = FlowTable()
        var packets = 0
        var total = Duration.zero
        try await forEachBatch(url) { batch, _ in
            total += clock.measure {
                for item in batch {
                    _ = table.assign(item.packet, frameNumber: item.frame.number, timestampNanos: item.frame.timestampNanos,
                                     length: item.frame.originalLength, protocolKind: .udp)
                }
            }
            packets += batch.count
        }
        return Measurement(stage: "Flow reconstruction", seconds: seconds(total), items: packets, unit: "packets",
                           notes: "\(table.flows.count) flows")
    }

    /// SIP parsing and transaction/dialog tracking (`SIPParser` + `SIPTracker`) for every SIP-over-UDP packet.
    public static func sip(_ url: URL) async throws -> Measurement {
        let clock = ContinuousClock()
        var tracker = SIPTracker()
        var messages = 0
        var total = Duration.zero
        try await forEachBatch(url) { batch, file in
            let sipFrames = batch.filter { if case .sip = $0.app { return true } else { return false } }
            total += clock.measure {
                for item in sipFrames {
                    let bytes = file.bytes(offset: item.frame.dataOffset, length: item.frame.capturedLength)
                    let payload = bytes.slice(item.packet.payloadOffset, item.packet.payloadLength)
                    guard let message = SIPParser.parse(payload), let source = item.packet.sourceEndpoint,
                          let destination = item.packet.destinationEndpoint else { continue }
                    _ = tracker.ingest(message, frameNumber: item.frame.number, time: Timestamp(nanoseconds: item.frame.timestampNanos),
                                       source: source, destination: destination, transport: .udp)
                    messages += 1
                }
            }
        }
        return Measurement(stage: "SIP reconstruction", seconds: seconds(total), items: messages, unit: "messages",
                           notes: "\(tracker.finalizedSessions().count) dialogs · \(tracker.transactions.count) transactions")
    }

    /// Per-SSRC RTP analysis (`RTPTracker`: sequence, loss, jitter, reordering) for every RTP packet.
    public static func rtp(_ url: URL) async throws -> Measurement {
        let clock = ContinuousClock()
        var tracker = RTPTracker()
        var packets = 0
        var total = Duration.zero
        try await forEachBatch(url) { batch, _ in
            let rtpFrames = batch.compactMap { item -> (RTPHeader, DecodedFrame)? in
                if case .rtp(let header) = item.app { return (header, item) }
                return nil
            }
            total += clock.measure {
                for (header, item) in rtpFrames {
                    guard let source = item.packet.sourceEndpoint, let destination = item.packet.destinationEndpoint else { continue }
                    _ = tracker.ingest(header, source: source, destination: destination, arrivalNanos: item.frame.timestampNanos) {
                        RTPNegotiation(codecs: [:], ptimeMs: 20)
                    }
                }
            }
            packets += rtpFrames.count
        }
        return Measurement(stage: "RTP analysis", seconds: seconds(total), items: packets, unit: "packets",
                           notes: "\(tracker.streamCount) streams")
    }
}
