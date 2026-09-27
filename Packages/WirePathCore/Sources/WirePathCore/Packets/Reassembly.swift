import Foundation

/// Reassembles fragmented IPv4/IPv6 datagrams (needed for large SIP INVITEs over UDP).
public struct IPFragmentReassembler: Sendable {
    public struct Key: Hashable, Sendable {
        var source: IPAddress
        var destination: IPAddress
        var identification: UInt32
        var ipProtocol: UInt8
    }

    /// A reassembled upper-layer payload (the UDP/TCP header followed by its data).
    public struct Datagram: Sendable {
        public var bytes: Data
        public var ipProtocol: UInt8
        public var source: IPAddress
        public var destination: IPAddress
        /// Frame numbers of every fragment, in arrival order.
        public var frameNumbers: [Int]
    }

    private struct Pending {
        var pieces: [(offset: Int, data: Data)] = []
        var offsets: Set<Int> = []
        var bytes = 0
        var totalLength: Int?
        var firstSeenNanos: Int64
        var frames: [Int] = []
    }

    /// Bounds that keep a crafted capture from growing reassembly state without limit.
    public static let maxPendingDatagrams = 1_024
    public static let maxPiecesPerDatagram = 1_024

    private var pending: [Key: Pending] = [:]
    /// Keys in arrival order, for evicting the oldest datagrams when too many are incomplete.
    private var arrivalOrder: [Key] = []
    private var orderHead = 0
    public let timeoutNanos: Int64
    public let maxDatagramSize: Int

    public init(timeoutSeconds: Double = 30, maxDatagramSize: Int = 65_535 + 64) {
        timeoutNanos = Int64(timeoutSeconds * 1e9)
        self.maxDatagramSize = maxDatagramSize
    }

    /// Adds the fragment carried by `packet` (bytes are the whole frame). Returns the datagram once complete.
    public mutating func add(frame bytes: UnsafeRawBufferPointer, packet: DecodedPacket, frameNumber: Int,
                             timestampNanos: Int64) -> Datagram? {
        guard let fragment = packet.fragment, let source = packet.source, let destination = packet.destination else {
            return nil
        }
        let key = Key(source: source, destination: destination, identification: fragment.identification,
                      ipProtocol: packet.ipProtocol)
        // Fragment data starts at the transport header position (payloadOffset for fragments).
        let dataStart = fragment.offset == 0 && packet.transportOffset > 0 ? packet.transportOffset : packet.payloadOffset
        let dataEnd = min(packet.networkEnd, bytes.count)
        guard dataStart >= 0, dataEnd > dataStart else { return nil }
        let data = Data(bytes.slice(dataStart, dataEnd - dataStart))

        var entry: Pending
        if let existing = pending[key] {
            entry = existing
        } else {
            entry = Pending(firstSeenNanos: timestampNanos)
            arrivalOrder.append(key)
        }
        // A repeated offset is a retransmitted fragment: keep the first copy.
        guard entry.offsets.insert(fragment.offset).inserted else { return nil }
        entry.pieces.append((fragment.offset, data))
        entry.bytes += data.count
        entry.frames.append(frameNumber)
        if !fragment.moreFragments { entry.totalLength = fragment.offset + data.count }

        if entry.bytes > maxDatagramSize || entry.pieces.count > Self.maxPiecesPerDatagram
            || (entry.totalLength ?? 0) > maxDatagramSize {
            pending[key] = nil  // not a real datagram: stop collecting it
            return nil
        }
        // Only try to assemble once enough bytes arrived to possibly cover the datagram.
        if let total = entry.totalLength, entry.bytes >= total {
            let sorted = entry.pieces.sorted { $0.offset < $1.offset }
            var covered = 0
            for piece in sorted where piece.offset <= covered {
                covered = max(covered, piece.offset + piece.data.count)
            }
            if covered >= total {
                var assembled = Data(count: total)
                for piece in sorted {
                    let length = min(piece.data.count, total - piece.offset)
                    guard length > 0 else { continue }
                    assembled.replaceSubrange(piece.offset..<(piece.offset + length), with: piece.data.prefix(length))
                }
                pending[key] = nil
                return Datagram(bytes: assembled, ipProtocol: packet.ipProtocol, source: source,
                                destination: destination, frameNumbers: entry.frames)
            }
        }
        pending[key] = entry
        if pending.count > 256 { expire(now: timestampNanos) }
        evictOldest()
        return nil
    }

    /// Drops datagrams whose first fragment is older than the timeout.
    public mutating func expire(now: Int64) {
        let limit = Double(timeoutNanos) / 1e9
        let current = Timestamp(nanoseconds: now)
        pending = pending.filter { current.seconds(since: Timestamp(nanoseconds: $0.value.firstSeenNanos)) < limit }
    }

    private mutating func evictOldest() {
        while pending.count > Self.maxPendingDatagrams, orderHead < arrivalOrder.count {
            pending[arrivalOrder[orderHead]] = nil
            orderHead += 1
        }
        if orderHead > 4_096, orderHead * 2 > arrivalOrder.count {
            arrivalOrder.removeFirst(orderHead)
            orderHead = 0
        }
        if arrivalOrder.count > Self.maxPendingDatagrams * 8 {
            // Completed datagrams leave stale keys behind; rebuild from what is still pending.
            arrivalOrder = arrivalOrder[orderHead...].filter { pending[$0] != nil }
            orderHead = 0
        }
    }
}

/// Delivers in-order TCP payload bytes per direction, dropping retransmissions and resetting on gaps.
public struct TCPStreamAssembler: Sendable {
    public struct FlowKey: Hashable, Sendable {
        public var source: Endpoint
        public var destination: Endpoint
        public init(source: Endpoint, destination: Endpoint) {
            self.source = source
            self.destination = destination
        }
    }

    private var nextSequence: [FlowKey: UInt32] = [:]

    public init() {}

    public enum Delivery: Sendable {
        /// New in-order bytes (possibly trimmed of already-seen data).
        case data(Data)
        /// A gap was detected; buffered data for this flow must be discarded before using `Data`.
        case gap(Data)
        case duplicate
    }

    /// Feeds one segment. `payload` must be the TCP payload only.
    public mutating func add(flow: FlowKey, sequence: UInt32, flags: UInt8, payload: UnsafeRawBufferPointer) -> Delivery {
        let syn = flags & 0x02 != 0
        let fin = flags & 0x01 != 0
        let rst = flags & 0x04 != 0
        defer { if rst { nextSequence[flow] = nil } }
        if syn {
            nextSequence[flow] = sequence &+ 1
            return payload.isEmpty ? .duplicate : .data(Data(payload))
        }
        guard !payload.isEmpty else {
            if fin, let expected = nextSequence[flow], expected == sequence { nextSequence[flow] = sequence &+ 1 }
            return .duplicate
        }
        let length = UInt32(payload.count)
        guard let expected = nextSequence[flow] else {
            nextSequence[flow] = sequence &+ length
            return .gap(Data(payload))
        }
        let delta = Int32(bitPattern: sequence &- expected)
        if delta == 0 {
            nextSequence[flow] = sequence &+ length
            return .data(Data(payload))
        }
        if delta < 0 {
            // Retransmission, possibly partially overlapping new data.
            let overlap = Int(delta.magnitude)  // Int32.min has no positive Int32 counterpart
            guard overlap < payload.count else { return .duplicate }
            nextSequence[flow] = sequence &+ length
            return .data(Data(UnsafeRawBufferPointer(rebasing: payload[overlap...])))
        }
        // Missing segment(s): resynchronise on this one.
        nextSequence[flow] = sequence &+ length
        return .gap(Data(payload))
    }
}
