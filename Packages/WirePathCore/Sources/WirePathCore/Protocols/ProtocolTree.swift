import Foundation

public struct ProtocolField: Sendable, Hashable, Identifiable {
    public var id: Int
    public var name: String
    public var value: String
    /// Byte range inside the frame, when the field maps to captured bytes.
    public var range: Range<Int>?
    /// Nesting below the layer (0 = direct field; 1 = e.g. a DNS answer's data, a TLS extension's value).
    public var level: Int

    public init(id: Int, name: String, value: String, range: Range<Int>? = nil, level: Int = 0) {
        self.id = id
        self.name = name
        self.value = value
        self.range = range
        self.level = level
    }
}

public struct ProtocolLayer: Sendable, Hashable, Identifiable {
    public var id: Int
    /// Registry name of the dissector that produced it ("eth", "ip", "dns"…).
    public var protocolName: String
    public var name: String
    public var summary: String
    public var range: Range<Int>?
    public var fields: [ProtocolField]
}

/// The protocol tree of one packet, as shown in the Packet Inspector.
public struct DissectedPacket: Sendable {
    public var frameNumber: Int
    public var bytes: Data
    public var layers: [ProtocolLayer]
    /// Short description such as "SIP INVITE" or "DNS Standard query 0x1200 A pbx.office.lan".
    public var summary: String
    /// Set when a header was truncated or invalid; the layers decoded before it are still listed.
    public var problem: DecodeProblem?

    public init(frameNumber: Int, bytes: Data, layers: [ProtocolLayer], summary: String, problem: DecodeProblem? = nil) {
        self.frameNumber = frameNumber
        self.bytes = bytes
        self.layers = layers
        self.summary = summary
        self.problem = problem
    }

    public func layer(_ protocolName: String) -> ProtocolLayer? { layers.first { $0.protocolName == protocolName } }
}

/// Accumulates layers and fields while dissectors walk a frame. Bounded so a crafted packet (thousands of DNS
/// records, TLS extensions, STUN attributes) cannot produce an unbounded tree.
public struct ProtocolTreeBuilder: Sendable {
    public static let maxFields = 2_000
    public private(set) var layers: [ProtocolLayer] = []
    private var nextID = 0
    private var fieldCount = 0
    public private(set) var truncatedTree = false

    public init() {}

    public mutating func layer(_ protocolName: String, _ name: String, _ summary: String = "", range: Range<Int>?) {
        layers.append(ProtocolLayer(id: nextID, protocolName: protocolName, name: name, summary: summary, range: range, fields: []))
        nextID += 1
    }

    /// Updates the summary of the current layer (known only after its fields are parsed).
    public mutating func setSummary(_ summary: String) {
        guard !layers.isEmpty else { return }
        layers[layers.count - 1].summary = summary
    }

    public mutating func setRange(_ range: Range<Int>) {
        guard !layers.isEmpty else { return }
        layers[layers.count - 1].range = range
    }

    public mutating func field(_ name: String, _ value: String, _ range: Range<Int>? = nil, level: Int = 0) {
        guard !layers.isEmpty else { return }
        guard fieldCount < Self.maxFields else {
            truncatedTree = true
            return
        }
        fieldCount += 1
        layers[layers.count - 1].fields.append(ProtocolField(id: nextID, name: name, value: value, range: range, level: level))
        nextID += 1
    }
}
