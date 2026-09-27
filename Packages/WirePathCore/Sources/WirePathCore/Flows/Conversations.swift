import Foundation

/// Traffic between two IP addresses, across every protocol and port (Wireshark's IPv4/IPv6 conversations).
public struct IPConversation: Sendable, Hashable, Identifiable {
    public var addressA: IPAddress
    public var addressB: IPAddress
    public var packetsAToB: Int
    public var packetsBToA: Int
    public var bytesAToB: Int64
    public var bytesBToA: Int64
    public var firstTime: Timestamp
    public var lastTime: Timestamp
    /// Flow indices making up the conversation.
    public var flows: [Int]

    public var id: String { "\(addressA)-\(addressB)" }
    public var packets: Int { packetsAToB + packetsBToA }
    public var bytes: Int64 { bytesAToB + bytesBToA }
}

/// Traffic sent and received by one IP address.
public struct EndpointTraffic: Sendable, Hashable, Identifiable {
    public var address: IPAddress
    public var packetsSent: Int
    public var packetsReceived: Int
    public var bytesSent: Int64
    public var bytesReceived: Int64
    public var flows: Int

    public var id: IPAddress { address }
    public var packets: Int { packetsSent + packetsReceived }
    public var bytes: Int64 { bytesSent + bytesReceived }
}

/// Aggregations built from flows (no packet is read again).
public enum Conversations {
    /// IP conversations, busiest first. Address A is the lower address, so direction labels are stable.
    public static func ip(_ flows: [FlowRecord]) -> [IPConversation] {
        var table: [[IPAddress]: IPConversation] = [:]
        for flow in flows {
            let (a, b) = flow.initiator.address <= flow.responder.address
                ? (flow.initiator, flow.responder) : (flow.responder, flow.initiator)
            let aIsInitiator = a == flow.initiator
            var entry = table[[a.address, b.address]] ?? IPConversation(
                addressA: a.address, addressB: b.address, packetsAToB: 0, packetsBToA: 0, bytesAToB: 0, bytesBToA: 0,
                firstTime: flow.firstTime, lastTime: flow.lastTime, flows: [])
            entry.packetsAToB += aIsInitiator ? flow.packetsFromInitiator : flow.packetsFromResponder
            entry.packetsBToA += aIsInitiator ? flow.packetsFromResponder : flow.packetsFromInitiator
            entry.bytesAToB += aIsInitiator ? flow.bytesFromInitiator : flow.bytesFromResponder
            entry.bytesBToA += aIsInitiator ? flow.bytesFromResponder : flow.bytesFromInitiator
            entry.firstTime = min(entry.firstTime, flow.firstTime)
            entry.lastTime = max(entry.lastTime, flow.lastTime)
            entry.flows.append(flow.id)
            table[[a.address, b.address]] = entry
        }
        return table.values.sorted { $0.bytes != $1.bytes ? $0.bytes > $1.bytes : $0.id < $1.id }
    }

    /// Per-address totals, busiest first.
    public static func endpoints(_ flows: [FlowRecord]) -> [EndpointTraffic] {
        var table: [IPAddress: EndpointTraffic] = [:]
        func update(_ address: IPAddress, sent: Int, received: Int, bytesSent: Int64, bytesReceived: Int64) {
            var entry = table[address] ?? EndpointTraffic(address: address, packetsSent: 0, packetsReceived: 0, bytesSent: 0,
                                                          bytesReceived: 0, flows: 0)
            entry.packetsSent += sent
            entry.packetsReceived += received
            entry.bytesSent += bytesSent
            entry.bytesReceived += bytesReceived
            entry.flows += 1
            table[address] = entry
        }
        for flow in flows {
            update(flow.initiator.address, sent: flow.packetsFromInitiator, received: flow.packetsFromResponder,
                   bytesSent: flow.bytesFromInitiator, bytesReceived: flow.bytesFromResponder)
            if flow.responder.address != flow.initiator.address {
                update(flow.responder.address, sent: flow.packetsFromResponder, received: flow.packetsFromInitiator,
                       bytesSent: flow.bytesFromResponder, bytesReceived: flow.bytesFromInitiator)
            }
        }
        return table.values.sorted { $0.bytes != $1.bytes ? $0.bytes > $1.bytes : $0.address < $1.address }
    }
}
