import Foundation

/// What a search text was understood as. One text can mean several things ("5060" is a port and a packet number),
/// and every interpretation is searched.
public enum SearchCriterion: Sendable, Equatable {
    case packetNumber(Int)
    case port(UInt16)
    case address(IPAddress)
    case ssrc(UInt32)
    case protocolName(PacketProtocol)
    /// Matched against SIP Call-IDs, URIs, users and display names.
    case sipText(String)
    /// Matched against packet bytes (ASCII, case-insensitive).
    case payloadText(String)

    public var label: String {
        switch self {
        case .packetNumber: return String(localized: "Packet number", bundle: CoreLocalization.bundle)
        case .port: return String(localized: "Port", bundle: CoreLocalization.bundle)
        case .address: return String(localized: "IP address", bundle: CoreLocalization.bundle)
        case .ssrc: return String(localized: "RTP SSRC", bundle: CoreLocalization.bundle)
        case .protocolName: return String(localized: "Protocol", bundle: CoreLocalization.bundle)
        case .sipText: return String(localized: "SIP Call-ID / URI", bundle: CoreLocalization.bundle)
        case .payloadText: return String(localized: "Payload text", bundle: CoreLocalization.bundle)
        }
    }
}

public struct SearchHit: Sendable, Hashable {
    /// 0-based packet position.
    public var position: Int
    /// Why it matched (the criterion's label).
    public var reason: String
}

public struct SearchResults: Sendable {
    public var criteria: [SearchCriterion]
    public var hits: [SearchHit]
    /// True when the hit limit stopped the search early.
    public var truncated: Bool
    /// True when the search was cancelled before scanning every packet.
    public var cancelled: Bool
}

/// Finds packets by IP, port, packet number, Call-ID, SIP URI, SSRC, protocol or payload text, scanning the
/// memory-mapped index (and bytes, for text) off the main actor. Cancellable via Task cancellation.
public enum PacketSearch {
    public static let maxHits = 100_000
    /// Payload text is searched in the first bytes of each packet only, bounding the cost of a full scan.
    public static let maxBytesScannedPerPacket = 16_384

    /// Every interpretation of `text`, most specific first.
    public static func criteria(for text: String) -> [SearchCriterion] {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.count <= 512 else { return [] }
        var result: [SearchCriterion] = []
        let lower = trimmed.lowercased()
        let numberText = trimmed.hasPrefix("#") ? String(trimmed.dropFirst()) : trimmed
        if let number = Int(numberText), number > 0 {
            result.append(.packetNumber(number))
            if !trimmed.hasPrefix("#"), let port = UInt16(exactly: number) { result.append(.port(port)) }
            if !trimmed.hasPrefix("#"), let ssrc = UInt32(exactly: number), number > 65_535 { result.append(.ssrc(ssrc)) }
        }
        if lower.hasPrefix("0x"), let ssrc = UInt32(lower.dropFirst(2), radix: 16) { result.append(.ssrc(ssrc)) }
        if let address = IPAddress(trimmed) { result.append(.address(address)) }
        if let kind = PacketProtocol.allCases.first(where: { $0 != .unknown && $0.displayName.lowercased() == lower }) {
            result.append(.protocolName(kind))
        }
        if result.isEmpty || trimmed.contains("@") || lower.hasPrefix("sip:") || lower.hasPrefix("sips:") || lower.hasPrefix("tel:") {
            result.append(.sipText(trimmed))
        }
        if trimmed.count >= 3, result.allSatisfy({ if case .packetNumber = $0 { return false }; return true }) {
            result.append(.payloadText(trimmed))
        }
        return result
    }

    /// Runs every interpretation of `text` over the packets of `store`.
    public static func run(_ text: String, in store: PacketStore, result: AnalysisResult,
                           progress: @Sendable (Double) -> Void = { _ in }) async -> SearchResults {
        let criteria = criteria(for: text)
        var hits: [SearchHit] = []
        guard !criteria.isEmpty, store.count > 0 else {
            return SearchResults(criteria: criteria, hits: [], truncated: false, cancelled: false)
        }
        // Precompute what can be answered from lookup tables.
        var addressIDs: Set<UInt32> = []
        var ssrcStreams: Set<Int32> = []
        var sipMessages: Set<UInt32> = []
        var needle: [UInt8] = []
        for criterion in criteria {
            switch criterion {
            case .address(let address):
                for id in 1..<max(1, store.addressCount) where store.address(UInt32(id)) == address { addressIDs.insert(UInt32(id)) }
            case .ssrc(let ssrc):
                for (index, stream) in result.streams.enumerated() where stream.ssrc == ssrc { ssrcStreams.insert(Int32(index)) }
            case .sipText(let text):
                for (index, message) in result.sipMessages.enumerated() where Self.sipMatches(message, text) {
                    sipMessages.insert(UInt32(index))
                }
            case .payloadText(let text):
                needle = Array(text.lowercased().utf8)
            default:
                break
            }
        }
        var truncated = false
        for position in 0..<store.count {
            if position & 0x3FFF == 0 {
                if Task.isCancelled { return SearchResults(criteria: criteria, hits: hits, truncated: false, cancelled: true) }
                progress(Double(position) / Double(store.count))
            }
            let record = store.record(at: position)
            var reason: SearchCriterion?
            for criterion in criteria {
                switch criterion {
                case .packetNumber(let number): if number == position + 1 { reason = criterion }
                case .port(let port):
                    if record.sourcePort == port || record.destinationPort == port, record.sourcePort != 0 || record.destinationPort != 0 {
                        reason = criterion
                    }
                case .address:
                    if addressIDs.contains(record.sourceAddress) || addressIDs.contains(record.destinationAddress) { reason = criterion }
                case .ssrc: if ssrcStreams.contains(record.streamIndex) { reason = criterion }
                case .protocolName(let kind):
                    if record.protocolKind == kind || (kind == .sip && record.protocolKind == .sipSDP) { reason = criterion }
                case .sipText: if record.protocolKind.isSIP, sipMessages.contains(record.aux) { reason = criterion }
                case .payloadText:
                    if !needle.isEmpty, store.withBytes(at: position, limit: maxBytesScannedPerPacket, { Self.contains($0, needle) }) {
                        reason = criterion
                    }
                }
                if reason != nil { break }
            }
            if let reason {
                hits.append(SearchHit(position: position, reason: reason.label))
                if hits.count >= maxHits {
                    truncated = true
                    break
                }
            }
        }
        progress(1)
        return SearchResults(criteria: criteria, hits: hits, truncated: truncated, cancelled: false)
    }

    static func sipMatches(_ message: SIPMessageRecord, _ text: String) -> Bool {
        let fields = [message.callID, message.from.uri, message.to.uri, message.from.user ?? "", message.to.user ?? "",
                      message.from.displayName ?? "", message.to.displayName ?? "", message.requestURI ?? "", message.contact ?? ""]
        return fields.contains { $0.range(of: text, options: .caseInsensitive) != nil }
    }

    /// Case-insensitive (ASCII) substring search; `needle` must already be lowercased.
    static func contains(_ haystack: UnsafeRawBufferPointer, _ needle: [UInt8]) -> Bool {
        guard !needle.isEmpty, haystack.count >= needle.count else { return false }
        let first = needle[0]
        let last = haystack.count - needle.count
        var i = 0
        while i <= last {
            if lower(haystack[i]) == first {
                var j = 1
                while j < needle.count, lower(haystack[i + j]) == needle[j] { j += 1 }
                if j == needle.count { return true }
            }
            i += 1
        }
        return false
    }

    @inline(__always) static func lower(_ byte: UInt8) -> UInt8 { byte >= 0x41 && byte <= 0x5A ? byte | 0x20 : byte }
}
