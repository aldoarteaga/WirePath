import Foundation

/// `a=rtpmap:<pt> <encoding>/<clock>[/<channels>]`
public struct RTPMap: Sendable, Hashable {
    public var payloadType: UInt8
    public var encodingName: String
    public var clockRate: Int?
    public var channels: Int?
}

/// An ICE candidate from SDP (`a=candidate:`, RFC 8839).
public struct ICECandidate: Codable, Sendable, Hashable {
    public enum Kind: String, Codable, Sendable {
        case host, srflx, prflx, relay

        public var label: String {
            switch self {
            case .host: return String(localized: "Host", bundle: CoreLocalization.bundle)
            case .srflx: return String(localized: "Server Reflexive", bundle: CoreLocalization.bundle)
            case .prflx: return String(localized: "Peer Reflexive", bundle: CoreLocalization.bundle)
            case .relay: return String(localized: "Relay", bundle: CoreLocalization.bundle)
            }
        }
    }

    public var foundation: String
    public var component: Int
    /// "udp" or "tcp".
    public var transport: String
    public var priority: UInt32
    public var address: String
    public var port: UInt16
    public var kind: Kind
    public var relatedAddress: String?
    public var relatedPort: UInt16?

    /// Parses the value of an `a=candidate:` line.
    public static func parse(_ value: Substring) -> ICECandidate? {
        let parts = value.split(separator: " ", omittingEmptySubsequences: true)
        guard parts.count >= 8, parts[6].lowercased() == "typ", let component = Int(parts[1]), let priority = UInt32(parts[3]),
              let port = UInt16(parts[5]), let kind = Kind(rawValue: parts[7].lowercased()) else { return nil }
        var candidate = ICECandidate(foundation: String(parts[0].prefix(32)), component: component, transport: parts[2].lowercased(),
                                     priority: priority, address: String(parts[4].prefix(64)), port: port, kind: kind)
        var index = 8
        while index + 1 < parts.count, index < 32 {
            switch parts[index].lowercased() {
            case "raddr": candidate.relatedAddress = String(parts[index + 1].prefix(64))
            case "rport": candidate.relatedPort = UInt16(parts[index + 1])
            default: break
            }
            index += 2
        }
        return candidate
    }
}

/// ICE and DTLS-SRTP attributes of a WebRTC-style offer/answer (session or media level).
public struct ICEParameters: Sendable, Hashable {
    public var ufrag: String?
    public var candidates: [ICECandidate] = []
    /// `a=fingerprint:` hash function (e.g. "sha-256"); the fingerprint value itself is not needed.
    public var fingerprintAlgorithm: String?
    /// DTLS role: actpass, active or passive.
    public var setup: String?
    public var iceLite = false

    public var isEmpty: Bool { ufrag == nil && candidates.isEmpty && fingerprintAlgorithm == nil }

    /// At most this many candidates are kept per section.
    public static let maxCandidates = 64
}

/// One `m=` section of an SDP body.
public struct MediaDescription: Sendable, Hashable {
    public var mediaType: String
    public var port: UInt16
    public var portCount: Int
    public var transportProtocol: String
    public var formats: [String]
    /// Media-level `c=` address, if present.
    public var connectionAddress: String?
    public var rtpMaps: [UInt8: RTPMap]
    public var fmtp: [UInt8: String]
    public var ptimeMs: Int?
    public var direction: MediaDirection?
    public var rtcpPort: UInt16?
    public var ice = ICEParameters()
    public var mid: String?
    public var rtcpMux = false

    /// Numeric payload types from the format list (RTP profiles only).
    public var payloadTypes: [UInt8] { formats.compactMap { UInt8($0) } }
}

public enum MediaDirection: String, Sendable, Hashable {
    case sendrecv, sendonly, recvonly, inactive
}

/// A parsed Session Description Protocol body (RFC 8866).
public struct SessionDescription: Sendable, Hashable {
    public var version: Int?
    public var origin: String?
    public var originAddress: String?
    public var sessionName: String?
    /// Session-level `c=` address.
    public var connectionAddress: String?
    public var direction: MediaDirection?
    public var media: [MediaDescription]
    /// Session-level ICE / DTLS attributes (media sections may override them).
    public var ice = ICEParameters()
    /// `a=group:BUNDLE` media identifiers.
    public var bundle: [String] = []

    /// ICE parameters in effect for a media section.
    public func effectiveICE(for media: MediaDescription) -> ICEParameters {
        var result = media.ice
        if result.ufrag == nil { result.ufrag = ice.ufrag }
        if result.fingerprintAlgorithm == nil { result.fingerprintAlgorithm = ice.fingerprintAlgorithm }
        if result.setup == nil { result.setup = ice.setup }
        result.iceLite = result.iceLite || ice.iceLite
        if result.candidates.isEmpty { result.candidates = ice.candidates }
        return result
    }

    /// True when the description negotiates ICE (a WebRTC-style session).
    public var usesICE: Bool { !ice.isEmpty || media.contains { !$0.ice.isEmpty } }

    /// Connection address in effect for a media section (media-level overrides session-level).
    public func effectiveAddress(for media: MediaDescription) -> String? {
        media.connectionAddress ?? connectionAddress
    }

    /// Direction in effect for a media section (media-level overrides session-level; default sendrecv).
    public func effectiveDirection(for media: MediaDescription) -> MediaDirection {
        media.direction ?? direction ?? .sendrecv
    }
}

public enum SDPParser {
    public static let maxMediaSections = 32
    public static let maxFormatsPerMedia = 64

    /// Parses an SDP body. Returns nil when the text does not look like SDP (no `v=` or `m=` lines).
    public static func parse(_ text: String) -> SessionDescription? {
        var description = SessionDescription(media: [])
        var current: MediaDescription?
        var sawSDPLine = false

        func flushMedia() {
            if let m = current { description.media.append(m) }
            current = nil
        }

        for rawLine in text.split(omittingEmptySubsequences: true, whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard line.count >= 2, line[line.index(after: line.startIndex)] == "=", let type = line.first else { continue }
            let value = String(line.dropFirst(2))
            switch type {
            case "v":
                sawSDPLine = true
                description.version = Int(value)
            case "o":
                description.origin = value
                let parts = value.split(separator: " ")
                if parts.count >= 6 { description.originAddress = String(parts[5]) }
            case "s":
                description.sessionName = value
            case "c":
                let parts = value.split(separator: " ")
                guard parts.count >= 3 else { break }
                // Strip TTL / address count suffixes of multicast addresses ("224.2.1.1/127").
                let address = String(parts[2].split(separator: "/").first ?? parts[2])
                if current != nil { current?.connectionAddress = address } else { description.connectionAddress = address }
            case "m":
                sawSDPLine = true
                flushMedia()
                // Real offers carry a few media sections; more is not a session description worth keeping.
                guard description.media.count < Self.maxMediaSections else { break }
                let parts = value.split(separator: " ")
                guard parts.count >= 3 else { break }
                let portParts = parts[1].split(separator: "/")
                current = MediaDescription(
                    mediaType: String(parts[0]),
                    port: UInt16(portParts.first ?? "") ?? 0,
                    portCount: portParts.count > 1 ? Int(portParts[1]) ?? 1 : 1,
                    transportProtocol: String(parts[2]),
                    formats: parts.dropFirst(3).prefix(Self.maxFormatsPerMedia).map(String.init),
                    connectionAddress: nil, rtpMaps: [:], fmtp: [:], ptimeMs: nil, direction: nil, rtcpPort: nil)
            case "a":
                parseAttribute(value, media: &current, session: &description)
            default:
                continue
            }
        }
        flushMedia()
        guard sawSDPLine else { return nil }
        return description
    }

    private static func parseAttribute(_ value: String, media: inout MediaDescription?, session: inout SessionDescription) {
        let name: Substring
        let argument: Substring
        if let colon = value.firstIndex(of: ":") {
            name = value[..<colon]
            argument = value[value.index(after: colon)...]
        } else {
            name = Substring(value)
            argument = ""
        }
        if let direction = MediaDirection(rawValue: String(name)) {
            if media != nil { media?.direction = direction } else { session.direction = direction }
            return
        }
        // ICE / DTLS attributes may appear at session or media level.
        func updateICE(_ body: (inout ICEParameters) -> Void) {
            if var current = media {
                body(&current.ice)
                media = current
            } else {
                body(&session.ice)
            }
        }
        switch name {
        case "ice-ufrag":
            updateICE { $0.ufrag = String(argument.trimmingCharacters(in: .whitespaces).prefix(256)) }
            return
        case "ice-pwd":
            return  // a credential: never kept
        case "ice-lite":
            updateICE { $0.iceLite = true }
            return
        case "candidate":
            if let candidate = ICECandidate.parse(argument) {
                updateICE { if $0.candidates.count < ICEParameters.maxCandidates { $0.candidates.append(candidate) } }
            }
            return
        case "fingerprint":
            updateICE { $0.fingerprintAlgorithm = argument.split(separator: " ").first.map { String($0.prefix(16)).lowercased() } }
            return
        case "setup":
            updateICE { $0.setup = String(argument.trimmingCharacters(in: .whitespaces).prefix(16)) }
            return
        case "group":
            let parts = argument.split(separator: " ")
            if parts.first?.uppercased() == "BUNDLE" { session.bundle = parts.dropFirst().prefix(32).map(String.init) }
            return
        default:
            break
        }
        // The remaining attributes only describe a media section.
        guard var current = media else { return }
        defer { media = current }
        switch name {
        case "rtpmap":
            let parts = argument.split(separator: " ", maxSplits: 1)
            guard parts.count == 2, let pt = UInt8(parts[0]) else { return }
            let encoding = parts[1].split(separator: "/")
            guard let encodingName = encoding.first else { return }
            current.rtpMaps[pt] = RTPMap(payloadType: pt, encodingName: String(encodingName),
                                         clockRate: encoding.count > 1 ? Int(encoding[1]) : nil,
                                         channels: encoding.count > 2 ? Int(encoding[2]) : nil)
        case "fmtp":
            let parts = argument.split(separator: " ", maxSplits: 1)
            guard parts.count == 2, let pt = UInt8(parts[0]) else { return }
            current.fmtp[pt] = String(parts[1].prefix(512))
        case "ptime":
            // Packetization times beyond a second are not real media; also keeps Int(ms) from trapping on nan/inf.
            if let ms = Double(argument.trimmingCharacters(in: .whitespaces)), ms.isFinite, (1...1_000).contains(ms) {
                current.ptimeMs = Int(ms)
            }
        case "rtcp":
            current.rtcpPort = UInt16(argument.split(separator: " ").first ?? "")
        case "rtcp-mux":
            current.rtcpMux = true
        case "mid":
            current.mid = String(argument.prefix(64))
        default:
            return
        }
    }
}
