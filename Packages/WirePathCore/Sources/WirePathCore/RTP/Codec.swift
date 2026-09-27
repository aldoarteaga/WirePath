import Foundation

/// Audio/video codecs WirePath knows how to label. Unknown encodings keep their SDP name.
public enum CodecKind: String, Codable, Sendable, CaseIterable {
    case pcmu, pcma, g729, g723, g722, g728, g726, gsm, ilbc, opus, speex, amr, amrWB, g7221, l16
    case telephoneEvent, comfortNoise, video, unknown

    /// Label used in tables ("G.711 µ", "G.729", …).
    public var displayName: String {
        switch self {
        case .pcmu: return "G.711 µ"
        case .pcma: return "G.711 a"
        case .g729: return "G.729"
        case .g723: return "G.723.1"
        case .g722: return "G.722"
        case .g728: return "G.728"
        case .g726: return "G.726"
        case .gsm: return "GSM"
        case .ilbc: return "iLBC"
        case .opus: return "Opus"
        case .speex: return "Speex"
        case .amr: return "AMR"
        case .amrWB: return "AMR-WB"
        case .g7221: return "G.722.1"
        case .l16: return "L16"
        case .telephoneEvent: return "DTMF"
        case .comfortNoise: return "CN"
        case .video: return "Video"
        case .unknown: return "Unknown"
        }
    }

    /// Family label used for codec chips on the Overview ("G.711" groups µ-law and A-law).
    public var familyName: String {
        switch self {
        case .pcmu, .pcma: return "G.711"
        default: return displayName
        }
    }

    /// Whether this payload carries voice (as opposed to DTMF events or comfort noise).
    public var isVoice: Bool {
        switch self {
        case .telephoneEvent, .comfortNoise, .video, .unknown: return false
        default: return true
        }
    }

    /// Maps an SDP/RTP encoding name (case-insensitive) to a codec kind.
    public static func from(encodingName name: String) -> CodecKind {
        switch name.uppercased() {
        case "PCMU", "G711U", "G711-U": return .pcmu
        case "PCMA", "G711A", "G711-A": return .pcma
        case "G729", "G729A", "G729B", "G729AB", "G729D", "G729E": return .g729
        case "G723", "G7231", "G723.1": return .g723
        case "G722": return .g722
        case "G728": return .g728
        case let n where n.hasPrefix("G726") || n.hasPrefix("AAL2-G726"): return .g726
        case "GSM", "GSM-EFR", "GSM-HR-08": return .gsm
        case "ILBC": return .ilbc
        case "OPUS": return .opus
        case "SPEEX": return .speex
        case "AMR": return .amr
        case "AMR-WB": return .amrWB
        case "G7221": return .g7221
        case "L16": return .l16
        case "TELEPHONE-EVENT": return .telephoneEvent
        case "CN": return .comfortNoise
        case "H261", "H263", "H263-1998", "H263-2000", "H264", "H265", "VP8", "VP9", "AV1", "MP4V-ES", "JPEG":
            return .video
        default: return .unknown
        }
    }
}

/// A concrete payload mapping observed in a capture (from the static RTP table or an SDP rtpmap).
public struct CodecDescriptor: Codable, Sendable, Hashable {
    public var kind: CodecKind
    public var encodingName: String
    public var payloadType: UInt8
    /// RTP timestamp clock rate in Hz (e.g. 8000 for G.722 by RFC 3551 even though audio is 16 kHz).
    public var clockRate: Int?
    public var channels: Int?

    public init(kind: CodecKind, encodingName: String, payloadType: UInt8, clockRate: Int?, channels: Int? = nil) {
        self.kind = kind
        self.encodingName = encodingName
        self.payloadType = payloadType
        self.clockRate = clockRate
        self.channels = channels
    }

    /// Audio sampling rate when it can be determined (differs from the RTP clock for G.722).
    public var sampleRate: Int? {
        switch kind {
        case .g722: return 16000
        default: return clockRate
        }
    }

    public var displayName: String {
        kind == .unknown ? (encodingName.isEmpty ? "PT \(payloadType)" : encodingName) : kind.displayName
    }
}
