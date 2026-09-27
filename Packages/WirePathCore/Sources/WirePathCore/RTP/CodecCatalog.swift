import Foundation

/// Static RTP payload types (RFC 3551 §6) and resolution of dynamic ones via SDP rtpmap.
public enum CodecCatalog {
    private static let staticTypes: [UInt8: (name: String, clock: Int, channels: Int?)] = [
        0: ("PCMU", 8000, 1), 3: ("GSM", 8000, 1), 4: ("G723", 8000, 1), 5: ("DVI4", 8000, 1),
        6: ("DVI4", 16000, 1), 7: ("LPC", 8000, 1), 8: ("PCMA", 8000, 1), 9: ("G722", 8000, 1),
        10: ("L16", 44100, 2), 11: ("L16", 44100, 1), 12: ("QCELP", 8000, 1), 13: ("CN", 8000, 1),
        14: ("MPA", 90000, nil), 15: ("G728", 8000, 1), 16: ("DVI4", 11025, 1), 17: ("DVI4", 22050, 1),
        18: ("G729", 8000, 1), 25: ("CelB", 90000, nil), 26: ("JPEG", 90000, nil), 28: ("nv", 90000, nil),
        31: ("H261", 90000, nil), 32: ("MPV", 90000, nil), 33: ("MP2T", 90000, nil), 34: ("H263", 90000, nil),
    ]

    /// Wireshark-style long names used in the packet list ("ITU-T G.729").
    public static func longName(for descriptor: CodecDescriptor) -> String {
        switch descriptor.kind {
        case .pcmu: return "ITU-T G.711 PCMU"
        case .pcma: return "ITU-T G.711 PCMA"
        case .g729: return "ITU-T G.729"
        case .g723: return "ITU-T G.723"
        case .g722: return "ITU-T G.722"
        case .g728: return "ITU-T G.728"
        case .gsm: return "GSM 06.10"
        case .comfortNoise: return "Comfort noise (CN)"
        case .telephoneEvent: return "telephone-event"
        default: return descriptor.encodingName.isEmpty ? "Unknown (\(descriptor.payloadType))" : descriptor.encodingName
        }
    }

    public static func isStatic(_ payloadType: UInt8) -> Bool { payloadType < 96 }

    /// Resolves a payload type using an optional rtpmap (name, clock rate, channels) from SDP.
    public static func descriptor(payloadType: UInt8, encodingName: String? = nil, clockRate: Int? = nil,
                                  channels: Int? = nil) -> CodecDescriptor? {
        if let encodingName {
            let fallback = staticTypes[payloadType]
            return CodecDescriptor(kind: CodecKind.from(encodingName: encodingName), encodingName: encodingName,
                                   payloadType: payloadType, clockRate: clockRate ?? fallback?.clock,
                                   channels: channels ?? fallback?.channels)
        }
        guard let entry = staticTypes[payloadType] else { return nil }
        return CodecDescriptor(kind: CodecKind.from(encodingName: entry.name), encodingName: entry.name,
                               payloadType: payloadType, clockRate: entry.clock, channels: entry.channels)
    }
}
