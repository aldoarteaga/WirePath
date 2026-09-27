import Foundation

/// Fixed RTP header (RFC 3550 §5.1).
public struct RTPHeader: Sendable, Hashable {
    public var padding: Bool
    public var hasExtension: Bool
    public var csrcCount: Int
    public var marker: Bool
    public var payloadType: UInt8
    public var sequenceNumber: UInt16
    public var timestamp: UInt32
    public var ssrc: UInt32
    /// Header length including CSRC list and extension.
    public var headerLength: Int
    public var payloadLength: Int

    /// Parses an RTP header. Rejects RTCP (payload types 72–76 with marker) and non-version-2 data.
    public static func parse(_ bytes: UnsafeRawBufferPointer) -> RTPHeader? {
        guard bytes.count >= 12 else { return nil }
        let b0 = bytes[0], b1 = bytes[1]
        guard b0 >> 6 == 2 else { return nil }
        let payloadType = b1 & 0x7F
        guard !(72...76).contains(payloadType) else { return nil }
        let csrcCount = Int(b0 & 0x0F)
        var headerLength = 12 + csrcCount * 4
        guard headerLength <= bytes.count else { return nil }
        let hasExtension = b0 & 0x10 != 0
        if hasExtension {
            guard headerLength + 4 <= bytes.count else { return nil }
            let words = Int(UInt16(bytes[headerLength + 2]) << 8 | UInt16(bytes[headerLength + 3]))
            headerLength += 4 + words * 4
            guard headerLength <= bytes.count else { return nil }
        }
        var payloadLength = bytes.count - headerLength
        let padding = b0 & 0x20 != 0
        if padding, payloadLength > 0 {
            let pad = Int(bytes[bytes.count - 1])
            payloadLength = max(0, payloadLength - pad)
        }
        return RTPHeader(
            padding: padding, hasExtension: hasExtension, csrcCount: csrcCount, marker: b1 & 0x80 != 0,
            payloadType: payloadType,
            sequenceNumber: UInt16(bytes[2]) << 8 | UInt16(bytes[3]),
            timestamp: UInt32(bytes[4]) << 24 | UInt32(bytes[5]) << 16 | UInt32(bytes[6]) << 8 | UInt32(bytes[7]),
            ssrc: UInt32(bytes[8]) << 24 | UInt32(bytes[9]) << 16 | UInt32(bytes[10]) << 8 | UInt32(bytes[11]),
            headerLength: headerLength, payloadLength: payloadLength)
    }
}

public enum RTCPDetector {
    /// RTCP compound packets start with SR (200), RR (201), SDES, BYE or APP, version 2.
    public static func looksLikeRTCP(_ bytes: UnsafeRawBufferPointer) -> Bool {
        guard bytes.count >= 8, bytes[0] >> 6 == 2 else { return false }
        let type = bytes[1]
        guard (200...207).contains(type) else { return false }
        let lengthWords = Int(UInt16(bytes[2]) << 8 | UInt16(bytes[3]))
        return (lengthWords + 1) * 4 <= bytes.count
    }

    public static func typeName(_ type: UInt8) -> String {
        switch type {
        case 200: return "Sender Report"
        case 201: return "Receiver Report"
        case 202: return "Source description"
        case 203: return "Goodbye"
        case 204: return "Application specific"
        case 205: return "Generic RTP Feedback"
        case 206: return "Payload-specific Feedback"
        case 207: return "Extended Report"
        default: return "Type \(type)"
        }
    }
}
