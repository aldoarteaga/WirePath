import Foundation

/// A decoded STUN message (RFC 8489) with the ICE (RFC 8445) and TURN (RFC 8656) attributes WirePath uses.
public struct STUNMessage: Sendable, Hashable {
    public enum MessageClass: String, Codable, Sendable {
        case request, indication, successResponse, errorResponse
    }

    public var method: UInt16
    public var messageClass: MessageClass
    /// 96-bit transaction ID as hex.
    public var transactionID: String
    public var username: String?
    public var priority: UInt32?
    public var useCandidate = false
    /// ICE role attributes (tie-breaker values are not kept).
    public var iceControlling = false
    public var iceControlled = false
    public var xorMappedAddress: Endpoint?
    public var xorRelayedAddress: Endpoint?
    public var xorPeerAddresses: [Endpoint] = []
    public var mappedAddress: Endpoint?
    public var errorCode: Int?
    public var errorReason: String?
    public var lifetime: UInt32?
    public var realm: String?
    public var hasNonce = false
    public var hasIntegrity = false
    public var channelNumber: UInt16?
    public var software: String?
    /// Bytes carried in a DATA attribute (Send/Data indications).
    public var dataLength = 0
    /// Where the DATA attribute's value is, relative to the start of the message.
    public var dataRange: Range<Int>?

    public var isICECheck: Bool { method == STUNMethod.binding && username?.contains(":") == true }
    public var isTURN: Bool { STUNMethod.isTURN(method) }
    public var methodName: String { STUNMethod.name(method) }
}

public enum STUNMethod {
    public static let binding: UInt16 = 0x001
    public static let allocate: UInt16 = 0x003
    public static let refresh: UInt16 = 0x004
    public static let send: UInt16 = 0x006
    public static let data: UInt16 = 0x007
    public static let createPermission: UInt16 = 0x008
    public static let channelBind: UInt16 = 0x009

    public static func isTURN(_ method: UInt16) -> Bool { (3...9).contains(method) }

    public static func name(_ method: UInt16) -> String {
        switch method {
        case binding: return "Binding"
        case allocate: return "Allocate"
        case refresh: return "Refresh"
        case send: return "Send"
        case data: return "Data"
        case createPermission: return "CreatePermission"
        case channelBind: return "ChannelBind"
        default: return String(format: "Method 0x%03x", method)
        }
    }
}

public enum STUNParser {
    public static let magicCookie: UInt32 = 0x2112_A442

    /// Parses a STUN message; nil when the bytes are not one (checked like `STUNDissector.isSTUN`).
    public static func parse(_ bytes: UnsafeRawBufferPointer) -> STUNMessage? {
        guard bytes.count >= 20, bytes[0] & 0xC0 == 0, bytes.u32be(4) == magicCookie else { return nil }
        let length = Int(bytes.u16be(2))
        guard length % 4 == 0, 20 + length <= bytes.count else { return nil }
        let type = bytes.u16be(0)
        let method = (type & 0x000F) | ((type & 0x00E0) >> 1) | ((type & 0x3E00) >> 2)
        let classBits = ((type & 0x0010) >> 4) | ((type & 0x0100) >> 7)
        let messageClass: STUNMessage.MessageClass = [.request, .indication, .successResponse, .errorResponse][Int(classBits & 3)]
        let transaction = bytes.slice(8, 12)
        var message = STUNMessage(method: method, messageClass: messageClass,
                                  transactionID: transaction.map { String(format: "%02x", $0) }.joined())
        var p = 20
        let end = 20 + length
        var count = 0
        while p + 4 <= end, count < 64 {
            count += 1
            let attribute = bytes.u16be(p)
            let attributeLength = Int(bytes.u16be(p + 2))
            let value = bytes.slice(p + 4, min(attributeLength, end - p - 4))
            func text() -> String { String(String(decoding: value, as: UTF8.self).prefix(512)) }
            switch attribute {
            case 0x0001: message.mappedAddress = plainAddress(value)
            case 0x0006: message.username = text()
            case 0x0008, 0x001C: message.hasIntegrity = true
            case 0x0009:
                if value.count >= 4 {
                    message.errorCode = Int(value[2] & 0x07) * 100 + Int(value[3])
                    message.errorReason = String(String(decoding: value.slice(4, value.count - 4), as: UTF8.self).prefix(256))
                }
            case 0x000C: if value.count >= 2 { message.channelNumber = value.u16be(0) }
            case 0x000D: if value.count >= 4 { message.lifetime = value.u32be(0) }
            case 0x0012:
                if let peer = xorAddress(value, transaction: transaction), message.xorPeerAddresses.count < 16 {
                    message.xorPeerAddresses.append(peer)
                }
            case 0x0013:
                message.dataLength = value.count
                message.dataRange = (p + 4)..<(p + 4 + value.count)
            case 0x0014: message.realm = text()
            case 0x0015: message.hasNonce = true
            case 0x0016: message.xorRelayedAddress = xorAddress(value, transaction: transaction)
            case 0x0020: message.xorMappedAddress = xorAddress(value, transaction: transaction)
            case 0x0024: if value.count >= 4 { message.priority = value.u32be(0) }
            case 0x0025: message.useCandidate = true
            case 0x8022: message.software = text()
            case 0x8029: message.iceControlled = true
            case 0x802A: message.iceControlling = true
            default: break
            }
            p += 4 + ((attributeLength + 3) & ~3)
        }
        return message
    }

    static func xorAddress(_ value: UnsafeRawBufferPointer, transaction: UnsafeRawBufferPointer) -> Endpoint? {
        guard value.count >= 8 else { return nil }
        let port = value.u16be(2) ^ 0x2112
        switch value[1] {
        case 1:
            return Endpoint(address: .v4(value.u32be(4) ^ magicCookie), port: port)
        case 2:
            guard value.count >= 20, transaction.count == 12 else { return nil }
            let key: [UInt8] = [0x21, 0x12, 0xA4, 0x42] + Array(transaction)
            let bytes = (0..<16).map { value[4 + $0] ^ key[$0] }
            return bytes.withUnsafeBytes { IPAddress(bytes: $0) }.map { Endpoint(address: $0, port: port) }
        default:
            return nil
        }
    }

    static func plainAddress(_ value: UnsafeRawBufferPointer) -> Endpoint? {
        guard value.count >= 8 else { return nil }
        let port = value.u16be(2)
        switch value[1] {
        case 1: return Endpoint(address: .v4(value.u32be(4)), port: port)
        case 2: return value.count >= 20 ? IPAddress(bytes: value.slice(4, 16)).map { Endpoint(address: $0, port: port) } : nil
        default: return nil
        }
    }
}

/// DTLS record detection (RFC 7983 demultiplexing: first byte 20–63; DTLS 1.0/1.2 versions 0xFEFF/0xFEFD).
public enum DTLSDetector {
    public static func looksLikeDTLS(_ bytes: UnsafeRawBufferPointer) -> Bool {
        guard bytes.count >= 13, (20...25).contains(bytes[0]), bytes[1] == 0xFE, bytes[2] == 0xFF || bytes[2] == 0xFD else { return false }
        return 13 + Int(bytes.u16be(11)) <= bytes.count
    }

    /// Handshake message type of the first record when it is a handshake (1 ClientHello, 2 ServerHello…).
    public static func handshakeType(_ bytes: UnsafeRawBufferPointer) -> UInt8? {
        guard looksLikeDTLS(bytes), bytes[0] == 22, bytes.count >= 14 else { return nil }
        return bytes[13]
    }
}
