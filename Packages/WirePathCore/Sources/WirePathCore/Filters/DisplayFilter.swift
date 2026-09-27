import Foundation

/// Lookup tables a display filter needs to evaluate index records.
public struct PacketFilterContext: Sendable {
    public var addresses: [IPAddress?]
    public var captureStartNanos: Int64
    public var streamSSRCs: [UInt32]
    public var streamPayloadTypes: [UInt8]
    public var sipCallIDs: [String]
    /// IP protocol of each flow (index = flow index), for `tcp.stream` / `udp.stream`.
    public var flowProtocols: [UInt8]
    /// Flow indices of each WebRTC session (checks, DTLS, media, TURN), for `webrtc` / `webrtc.session`.
    public var webrtcSessionFlows: [[Int]]

    public init(addresses: [IPAddress?], captureStartNanos: Int64, streamSSRCs: [UInt32],
                streamPayloadTypes: [UInt8], sipCallIDs: [String], flowProtocols: [UInt8] = [], webrtcSessionFlows: [[Int]] = []) {
        self.webrtcSessionFlows = webrtcSessionFlows
        self.addresses = addresses
        self.captureStartNanos = captureStartNanos
        self.streamSSRCs = streamSSRCs
        self.streamPayloadTypes = streamPayloadTypes
        self.sipCallIDs = sipCallIDs
        self.flowProtocols = flowProtocols
    }

    /// Sessions (0-based) each WebRTC flow belongs to.
    func webrtcSessionsByFlow() -> [Int32: [Int]] {
        var map: [Int32: [Int]] = [:]
        for (session, flows) in webrtcSessionFlows.enumerated() {
            for flow in flows where flow >= 0 && flow <= Int(Int32.max) { map[Int32(flow), default: []].append(session) }
        }
        return map
    }

    /// For each flow, its 0-based number among flows of the same transport (Wireshark's tcp.stream / udp.stream).
    func streamNumbers() -> [Int32] {
        var counters: [UInt8: Int32] = [:]
        return flowProtocols.map { proto in
            defer { counters[proto, default: 0] += 1 }
            return counters[proto, default: 0]
        }
    }
}

public struct DisplayFilterError: Error, Sendable, Equatable, CustomStringConvertible {
    public var message: String
    public var position: Int
    public var description: String { message }
}

/// A compiled Wireshark-like display filter, e.g. `rtp.seq_gap or sip.status >= 400`.
///
/// Supported: protocol names (`sip`, `rtp`, `rtcp`, `sdp`, `udp`, `tcp`, …), `ip.addr/src/dst`
/// (addresses or IPv4 CIDR), `udp.port`, `tcp.port`, `port`, `frame.number`, `frame.len`,
/// `frame.time_relative`, `sip.status`, `sip.method`, `sip.call_id`, `sip.error`, `rtp.ssrc`,
/// `rtp.pt`, `rtp.seq_gap`, `rtp.duplicate`, `rtp.out_of_order`, `rtp.ssrc_change`, `call`,
/// `stream`, `flow`, `webrtc`, `webrtc.session`, `issues`; operators `== != > >= < <= contains` (and `eq ne gt ge lt le`),
/// combined with `and`/`&&`, `or`/`||`, `not`/`!` and parentheses.
public struct DisplayFilter: Sendable {
    public typealias Predicate = @Sendable (_ record: PacketIndexRecord, _ frameNumber: Int) -> Bool

    public let source: String
    private let predicate: Predicate

    public init(_ source: String, context: PacketFilterContext) throws(DisplayFilterError) {
        self.source = source
        let trimmed = source.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty {
            predicate = { _, _ in true }
            return
        }
        var parser = Parser(tokens: try Lexer.tokenize(trimmed), context: context)
        predicate = try parser.parseFilter()
    }

    public func matches(_ record: PacketIndexRecord, frameNumber: Int) -> Bool {
        predicate(record, frameNumber)
    }

    /// Field names offered for completion / help.
    public static let knownFields: [String] = [
        "sip", "sdp", "rtp", "rtcp", "udp", "tcp", "ip", "ipv6", "arp", "icmp", "icmpv6", "dns", "dhcp", "ntp", "stun",
        "turn", "http", "tls", "dtls", "webrtc", "webrtc.session",
        "ip.addr", "ip.src", "ip.dst", "port", "udp.port", "udp.srcport", "udp.dstport", "tcp.port",
        "tcp.srcport", "tcp.dstport", "frame.number", "frame.len", "frame.time_relative", "sip.status",
        "sip.method", "sip.call_id", "sip.error", "rtp.ssrc", "rtp.pt", "rtp.seq_gap", "rtp.duplicate",
        "rtp.out_of_order", "rtp.ssrc_change", "call", "stream", "flow", "tcp.stream", "udp.stream", "issues",
        "tcp.analysis.flags", "tcp.analysis.retransmission", "tcp.analysis.out_of_order", "tcp.analysis.lost_segment",
        "tcp.analysis.duplicate_ack", "tcp.analysis.zero_window", "tcp.analysis.keep_alive", "tcp.analysis.window_update",
        "tcp.analysis.ack_lost_segment", "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin", "tcp.flags.reset", "tcp.flags.push",
    ]
}

// MARK: - Lexer

private enum Token: Equatable {
    case word(String)
    case string(String)
    case op(String)
    case lparen, rparen
    case lbrace, rbrace
    case and, or, not
}

private struct PositionedToken {
    var token: Token
    var position: Int
}

private enum Lexer {
    static func tokenize(_ text: String) throws(DisplayFilterError) -> [PositionedToken] {
        var tokens: [PositionedToken] = []
        let chars = Array(text)
        var i = 0
        while i < chars.count {
            let c = chars[i]
            if c.isWhitespace { i += 1; continue }
            let start = i
            switch c {
            case "(":
                tokens.append(.init(token: .lparen, position: start)); i += 1
            case ")":
                tokens.append(.init(token: .rparen, position: start)); i += 1
            case "{":
                tokens.append(.init(token: .lbrace, position: start)); i += 1
            case "}":
                tokens.append(.init(token: .rbrace, position: start)); i += 1
            case ",":
                i += 1  // set members may be separated by commas or spaces
            case "\"":
                i += 1
                var value = ""
                while i < chars.count && chars[i] != "\"" {
                    if chars[i] == "\\" && i + 1 < chars.count { i += 1 }
                    value.append(chars[i]); i += 1
                }
                guard i < chars.count else {
                    throw DisplayFilterError(message: "Unterminated string", position: start)
                }
                i += 1
                tokens.append(.init(token: .string(value), position: start))
            case "=", "!", ">", "<":
                if i + 1 < chars.count && chars[i + 1] == "=" {
                    tokens.append(.init(token: .op(String([c, "="])), position: start)); i += 2
                } else if c == "!" {
                    tokens.append(.init(token: .not, position: start)); i += 1
                } else if c == "=" {
                    tokens.append(.init(token: .op("=="), position: start)); i += 1
                } else {
                    tokens.append(.init(token: .op(String(c)), position: start)); i += 1
                }
            case "&":
                guard i + 1 < chars.count && chars[i + 1] == "&" else {
                    throw DisplayFilterError(message: "Expected &&", position: start)
                }
                tokens.append(.init(token: .and, position: start)); i += 2
            case "|":
                guard i + 1 < chars.count && chars[i + 1] == "|" else {
                    throw DisplayFilterError(message: "Expected ||", position: start)
                }
                tokens.append(.init(token: .or, position: start)); i += 2
            default:
                var word = ""
                while i < chars.count, !chars[i].isWhitespace, !"(){},=!<>&|\"".contains(chars[i]) {
                    word.append(chars[i]); i += 1
                }
                guard !word.isEmpty else {
                    throw DisplayFilterError(message: "Unexpected character “\(c)”", position: start)
                }
                switch word.lowercased() {
                case "and": tokens.append(.init(token: .and, position: start))
                case "or": tokens.append(.init(token: .or, position: start))
                case "not": tokens.append(.init(token: .not, position: start))
                case "eq": tokens.append(.init(token: .op("=="), position: start))
                case "ne": tokens.append(.init(token: .op("!="), position: start))
                case "gt": tokens.append(.init(token: .op(">"), position: start))
                case "ge": tokens.append(.init(token: .op(">="), position: start))
                case "lt": tokens.append(.init(token: .op("<"), position: start))
                case "le": tokens.append(.init(token: .op("<="), position: start))
                case "contains": tokens.append(.init(token: .op("contains"), position: start))
                default: tokens.append(.init(token: .word(word), position: start))
                }
            }
        }
        return tokens
    }
}

// MARK: - Parser

private struct Parser {
    typealias Predicate = DisplayFilter.Predicate

    let tokens: [PositionedToken]
    let context: PacketFilterContext
    var index = 0
    /// Nesting of parentheses and `not`, bounded so a pasted filter cannot exhaust the stack.
    var depth = 0
    static let maxDepth = 64
    static let maxTokens = 1_000

    init(tokens: [PositionedToken], context: PacketFilterContext) {
        self.tokens = tokens
        self.context = context
    }

    var current: PositionedToken? { index < tokens.count ? tokens[index] : nil }
    var position: Int { current?.position ?? (tokens.last.map { $0.position + 1 } ?? 0) }

    mutating func parseFilter() throws(DisplayFilterError) -> Predicate {
        guard tokens.count <= Self.maxTokens else {
            throw DisplayFilterError(message: "The filter is too long", position: tokens[Self.maxTokens].position)
        }
        let predicate = try parseOr()
        if let extra = current {
            throw DisplayFilterError(message: "Unexpected “\(describe(extra.token))”", position: extra.position)
        }
        return predicate
    }

    // `or`/`and` chains are evaluated in a loop over their terms rather than as nested closures, so long filters
    // do not deepen the call stack while matching millions of packets.
    mutating func parseOr() throws(DisplayFilterError) -> Predicate {
        var terms = [try parseAnd()]
        while current?.token == .or {
            index += 1
            terms.append(try parseAnd())
        }
        if terms.count == 1 { return terms[0] }
        let alternatives = terms
        return { record, frame in alternatives.contains { $0(record, frame) } }
    }

    mutating func parseAnd() throws(DisplayFilterError) -> Predicate {
        var terms = [try parseNot()]
        while current?.token == .and {
            index += 1
            terms.append(try parseNot())
        }
        if terms.count == 1 { return terms[0] }
        let conditions = terms
        return { record, frame in conditions.allSatisfy { $0(record, frame) } }
    }

    mutating func parseNot() throws(DisplayFilterError) -> Predicate {
        if current?.token == .not {
            try enter()
            defer { depth -= 1 }
            index += 1
            let inner = try parseNot()
            return { !inner($0, $1) }
        }
        return try parsePrimary()
    }

    mutating func enter() throws(DisplayFilterError) {
        depth += 1
        guard depth <= Self.maxDepth else {
            throw DisplayFilterError(message: "The filter is nested too deeply", position: position)
        }
    }

    mutating func parsePrimary() throws(DisplayFilterError) -> Predicate {
        guard let token = current else {
            throw DisplayFilterError(message: "Expression expected", position: position)
        }
        switch token.token {
        case .lparen:
            try enter()
            defer { depth -= 1 }
            index += 1
            let inner = try parseOr()
            guard current?.token == .rparen else {
                throw DisplayFilterError(message: "Missing “)”", position: position)
            }
            index += 1
            return inner
        case .word(let field):
            index += 1
            // Set membership: `field in {a b c}` is `field == a or field == b or field == c`.
            if case .word(let keyword)? = current?.token, keyword.lowercased() == "in" {
                index += 1
                guard current?.token == .lbrace else {
                    throw DisplayFilterError(message: "“{” expected after in", position: position)
                }
                index += 1
                var members: [Predicate] = []
                while let member = current, member.token != .rbrace {
                    index += 1
                    let value: String
                    switch member.token {
                    case .word(let w): value = w
                    case .string(let s): value = s
                    default: throw DisplayFilterError(message: "Value expected in the set", position: member.position)
                    }
                    members.append(try comparison(field: field, op: "==", value: value, position: token.position,
                                                  valuePosition: member.position))
                }
                guard current?.token == .rbrace else { throw DisplayFilterError(message: "Missing “}”", position: position) }
                index += 1
                guard !members.isEmpty else { throw DisplayFilterError(message: "The set is empty", position: token.position) }
                let alternatives = members
                return { record, frame in alternatives.contains { $0(record, frame) } }
            }
            if case .op(let op)? = current?.token {
                index += 1
                guard let valueToken = current else {
                    throw DisplayFilterError(message: "Value expected after \(op)", position: position)
                }
                index += 1
                let value: String
                switch valueToken.token {
                case .word(let w): value = w
                case .string(let s): value = s
                default:
                    throw DisplayFilterError(message: "Value expected after \(op)", position: valueToken.position)
                }
                return try comparison(field: field, op: op, value: value, position: token.position,
                                      valuePosition: valueToken.position)
            }
            return try booleanField(field, position: token.position)
        default:
            throw DisplayFilterError(message: "Unexpected “\(describe(token.token))”", position: token.position)
        }
    }

    func describe(_ token: Token) -> String {
        switch token {
        case .word(let w): return w
        case .string(let s): return "\"\(s)\""
        case .op(let o): return o
        case .lparen: return "("
        case .rparen: return ")"
        case .lbrace: return "{"
        case .rbrace: return "}"
        case .and: return "and"
        case .or: return "or"
        case .not: return "not"
        }
    }

    // MARK: Fields

    func booleanField(_ rawField: String, position: Int) throws(DisplayFilterError) -> Predicate {
        let field = rawField.lowercased()
        func proto(_ kinds: Set<UInt8>) -> Predicate {
            { r, _ in kinds.contains(r.protocolRaw) }
        }
        func flag(_ f: PacketFlags) -> Predicate {
            { r, _ in r.flagsRaw & f.rawValue != 0 }
        }
        func analysis(_ f: PacketAnalysisFlags) -> Predicate {
            { r, _ in r.analysisFlagsRaw & f.rawValue != 0 }
        }
        func tcpFlag(_ bit: UInt8) -> Predicate {
            { r, _ in r.ipProtocolRaw == 6 && r.tcpFlags & bit != 0 }
        }
        switch field {
        case "frame": return { _, _ in true }
        case "sip": return proto([PacketProtocol.sip.rawValue, PacketProtocol.sipSDP.rawValue])
        case "sdp": return proto([PacketProtocol.sipSDP.rawValue])
        case "rtp": return proto([PacketProtocol.rtp.rawValue])
        case "rtcp": return proto([PacketProtocol.rtcp.rawValue])
        case "dns": return proto([PacketProtocol.dns.rawValue])
        case "dhcp", "bootp": return proto([PacketProtocol.dhcp.rawValue])
        case "stun": return proto([PacketProtocol.stun.rawValue, PacketProtocol.turn.rawValue])
        case "turn": return proto([PacketProtocol.turn.rawValue])
        case "http": return proto([PacketProtocol.http.rawValue])
        case "dtls": return proto([PacketProtocol.dtls.rawValue])
        case "webrtc":
            // STUN, TURN and DTLS anywhere, plus every packet on a flow that belongs to an ICE session (its media).
            let kinds: Set<UInt8> = [PacketProtocol.stun.rawValue, PacketProtocol.turn.rawValue, PacketProtocol.dtls.rawValue]
            let flows = Set(context.webrtcSessionsByFlow().keys)
            return { r, _ in kinds.contains(r.protocolRaw) || (r.flowIndex >= 0 && flows.contains(r.flowIndex)) }
        case "ntp": return proto([PacketProtocol.ntp.rawValue])
        case "arp": return proto([PacketProtocol.arp.rawValue])
        case "icmp": return proto([PacketProtocol.icmp.rawValue])
        case "icmpv6": return proto([PacketProtocol.icmpv6.rawValue])
        case "tls": return proto([PacketProtocol.tls.rawValue])
        case "udp": return { r, _ in r.ipProtocolRaw == 17 }
        case "tcp": return { r, _ in r.ipProtocolRaw == 6 }
        case "ip", "ipv4":
            let addresses = context.addresses
            return { r, _ in
                guard r.sourceAddress != 0, Int(r.sourceAddress) < addresses.count else { return false }
                return addresses[Int(r.sourceAddress)]?.isV4 ?? false
            }
        case "ipv6":
            let addresses = context.addresses
            return { r, _ in
                guard r.sourceAddress != 0, Int(r.sourceAddress) < addresses.count else { return false }
                return !(addresses[Int(r.sourceAddress)]?.isV4 ?? true)
            }
        case "sip.error": return flag(.sipError)
        case "rtp.seq_gap", "rtp.lost", "rtp.gap": return flag(.sequenceGap)
        case "rtp.duplicate", "rtp.dup": return flag(.duplicate)
        case "rtp.out_of_order", "rtp.ooo": return flag(.outOfOrder)
        case "rtp.ssrc_change": return flag(.ssrcChange)
        case "sip.retransmission": return flag(.retransmission)
        case "issues":
            return { r, _ in r.flagsRaw & PacketFlags.issues.rawValue != 0 || r.analysisFlagsRaw & PacketAnalysisFlags.problems.rawValue != 0 }
        case "rtp.issues": return flag(.issues)
        case "tcp.analysis.flags": return analysis(.problems)
        case "tcp.analysis.retransmission": return analysis(.retransmission)
        case "tcp.analysis.out_of_order": return analysis(.outOfOrder)
        case "tcp.analysis.lost_segment": return analysis(.previousSegmentNotCaptured)
        case "tcp.analysis.duplicate_ack": return analysis(.duplicateACK)
        case "tcp.analysis.zero_window": return analysis(.zeroWindow)
        case "tcp.analysis.keep_alive": return analysis(.keepAlive)
        case "tcp.analysis.window_update": return analysis(.windowUpdate)
        case "tcp.analysis.ack_lost_segment": return analysis(.ackedUnseenSegment)
        case "tcp.flags.syn": return tcpFlag(0x02)
        case "tcp.flags.ack": return tcpFlag(0x10)
        case "tcp.flags.fin": return tcpFlag(0x01)
        case "tcp.flags.reset": return tcpFlag(0x04)
        case "tcp.flags.push": return tcpFlag(0x08)
        case "malformed": return flag(.malformed)
        case "call": return { r, _ in r.callIndex >= 0 }
        default:
            if isComparableField(field) {
                throw DisplayFilterError(message: "“\(rawField)” needs a comparison, e.g. \(rawField) == …",
                                         position: position)
            }
            throw DisplayFilterError(message: "Unknown field “\(rawField)”", position: position)
        }
    }

    func isComparableField(_ field: String) -> Bool {
        ["ip.addr", "ip.src", "ip.dst", "ipv6.addr", "ipv6.src", "ipv6.dst", "port", "udp.port", "tcp.port",
         "udp.srcport", "udp.dstport", "tcp.srcport", "tcp.dstport", "frame.number", "frame.len",
         "frame.time_relative", "sip.status", "sip.status-code", "sip.method", "sip.call_id", "sip.call-id",
         "rtp.ssrc", "rtp.pt", "rtp.p_type", "call", "stream", "flow", "tcp.stream", "udp.stream"].contains(field)
    }

    enum NumericOp { case eq, ne, gt, ge, lt, le }

    func numericOp(_ op: String, position: Int) throws(DisplayFilterError) -> NumericOp {
        switch op {
        case "==": return .eq
        case "!=": return .ne
        case ">": return .gt
        case ">=": return .ge
        case "<": return .lt
        case "<=": return .le
        default: throw DisplayFilterError(message: "“\(op)” is not valid for numbers", position: position)
        }
    }

    func compare<T: Comparable>(_ a: T, _ op: NumericOp, _ b: T) -> Bool {
        switch op {
        case .eq: return a == b
        case .ne: return a != b
        case .gt: return a > b
        case .ge: return a >= b
        case .lt: return a < b
        case .le: return a <= b
        }
    }

    func parseInteger(_ value: String, position: Int) throws(DisplayFilterError) -> Int64 {
        let v = value.lowercased()
        if v.hasPrefix("0x"), let n = Int64(v.dropFirst(2), radix: 16) { return n }
        if let n = Int64(v) { return n }
        throw DisplayFilterError(message: "“\(value)” is not a number", position: position)
    }

    func comparison(field rawField: String, op: String, value: String, position: Int,
                    valuePosition: Int) throws(DisplayFilterError) -> Predicate {
        let field = rawField.lowercased()
        switch field {
        case "ip.addr", "ip.src", "ip.dst", "ipv6.addr", "ipv6.src", "ipv6.dst":
            guard op == "==" || op == "!=" else {
                throw DisplayFilterError(message: "Addresses support == and != only", position: position)
            }
            let matching = try addressIndices(matching: value, position: valuePosition)
            let negate = op == "!="
            let side = field.hasSuffix("src") ? 1 : field.hasSuffix("dst") ? 2 : 0
            return { r, _ in
                let hit: Bool
                switch side {
                case 1: hit = matching.contains(r.sourceAddress)
                case 2: hit = matching.contains(r.destinationAddress)
                default: hit = matching.contains(r.sourceAddress) || matching.contains(r.destinationAddress)
                }
                return negate ? !hit : hit
            }
        case "port", "udp.port", "tcp.port", "udp.srcport", "udp.dstport", "tcp.srcport", "tcp.dstport":
            let nop = try numericOp(op, position: position)
            let port = try parseInteger(value, position: valuePosition)
            let side = field.hasSuffix("srcport") ? 1 : field.hasSuffix("dstport") ? 2 : 0
            let transport: UInt8? = field.hasPrefix("tcp") ? 6 : field.hasPrefix("udp") ? 17 : nil
            return { r, _ in
                guard r.sourcePort != 0 || r.destinationPort != 0 else { return false }
                if let transport, r.ipProtocolRaw != transport { return false }
                let s = Int64(r.sourcePort), d = Int64(r.destinationPort)
                switch side {
                case 1: return self.compare(s, nop, port)
                case 2: return self.compare(d, nop, port)
                default:
                    return nop == .ne ? (self.compare(s, nop, port) && self.compare(d, nop, port))
                        : (self.compare(s, nop, port) || self.compare(d, nop, port))
                }
            }
        case "frame.number":
            let nop = try numericOp(op, position: position)
            let n = try parseInteger(value, position: valuePosition)
            return { _, frame in self.compare(Int64(frame), nop, n) }
        case "frame.len":
            let nop = try numericOp(op, position: position)
            let n = try parseInteger(value, position: valuePosition)
            return { r, _ in self.compare(Int64(r.originalLength), nop, n) }
        case "frame.time_relative":
            let nop = try numericOp(op, position: position)
            guard let seconds = Double(value) else {
                throw DisplayFilterError(message: "“\(value)” is not a number", position: valuePosition)
            }
            let start = context.captureStartNanos
            let origin = Timestamp(nanoseconds: start)
            return { r, _ in self.compare(r.timestamp.seconds(since: origin), nop, seconds) }
        case "sip.status", "sip.status-code":
            let nop = try numericOp(op, position: position)
            let code = try parseInteger(value, position: valuePosition)
            return { r, _ in
                guard r.protocolKind.isSIP, SIPMethodCode.isResponse(r.sipCode) else { return false }
                return self.compare(Int64(r.sipCode), nop, code)
            }
        case "sip.method":
            guard op == "==" || op == "!=" || op == "contains" else {
                throw DisplayFilterError(message: "sip.method supports ==, != and contains", position: position)
            }
            let wanted = value.uppercased()
            let negate = op == "!="
            return { r, _ in
                guard r.protocolKind.isSIP, !SIPMethodCode.isResponse(r.sipCode),
                      let method = SIPMethodCode.method(for: r.sipCode) else { return negate }
                let hit = op == "contains" ? method.contains(wanted) : method == wanted
                return negate ? !hit : hit
            }
        case "sip.call_id", "sip.call-id":
            guard op == "==" || op == "!=" || op == "contains" else {
                throw DisplayFilterError(message: "sip.call_id supports ==, != and contains", position: position)
            }
            let ids = context.sipCallIDs
            let negate = op == "!="
            return { r, _ in
                guard r.protocolKind.isSIP, Int(r.aux) < ids.count else { return negate }
                let id = ids[Int(r.aux)]
                let hit = op == "contains" ? id.contains(value) : id == value
                return negate ? !hit : hit
            }
        case "rtp.ssrc":
            let nop = try numericOp(op, position: position)
            let ssrc = try parseInteger(value, position: valuePosition)
            let ssrcs = context.streamSSRCs
            return { r, _ in
                guard r.streamIndex >= 0, Int(r.streamIndex) < ssrcs.count else { return false }
                return self.compare(Int64(ssrcs[Int(r.streamIndex)]), nop, ssrc)
            }
        case "rtp.pt", "rtp.p_type":
            let nop = try numericOp(op, position: position)
            let pt = try parseInteger(value, position: valuePosition)
            let pts = context.streamPayloadTypes
            return { r, _ in
                guard r.streamIndex >= 0, Int(r.streamIndex) < pts.count else { return false }
                return self.compare(Int64(pts[Int(r.streamIndex)]), nop, pt)
            }
        case "call":
            let nop = try numericOp(op, position: position)
            let n = try parseInteger(value, position: valuePosition)
            return { r, _ in r.callIndex >= 0 && self.compare(Int64(r.callIndex) + 1, nop, n) }
        case "stream":
            let nop = try numericOp(op, position: position)
            let n = try parseInteger(value, position: valuePosition)
            return { r, _ in r.streamIndex >= 0 && self.compare(Int64(r.streamIndex) + 1, nop, n) }
        case "flow":
            let nop = try numericOp(op, position: position)
            let n = try parseInteger(value, position: valuePosition)
            return { r, _ in r.flowIndex >= 0 && self.compare(Int64(r.flowIndex) + 1, nop, n) }
        case "webrtc.session":
            let nop = try numericOp(op, position: position)
            let n = try parseInteger(value, position: valuePosition)
            let sessions = context.webrtcSessionsByFlow()
            return { r, _ in
                guard r.flowIndex >= 0, let owners = sessions[r.flowIndex] else { return false }
                return owners.contains { self.compare(Int64($0) + 1, nop, n) }
            }
        case "tcp.stream", "udp.stream":
            let nop = try numericOp(op, position: position)
            let n = try parseInteger(value, position: valuePosition)
            let transport: UInt8 = field == "tcp.stream" ? 6 : 17
            let numbers = context.streamNumbers()
            return { r, _ in
                guard r.ipProtocolRaw == transport, r.flowIndex >= 0, Int(r.flowIndex) < numbers.count else { return false }
                return self.compare(Int64(numbers[Int(r.flowIndex)]), nop, n)
            }
        default:
            if (try? booleanField(rawField, position: position)) != nil {
                throw DisplayFilterError(message: "“\(rawField)” is a flag and cannot be compared", position: position)
            }
            throw DisplayFilterError(message: "Unknown field “\(rawField)”", position: position)
        }
    }

    func addressIndices(matching value: String, position: Int) throws(DisplayFilterError) -> Set<UInt32> {
        var result = Set<UInt32>()
        if let slash = value.firstIndex(of: "/") {
            guard let base = IPAddress(String(value[..<slash])), case .v4(let network) = base,
                  let bits = Int(value[value.index(after: slash)...]), (0...32).contains(bits) else {
                throw DisplayFilterError(message: "“\(value)” is not a valid IPv4 network", position: position)
            }
            let mask: UInt32 = bits == 0 ? 0 : ~UInt32(0) << UInt32(32 - bits)
            for (index, address) in context.addresses.enumerated() {
                if case .v4(let a)? = address, a & mask == network & mask { result.insert(UInt32(index)) }
            }
            return result
        }
        guard let address = IPAddress(value) else {
            throw DisplayFilterError(message: "“\(value)” is not a valid IP address", position: position)
        }
        for (index, candidate) in context.addresses.enumerated() where candidate == address {
            result.insert(UInt32(index))
        }
        return result
    }
}
