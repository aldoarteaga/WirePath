import Foundation

public struct SIPHeader: Sendable, Hashable {
    /// Canonical header name (compact forms expanded, e.g. `i` → `Call-ID`).
    public var name: String
    public var value: String
}

/// A parsed SIP request or response (RFC 3261 §7).
public struct SIPMessage: Sendable {
    public var isRequest: Bool
    public var method: String
    public var requestURI: String?
    public var statusCode: Int?
    public var reasonPhrase: String?
    public var headers: [SIPHeader]
    public var body: String
    /// Bytes consumed from the input (start line + headers + body).
    public var totalLength: Int
    /// The message text exactly as captured (decoded as UTF-8).
    public var rawText: String
    /// The SDP body parsed once by `SIPParser.parse` (which runs in the parallel decoding stage).
    var parsedSDP: SessionDescription?

    public func header(_ name: String) -> String? {
        headers.first { ASCII.equalsIgnoringCase($0.name, name) }?.value
    }

    public func headerValues(_ name: String) -> [String] {
        headers.filter { ASCII.equalsIgnoringCase($0.name, name) }.map(\.value)
    }

    public var callID: String? { header("Call-ID")?.trimmingCharacters(in: .whitespaces) }

    public var cseq: (number: Int, method: String)? {
        guard let value = header("CSeq") else { return nil }
        let parts = value.split(separator: " ", omittingEmptySubsequences: true)
        guard parts.count >= 2, let number = Int(parts[0]) else { return nil }
        return (number, String(parts[1]).uppercased())
    }

    public var from: SIPAddress? { header("From").map(SIPHeaderParser.parseAddress) }
    public var to: SIPAddress? { header("To").map(SIPHeaderParser.parseAddress) }
    public var contact: String? { header("Contact") }
    public var userAgent: String? { header("User-Agent") ?? header("Server") }
    public var contentType: String? { header("Content-Type") }

    /// Every Via value (a header line may contain several comma-separated values).
    public var viaValues: [String] {
        headerValues("Via").flatMap { SIPHeaderParser.splitList($0) }
    }

    public var topViaBranch: String? {
        guard let top = viaValues.first else { return nil }
        return SIPHeaderParser.parameter("branch", in: top)
    }

    /// The SDP body, if the message carries one (also found inside simple multipart bodies).
    public var sdp: SessionDescription? {
        if let parsedSDP { return parsedSDP }
        return describedSDP
    }

    fileprivate var describedSDP: SessionDescription? {
        guard !body.isEmpty else { return nil }
        let type = contentType?.lowercased() ?? ""
        if type.contains("application/sdp") { return SDPParser.parse(body) }
        if type.contains("multipart"), let range = body.range(of: "v=0") {
            return SDPParser.parse(String(body[range.lowerBound...]))
        }
        return nil
    }
}

/// ASCII-only string helpers for protocol tokens (header names, keywords), without Foundation bridging.
enum ASCII {
    @inline(__always) static func lower(_ byte: UInt8) -> UInt8 { byte >= 65 && byte <= 90 ? byte | 0x20 : byte }

    /// Case-insensitive equality of two ASCII tokens (header names are ASCII by RFC 3261).
    static func equalsIgnoringCase(_ a: String, _ b: String) -> Bool {
        var a = a, b = b
        return a.withUTF8 { x in
            b.withUTF8 { y in
                guard x.count == y.count else { return false }
                for i in 0..<x.count where lower(x[i]) != lower(y[i]) { return false }
                return true
            }
        }
    }

    /// Whether `text` contains the lowercase ASCII `needle`, ignoring the case of `text`.
    static func contains(_ text: String, lowercased needle: StaticString) -> Bool {
        var text = text
        return text.withUTF8 { haystack in
            needle.withUTF8Buffer { pattern in
                guard let first = pattern.first, pattern.count <= haystack.count else { return false }
                var i = 0
                let last = haystack.count - pattern.count
                while i <= last {
                    if lower(haystack[i]) == first {
                        var j = 1
                        while j < pattern.count, lower(haystack[i + j]) == pattern[j] { j += 1 }
                        if j == pattern.count { return true }
                    }
                    i += 1
                }
                return false
            }
        }
    }
}

public enum SIPParser {
    private static let knownMethods: Set<String> = [
        "INVITE", "ACK", "BYE", "CANCEL", "OPTIONS", "REGISTER", "REFER", "NOTIFY", "INFO", "UPDATE", "PRACK",
        "SUBSCRIBE", "MESSAGE", "PUBLISH",
    ]

    /// Cheap check on the first bytes: "SIP/2.0 NNN" or "METHOD sip:…".
    public static func looksLikeSIP(_ bytes: UnsafeRawBufferPointer) -> Bool {
        guard bytes.count >= 12 else { return false }
        // "SIP/2.0 "
        if bytes[0] == 0x53, bytes[1] == 0x49, bytes[2] == 0x50, bytes[3] == 0x2F, bytes[4] == 0x32,
           bytes[5] == 0x2E, bytes[6] == 0x30, bytes[7] == 0x20 {
            return true
        }
        var i = 0
        while i < min(bytes.count, 18), bytes[i] >= 0x41, bytes[i] <= 0x5A { i += 1 }
        guard i >= 3, i < bytes.count - 5, bytes[i] == 0x20 else { return false }
        let s = bytes[i + 1] | 0x20, t = bytes[i + 2] | 0x20, u = bytes[i + 3] | 0x20
        // sip: / sips: / tel: / urn:
        return (s == 0x73 && t == 0x69 && u == 0x70) || (s == 0x74 && t == 0x65 && u == 0x6C)
            || (s == 0x75 && t == 0x72 && u == 0x6E)
    }

    /// Parses one message from the start of `bytes`.
    /// - Parameter requireContentLength: For stream transports (TCP) the body length must be known and
    ///   complete; returns nil when more data is needed.
    public static func parse(_ bytes: UnsafeRawBufferPointer, requireContentLength: Bool = false) -> SIPMessage? {
        guard let headerEnd = findHeaderEnd(bytes, allowUnterminated: !requireContentLength) else { return nil }
        let headerText = String(decoding: UnsafeRawBufferPointer(rebasing: bytes[0..<headerEnd.headersEnd]), as: UTF8.self)
        var lines = headerText.components(separatedBy: "\n").map { $0.hasSuffix("\r") ? String($0.dropLast()) : $0 }
        guard !lines.isEmpty else { return nil }
        let startLine = lines.removeFirst()

        var message = SIPMessage(isRequest: false, method: "", requestURI: nil, statusCode: nil, reasonPhrase: nil,
                                 headers: [], body: "", totalLength: 0, rawText: "")
        if startLine.hasPrefix("SIP/2.0 ") {
            let rest = startLine.dropFirst(8)
            let parts = rest.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: false)
            guard let code = Int(parts.first ?? ""), (100...699).contains(code) else { return nil }
            message.statusCode = code
            message.reasonPhrase = parts.count > 1 ? String(parts[1]) : SIPStatus.reasonPhrase(for: code)
        } else {
            let parts = startLine.split(separator: " ")
            guard parts.count >= 3, parts.last == "SIP/2.0" else { return nil }
            message.isRequest = true
            message.method = String(parts[0]).uppercased()
            message.requestURI = String(parts[1])
        }

        // Unfold continuation lines (RFC 3261 §7.3.1) and split name: value.
        for line in lines {
            if line.isEmpty { continue }
            if (line.first == " " || line.first == "\t"), !message.headers.isEmpty {
                message.headers[message.headers.count - 1].value += " " + line.trimmingCharacters(in: .whitespaces)
                continue
            }
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = line[..<colon].trimmingCharacters(in: .whitespaces)
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            message.headers.append(SIPHeader(name: SIPHeaderParser.canonicalName(name), value: value))
        }

        if !message.isRequest, let cseq = message.cseq { message.method = cseq.method }

        let bodyStart = headerEnd.bodyStart
        let available = bytes.count - bodyStart
        var bodyLength = available
        if let lengthText = message.header("Content-Length"), let declared = Int(lengthText.trimmingCharacters(in: .whitespaces)) {
            if declared < 0 {
                // Invalid: over TCP the message cannot be framed; over UDP the datagram bounds the body.
                if requireContentLength { return nil }
            } else if declared > available {
                if requireContentLength { return nil }
            } else {
                bodyLength = declared
            }
        } else if requireContentLength {
            bodyLength = 0
        }
        if bodyLength > 0 {
            message.body = String(decoding: UnsafeRawBufferPointer(rebasing: bytes[bodyStart..<(bodyStart + bodyLength)]),
                                  as: UTF8.self)
        }
        message.totalLength = bodyStart + bodyLength
        message.rawText = String(decoding: UnsafeRawBufferPointer(rebasing: bytes[0..<message.totalLength]), as: UTF8.self)
        message.parsedSDP = message.describedSDP
        return message
    }

    /// Finds the blank line ending the header section. Accepts CRLF and bare LF line endings.
    private static func findHeaderEnd(_ bytes: UnsafeRawBufferPointer, allowUnterminated: Bool) -> (headersEnd: Int, bodyStart: Int)? {
        let count = bytes.count
        var i = 0
        while i < count - 1 {
            if bytes[i] == 0x0A {
                if bytes[i + 1] == 0x0A { return (i, i + 2) }
                if i + 2 < count, bytes[i + 1] == 0x0D, bytes[i + 2] == 0x0A { return (i, i + 3) }
            }
            i += 1
        }
        // UDP messages without a body sometimes end right after the last header line. Over TCP that only means
        // the segment ended at a line break, so the message is not complete yet.
        if allowUnterminated, count > 0, bytes[count - 1] == 0x0A { return (count, count) }
        return nil
    }

    public static func isKnownMethod(_ method: String) -> Bool { knownMethods.contains(method) }
}

public enum SIPHeaderParser {
    private static let compactForms: [String: String] = [
        "i": "Call-ID", "m": "Contact", "e": "Content-Encoding", "l": "Content-Length", "c": "Content-Type",
        "f": "From", "s": "Subject", "k": "Supported", "t": "To", "v": "Via", "o": "Event", "r": "Refer-To",
        "b": "Referred-By", "x": "Session-Expires", "u": "Allow-Events", "a": "Accept-Contact",
        "j": "Reject-Contact", "d": "Request-Disposition", "y": "Identity",
    ]
    private static let canonical: [String: String] = [
        "call-id": "Call-ID", "cseq": "CSeq", "via": "Via", "from": "From", "to": "To", "contact": "Contact",
        "content-length": "Content-Length", "content-type": "Content-Type", "max-forwards": "Max-Forwards",
        "user-agent": "User-Agent", "server": "Server", "allow": "Allow", "supported": "Supported",
        "record-route": "Record-Route", "route": "Route", "expires": "Expires", "session-expires": "Session-Expires",
        "p-asserted-identity": "P-Asserted-Identity", "authorization": "Authorization",
        "www-authenticate": "WWW-Authenticate", "proxy-authenticate": "Proxy-Authenticate",
        "proxy-authorization": "Proxy-Authorization", "reason": "Reason", "require": "Require",
        "refer-to": "Refer-To", "referred-by": "Referred-By", "event": "Event", "subscription-state": "Subscription-State",
        "rseq": "RSeq", "rack": "RAck", "accept": "Accept", "allow-events": "Allow-Events",
    ]

    public static func canonicalName(_ name: String) -> String {
        let lower = name.lowercased()
        if lower.count == 1, let full = compactForms[lower] { return full }
        return canonical[lower] ?? name
    }

    /// Parses name-addr / addr-spec values such as `"Soporte N1" <sip:1003@pbx.lan>;tag=a83f21`.
    public static func parseAddress(_ value: String) -> SIPAddress {
        let trimmed = value.trimmingCharacters(in: .whitespaces)
        var display: String?
        var uri: String
        var params: Substring
        if let open = trimmed.firstIndex(of: "<"), let close = trimmed[open...].firstIndex(of: ">") {
            let rawDisplay = trimmed[..<open].trimmingCharacters(in: .whitespaces)
            if !rawDisplay.isEmpty {
                display = rawDisplay.hasPrefix("\"") && rawDisplay.hasSuffix("\"") && rawDisplay.count >= 2
                    ? String(rawDisplay.dropFirst().dropLast()) : rawDisplay
            }
            uri = String(trimmed[trimmed.index(after: open)..<close])
            params = trimmed[trimmed.index(after: close)...]
        } else if let semicolon = trimmed.firstIndex(of: ";") {
            uri = String(trimmed[..<semicolon])
            params = trimmed[semicolon...]
        } else {
            uri = trimmed
            params = ""
        }
        let (user, host) = userAndHost(of: uri)
        return SIPAddress(displayName: display, uri: uri, user: user, host: host, tag: parameter("tag", in: String(params)))
    }

    /// Extracts user and host from sip:/sips:/tel: URIs.
    public static func userAndHost(of uri: String) -> (user: String?, host: String?) {
        var rest = Substring(uri)
        if let colon = rest.firstIndex(of: ":") {
            let scheme = rest[..<colon].lowercased()
            if scheme == "tel" {
                let number = rest[rest.index(after: colon)...].split(separator: ";").first.map(String.init)
                return (number, nil)
            }
            if scheme == "sip" || scheme == "sips" { rest = rest[rest.index(after: colon)...] }
        }
        rest = rest.split(separator: ";", maxSplits: 1).first ?? rest
        rest = rest.split(separator: "?", maxSplits: 1).first ?? rest
        guard let at = rest.lastIndex(of: "@") else {
            return (nil, rest.split(separator: ":").first.map(String.init))
        }
        var user = rest[..<at]
        if let colon = user.firstIndex(of: ":") { user = user[..<colon] }  // strip password
        let hostPart = rest[rest.index(after: at)...]
        let host: String
        if hostPart.hasPrefix("["), let end = hostPart.firstIndex(of: "]") {
            host = String(hostPart[hostPart.index(after: hostPart.startIndex)..<end])
        } else {
            host = String(hostPart.split(separator: ":").first ?? hostPart)
        }
        return (user.removingPercentEncoding ?? String(user), host)
    }

    /// Value of `;name=value` in a header value (case-insensitive name).
    public static func parameter(_ name: String, in value: String) -> String? {
        for part in value.split(separator: ";", omittingEmptySubsequences: false).dropFirst() {
            let pair = part.split(separator: "=", maxSplits: 1)
            if pair.first?.trimmingCharacters(in: .whitespaces).lowercased() == name.lowercased() {
                return pair.count > 1 ? pair[1].trimmingCharacters(in: .whitespaces) : ""
            }
        }
        return nil
    }

    /// Splits comma-separated header lists, respecting quotes and angle brackets.
    public static func splitList(_ value: String) -> [String] {
        var result: [String] = []
        var current = ""
        var inQuotes = false
        var angle = 0
        for ch in value {
            switch ch {
            case "\"": inQuotes.toggle(); current.append(ch)
            case "<" where !inQuotes: angle += 1; current.append(ch)
            case ">" where !inQuotes: angle = max(0, angle - 1); current.append(ch)
            case "," where !inQuotes && angle == 0:
                result.append(current.trimmingCharacters(in: .whitespaces))
                current = ""
            default: current.append(ch)
            }
        }
        let last = current.trimmingCharacters(in: .whitespaces)
        if !last.isEmpty { result.append(last) }
        return result
    }
}
