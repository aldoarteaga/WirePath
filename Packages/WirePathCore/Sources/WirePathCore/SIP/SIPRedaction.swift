import Foundation

/// Removes secrets from SIP/SDP text before WirePath stores it with an analysis: SRTP keys (`a=crypto` inline key
/// material), ICE passwords (`a=ice-pwd`) and Digest `response` hashes (which allow offline password guessing).
/// The capture file is never modified; only WirePath's own copy of the message text is redacted.
public enum SIPRedaction {
    public static let marker = "[redacted]"

    public static func redact(_ text: String) -> String {
        // Fast path (every stored SIP message goes through here): a byte scan for the three keywords.
        guard ASCII.contains(text, lowercased: "inline:") || ASCII.contains(text, lowercased: "ice-pwd")
                || ASCII.contains(text, lowercased: "response=") else { return text }
        var lines = text.components(separatedBy: "\n")
        for index in lines.indices {
            let line = lines[index]
            let lower = line.lowercased()
            if lower.hasPrefix("a=ice-pwd:") {
                lines[index] = "a=ice-pwd:" + marker + (line.hasSuffix("\r") ? "\r" : "")
            } else if lower.hasPrefix("a=crypto:") {
                lines[index] = redactValues(in: line, after: "inline:", terminators: ["|", " ", ";", "\r"])
            } else if lower.hasPrefix("authorization:") || lower.hasPrefix("proxy-authorization:") {
                lines[index] = redactValues(in: line, after: "response=", terminators: [",", " ", "\r"])
            }
        }
        return lines.joined(separator: "\n")
    }

    /// Replaces every value following `key` (quoted or up to a terminator).
    static func redactValues(in line: String, after key: String, terminators: Set<Character>) -> String {
        var result = ""
        var rest = Substring(line)
        while let range = rest.range(of: key, options: .caseInsensitive) {
            result += rest[..<range.upperBound]
            rest = rest[range.upperBound...]
            if rest.first == "\"" {
                let closing = rest.dropFirst().firstIndex(of: "\"") ?? rest.endIndex
                result += "\"" + marker + "\""
                rest = closing < rest.endIndex ? rest[rest.index(after: closing)...] : ""
            } else {
                let end = rest.firstIndex { terminators.contains($0) } ?? rest.endIndex
                result += marker
                rest = rest[end...]
            }
        }
        return result + rest
    }
}
