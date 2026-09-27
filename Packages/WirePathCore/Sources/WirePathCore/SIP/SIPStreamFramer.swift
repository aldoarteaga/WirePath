import Foundation

/// Splits a byte stream (SIP over TCP) into complete messages using Content-Length (RFC 3261 §18.3).
///
/// Work is linear in the stream length: the header terminator search resumes where the previous one stopped,
/// headers are parsed once per message, and consumed bytes are released as the stream advances.
public struct SIPStreamFramer: Sendable {
    private var buffer: [UInt8] = []
    /// Offset of the first unconsumed byte in `buffer`.
    private var start = 0
    /// Bytes after `start` already searched for the end of the headers.
    private var scanned = 0
    /// Total length of the message at `start`, once its headers are complete.
    private var needed: Int?
    public let maxBufferSize: Int

    public init(maxBufferSize: Int = 256 * 1024) {
        self.maxBufferSize = maxBufferSize
    }

    private var available: Int { buffer.count - start }

    /// Discards partial data (e.g. after a TCP gap).
    public mutating func reset() {
        buffer = []
        start = 0
        scanned = 0
        needed = nil
    }

    /// Appends bytes and returns every message completed by them.
    public mutating func append(_ data: Data) -> [SIPMessage] {
        buffer.append(contentsOf: data)
        var messages: [SIPMessage] = []
        while true {
            if needed == nil {
                // Skip CRLF keep-alives between messages (RFC 5626).
                while start < buffer.count, buffer[start] == 0x0D || buffer[start] == 0x0A { start += 1 }
            }
            guard available > 0 else { break }
            if needed == nil {
                guard let bodyStart = headerEnd() else {
                    if !looksLikeSIP() || available > maxBufferSize { reset() }
                    break
                }
                guard let length = contentLength(headersEnd: bodyStart), length <= maxBufferSize else {
                    // No usable Content-Length: the stream cannot be framed; resynchronise.
                    reset()
                    break
                }
                needed = bodyStart + length
            }
            guard let total = needed, available >= total else { break }
            let message = buffer.withUnsafeBytes { raw in
                SIPParser.parse(UnsafeRawBufferPointer(rebasing: raw[start..<(start + total)]), requireContentLength: true)
            }
            start += total
            scanned = 0
            needed = nil
            if let message { messages.append(message) }
        }
        compact()
        return messages
    }

    /// Offset (relative to `start`) where the body begins, searching only bytes not searched before.
    private mutating func headerEnd() -> Int? {
        let from = start + max(0, scanned - 3)
        let end = buffer.count
        var i = from
        while i + 1 < end {
            if buffer[i] == 0x0A {
                if buffer[i + 1] == 0x0A { return i + 2 - start }
                if i + 2 < end, buffer[i + 1] == 0x0D, buffer[i + 2] == 0x0A { return i + 3 - start }
            }
            i += 1
        }
        scanned = available
        return nil
    }

    /// Declared body length; a missing header means no body (as senders that omit it on TCP intend), an invalid
    /// one makes the stream unframeable (nil).
    private func contentLength(headersEnd: Int) -> Int? {
        let headers = buffer.withUnsafeBytes { raw in
            SIPParser.parse(UnsafeRawBufferPointer(rebasing: raw[start..<(start + headersEnd)]))
        }
        guard let headers else { return nil }
        guard let text = headers.header("Content-Length") else { return 0 }
        guard let value = Int(text.trimmingCharacters(in: .whitespaces)), value >= 0 else { return nil }
        return value
    }

    private func looksLikeSIP() -> Bool {
        available < 12 || buffer.withUnsafeBytes { raw in
            SIPParser.looksLikeSIP(UnsafeRawBufferPointer(rebasing: raw[start..<buffer.count]))
        }
    }

    /// Releases consumed bytes once they dominate the buffer.
    private mutating func compact() {
        if start == buffer.count {
            buffer.removeAll(keepingCapacity: buffer.capacity <= 65_536)
            start = 0
        } else if start > 65_536, start * 2 > buffer.count {
            buffer.removeFirst(start)
            start = 0
        }
    }
}
