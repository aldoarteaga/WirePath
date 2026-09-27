import Foundation

/// The saved form of an `AnalysisResult`, written and read in chunks so memory stays bounded.
///
/// Encoding a whole result with `JSONEncoder` builds an in-memory tree roughly ten times the size of the JSON
/// (2.5 GB for a capture with 170,000 SIP messages), which an iPad cannot afford. Here the large arrays are split
/// into JSON chunks of `chunkSize` records, each encoded and decoded on its own; the rest of the result is a small
/// JSON head. Layout: the magic line, then blocks of `[kind: UInt8][length: UInt64 LE][JSON]`.
/// The file is read memory-mapped and every length is checked, so a damaged file fails cleanly.
enum ResultArchive {
    static let magic = Data("WPRESULT1\n".utf8)
    static let chunkSize = 4096

    enum Section: UInt8, CaseIterable {
        case head = 0
        case sipMessages, sipTransactions, sipSessions, calls, streams, findings, rtcpReports, stunTransactions
    }

    struct Head: Codable {
        var result: AnalysisResult
        /// Records per section, to reserve capacity and to check that nothing is missing.
        var counts: [UInt8: Int]
    }

    static func write(_ result: AnalysisResult, to url: URL, encoder: JSONEncoder) throws {
        let temporary = url.deletingLastPathComponent().appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString)")
        FileManager.default.createFile(atPath: temporary.path, contents: nil)
        let handle = try FileHandle(forWritingTo: temporary)
        var succeeded = false
        defer {
            try? handle.close()
            if !succeeded { try? FileManager.default.removeItem(at: temporary) }
        }
        try handle.write(contentsOf: magic)
        func block(_ section: Section, _ json: Data) throws {
            var length = UInt64(json.count).littleEndian
            try handle.write(contentsOf: Data([section.rawValue]) + Data(bytes: &length, count: 8))
            try handle.write(contentsOf: json)
        }
        func chunks<T: Encodable>(_ section: Section, _ values: [T]) throws {
            var start = 0
            while start < values.count {
                let end = min(values.count, start + chunkSize)
                try autoreleasepool { try block(section, encoder.encode(Array(values[start..<end]))) }
                start = end
            }
        }

        var head = result
        head.sipMessages = []
        head.sipTransactions = []
        head.sipSessions = []
        head.calls = []
        head.streams = []
        head.findings = []
        head.rtcpReports = []
        head.webrtc.transactions = []
        let counts: [Section: Int] = [
            .sipMessages: result.sipMessages.count, .sipTransactions: result.sipTransactions.count,
            .sipSessions: result.sipSessions.count, .calls: result.calls.count, .streams: result.streams.count,
            .findings: result.findings.count, .rtcpReports: result.rtcpReports.count,
            .stunTransactions: result.webrtc.transactions.count,
        ]
        try block(.head, encoder.encode(Head(result: head, counts: Dictionary(uniqueKeysWithValues: counts.map { ($0.key.rawValue, $0.value) }))))
        try chunks(.sipMessages, result.sipMessages)
        try chunks(.sipTransactions, result.sipTransactions)
        try chunks(.sipSessions, result.sipSessions)
        try chunks(.calls, result.calls)
        try chunks(.streams, result.streams)
        try chunks(.findings, result.findings)
        try chunks(.rtcpReports, result.rtcpReports)
        try chunks(.stunTransactions, result.webrtc.transactions)
        try handle.synchronize()
        try handle.close()
        _ = try FileManager.default.replaceItemAt(url, withItemAt: temporary)
        succeeded = true
    }

    static func read(from url: URL, decoder: JSONDecoder) throws -> AnalysisResult {
        let data = try Data(contentsOf: url, options: .alwaysMapped)
        func damaged() -> CocoaError {
            CocoaError(.fileReadCorruptFile, userInfo: [NSLocalizedDescriptionKey: String(localized: "The saved results are damaged. Re-analyze the capture.", bundle: CoreLocalization.bundle)])
        }
        guard data.count >= magic.count, data.prefix(magic.count) == magic else { throw damaged() }
        var offset = magic.count
        var head: Head?
        var result: AnalysisResult?
        while offset < data.count {
            guard data.count - offset >= 9, let section = Section(rawValue: data[data.startIndex + offset]) else { throw damaged() }
            var length: UInt64 = 0
            withUnsafeMutableBytes(of: &length) { $0.copyBytes(from: data[(data.startIndex + offset + 1)..<(data.startIndex + offset + 9)]) }
            length = UInt64(littleEndian: length)
            offset += 9
            guard length <= UInt64(data.count - offset) else { throw damaged() }
            let json = data[(data.startIndex + offset)..<(data.startIndex + offset + Int(length))]
            offset += Int(length)
            try autoreleasepool {
                if section == .head {
                    guard head == nil else { throw damaged() }
                    let decoded = try decoder.decode(Head.self, from: json)
                    var base = decoded.result
                    // Reserve what the head announces (bounded: a damaged count must not allocate without limit).
                    func reserve(_ section: Section) -> Int { min(decoded.counts[section.rawValue] ?? 0, 10_000_000) }
                    base.sipMessages.reserveCapacity(reserve(.sipMessages))
                    base.streams.reserveCapacity(reserve(.streams))
                    head = decoded
                    result = base
                    return
                }
                guard var current = result else { throw damaged() }
                result = nil  // keep the arrays uniquely referenced while appending
                switch section {
                case .head: break
                case .sipMessages: current.sipMessages += try decoder.decode([SIPMessageRecord].self, from: json)
                case .sipTransactions: current.sipTransactions += try decoder.decode([SIPTransactionRecord].self, from: json)
                case .sipSessions: current.sipSessions += try decoder.decode([SIPSessionRecord].self, from: json)
                case .calls: current.calls += try decoder.decode([CallRecord].self, from: json)
                case .streams: current.streams += try decoder.decode([RTPStreamRecord].self, from: json)
                case .findings: current.findings += try decoder.decode([Finding].self, from: json)
                case .rtcpReports: current.rtcpReports += try decoder.decode([RTCPReportRecord].self, from: json)
                case .stunTransactions: current.webrtc.transactions += try decoder.decode([STUNTransactionRecord].self, from: json)
                }
                result = current
            }
        }
        guard let head, let result else { throw damaged() }
        // Every section must be complete.
        let actual: [Section: Int] = [
            .sipMessages: result.sipMessages.count, .sipTransactions: result.sipTransactions.count,
            .sipSessions: result.sipSessions.count, .calls: result.calls.count, .streams: result.streams.count,
            .findings: result.findings.count, .rtcpReports: result.rtcpReports.count,
            .stunTransactions: result.webrtc.transactions.count,
        ]
        for (section, count) in actual where (head.counts[section.rawValue] ?? 0) != count { throw damaged() }
        return result
    }
}
