import OSLog

/// OSLog categories used by the engine (subsystem `com.wirepath`). Capture contents (payloads,
/// numbers, Call-IDs) are never logged; only counts, offsets and error reasons.
public enum Log {
    public static let subsystem = "com.wirepath"
    public static let core = Logger(subsystem: subsystem, category: "wirepath.core")
    public static let pcap = Logger(subsystem: subsystem, category: "wirepath.pcap")
    public static let proto = Logger(subsystem: subsystem, category: "wirepath.protocol")
    public static let sip = Logger(subsystem: subsystem, category: "wirepath.sip")
    public static let rtp = Logger(subsystem: subsystem, category: "wirepath.rtp")
    public static let webrtc = Logger(subsystem: subsystem, category: "wirepath.webrtc")
    public static let ui = Logger(subsystem: subsystem, category: "wirepath.ui")
}
