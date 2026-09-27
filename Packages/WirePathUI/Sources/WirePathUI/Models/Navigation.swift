import Foundation

/// Sections listed under an analysis in the sidebar (⌘1 – ⌘9, then ⌘0).
public enum AnalysisSection: Int, CaseIterable, Hashable, Codable {
    case overview, calls, sipDialogs, rtpStreams, webrtc, timeline, packets, flows, statistics, diagnostics

    public var title: String {
        switch self {
        case .overview: return String(localized: "Overview")
        case .calls: return String(localized: "Calls")
        case .sipDialogs: return String(localized: "SIP Dialogs")
        case .rtpStreams: return String(localized: "RTP Streams")
        case .webrtc: return String(localized: "WebRTC")
        case .timeline: return String(localized: "Timeline")
        case .packets: return String(localized: "Packets")
        case .flows: return String(localized: "Flows")
        case .statistics: return String(localized: "Statistics")
        case .diagnostics: return String(localized: "Diagnostics")
        }
    }

    var icon: IconSpec {
        switch self {
        case .overview: return Icons.overview
        case .calls: return Icons.phone
        case .sipDialogs: return Icons.sipDialogs
        case .rtpStreams: return Icons.rtp
        case .webrtc: return Icons.webrtc
        case .timeline: return Icons.timeline
        case .packets: return Icons.packets
        case .flows: return Icons.flows
        case .statistics: return Icons.statistics
        case .diagnostics: return Icons.diagnostics
        }
    }

    /// ⌘1 – ⌘9 for the first nine sections, ⌘0 for the tenth.
    public var shortcutDigit: Character { Character("\((rawValue + 1) % 10)") }

    /// Stable identifier for UI tests and state restoration.
    public var identifier: String {
        switch self {
        case .overview: return "overview"
        case .calls: return "calls"
        case .sipDialogs: return "sip"
        case .rtpStreams: return "rtp"
        case .webrtc: return "webrtc"
        case .timeline: return "timeline"
        case .packets: return "packets"
        case .flows: return "flows"
        case .statistics: return "statistics"
        case .diagnostics: return "diagnostics"
        }
    }
}

/// What the detail area shows for an analysis.
public enum Route: Hashable {
    case section(AnalysisSection)
    /// Call investigation (sidebar keeps "Calls" highlighted).
    case call(Int)
    /// Packet inspector scoped to one call.
    case packets(callIndex: Int?)

    public var section: AnalysisSection {
        switch self {
        case .section(let section): return section
        case .call: return .calls
        case .packets: return .packets
        }
    }
}

public struct Location: Hashable {
    public var analysisID: UUID
    public var route: Route
}
