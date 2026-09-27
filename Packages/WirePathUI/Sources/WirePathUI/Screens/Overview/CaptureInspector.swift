import WirePathCore
import SwiftUI

/// Right-hand inspector (⌥⌘I): facts about the capture — file, time span, protocols, IPs, topology.
struct CaptureInspector: View {
    var result: AnalysisResult
    var manifest: AnalysisManifest

    var body: some View {
        let capture = result.capture
        ScrollView(.vertical) {
            VStack(alignment: .leading, spacing: 18) {
                group("Capture") {
                    row(String(localized: "File"), capture.fileName)
                    row(String(localized: "Size"), Formatters.bytes(capture.fileSize))
                    row(String(localized: "Format"), [capture.format.label, capture.formatVersion].filter { !$0.isEmpty }.joined(separator: " ")
                        + (capture.compressed ? " · gzip" : ""))
                    row(String(localized: "Link"), capture.linkTypes.joined(separator: ", "))
                    row(String(localized: "Imported"), manifest.importedAt.formatted(date: .abbreviated, time: .shortened))
                }
                if let section = capture.section, section.hardware != nil || section.operatingSystem != nil
                    || section.application != nil || !section.comments.isEmpty {
                    group("Recorded With") {
                        if let application = section.application { row(String(localized: "Application"), application) }
                        if let system = section.operatingSystem { row(String(localized: "System"), system) }
                        if let hardware = section.hardware { row(String(localized: "Hardware"), hardware) }
                        ForEach(section.comments, id: \.self) { comment in
                            Text(comment).font(.wp(11.5)).foregroundStyle(Theme.fg2).textSelection(.enabled)
                        }
                    }
                }
                if capture.interfaces.count > 1 || capture.interfaces.contains(where: { $0.name != nil || $0.packetsReceived != nil }) {
                    group("Interfaces · \(capture.interfaces.count)") {
                        ForEach(capture.interfaces, id: \.id) { interface in
                            InterfaceSummary(interface: interface)
                        }
                    }
                }
                group("Time") {
                    row(String(localized: "Start"), capture.firstPacketTime.map(Formatters.dayTime) ?? "—")
                    row(String(localized: "End"), capture.lastPacketTime.map(Formatters.dayTime) ?? "—")
                    row(String(localized: "Duration"), Formatters.hms(capture.durationSeconds))
                }
                group("Traffic") {
                    row(String(localized: "Packets"), Formatters.count(capture.packetCount))
                    row(String(localized: "Bytes"), Formatters.bytes(capture.byteCount))
                    row(String(localized: "SIP"), Formatters.count(capture.sipPackets))
                    row(String(localized: "RTP"), Formatters.count(capture.rtpPackets))
                    row(String(localized: "RTCP"), Formatters.count(capture.rtcpPackets))
                    row(String(localized: "Flows"), Formatters.count(capture.flowCount))
                    if capture.truncatedPackets > 0 { row(String(localized: "Truncated"), Formatters.count(capture.truncatedPackets)) }
                    if !capture.packetComments.isEmpty { row(String(localized: "Packet comments"), Formatters.count(capture.packetComments.count)) }
                }
                group("Protocols") {
                    ForEach(capture.protocols, id: \.name) { item in
                        row(item.name, Formatters.count(item.packets))
                    }
                }
                group("Topology") {
                    row(String(localized: "SIP server"), result.topology.sipServer?.description ?? String(localized: "Not determined"), mono: result.topology.sipServer != nil)
                    row(String(localized: "Endpoints"), "\(result.topology.endpoints.count)")
                    ForEach(result.topology.trunks, id: \.self) { row(String(localized: "SIP trunk"), $0.description, mono: true) }
                }
                group("IP Addresses · \(capture.addresses.count)") {
                    ForEach(capture.addresses.prefix(40), id: \.address) { entry in
                        row(entry.address.description, Formatters.count(entry.packets), monoLabel: true)
                    }
                    if capture.addresses.count > 40 {
                        Text("+ \(capture.addresses.count - 40) more").font(.wp(11)).foregroundStyle(Theme.fg3)
                    }
                }
                if !capture.warnings.isEmpty {
                    group("Warnings") {
                        ForEach(capture.warnings, id: \.self) { warning in
                            HStack(alignment: .top, spacing: 6) {
                                StatusIcon(severity: .warning, size: 11)
                                Text(warning).font(.wp(11.5)).foregroundStyle(Theme.fg2)
                            }
                        }
                    }
                }
            }
            .padding(16)
        }
        .frame(width: 280)
        .background(Theme.surf)
        .overlay(alignment: .leading) { Rectangle().fill(Theme.line).frame(width: 1) }
    }

    private struct InterfaceSummary: View {
        var interface: CaptureInterfaceInfo

        var body: some View {
            let drops = (interface.packetsDroppedByInterface ?? 0) + (interface.packetsDroppedByOS ?? 0)
            VStack(alignment: .leading, spacing: 2) {
                Text(interface.name ?? String(localized: "Interface \(interface.id)")).font(.wp(12, .medium)).foregroundStyle(Theme.fg)
                if let description = interface.interfaceDescription {
                    Text(description).font(.wp(11.5)).foregroundStyle(Theme.fg2)
                }
                Text("\(interface.linkTypeName) · \(interface.packetCount) packets · \(interface.timestampResolution)")
                    .font(.wp(11.5)).foregroundStyle(Theme.fg3)
                if interface.snapLength > 0 && interface.snapLength < 65_535 {
                    Text("Snapshot length \(interface.snapLength) bytes").font(.wp(11.5)).foregroundStyle(Theme.fg3)
                }
                if interface.packetsReceived != nil || drops > 0 {
                    HStack(spacing: 4) {
                        if drops > 0 { StatusIcon(severity: .warning, size: 10) }
                        Text("Dropped while capturing: \(Int(clamping: drops))")
                            .font(.wp(11.5)).foregroundStyle(drops > 0 ? Theme.warn : Theme.fg3)
                    }
                    .accessibilityElement(children: .combine)
                }
            }
            .accessibilityElement(children: .combine)
        }
    }

    private func group<Content: View>(_ title: LocalizedStringKey, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.wp(11, .semibold)).foregroundStyle(Theme.fg3)
            content()
        }
    }

    private func row(_ label: String, _ value: String, mono: Bool = false, monoLabel: Bool = false) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(label).font(monoLabel ? .wpMono(11.5) : .wp(12)).foregroundStyle(monoLabel ? Theme.fg : Theme.fg2)
            Spacer(minLength: 4)
            Text(value).font(mono ? .wpMono(11.5) : .wp(12)).foregroundStyle(monoLabel ? Theme.fg2 : Theme.fg)
                .multilineTextAlignment(.trailing).lineLimit(2).textSelection(.enabled)
        }
    }
}
