import Charts
import WirePathCore
import SwiftUI

/// Statistics: traffic over time, protocol distribution, packet sizes, top endpoints and conversations, and totals
/// by transport and for VoIP. Everything shown is measured from the capture.
struct StatisticsScreen: View {
    enum TrafficUnit: Hashable { case packets, bits }

    @Environment(\.layoutWidth) private var layoutWidth
    @Bindable var document: AnalysisDocument
    @State private var unit = TrafficUnit.packets

    private var result: AnalysisResult { document.result }
    private var statistics: CaptureStatistics? { result.statistics }

    var body: some View {
        VStack(spacing: 0) {
            HeaderBar(title: String(localized: "Statistics"), subtitle: "\(document.manifest.displayName) · \(Formatters.spoken(result.capture.durationSeconds))") {
                EmptyView()
            }
            ScrollView(.vertical) {
                VStack(spacing: 14) {
                    ScreenTitle(title: String(localized: "Statistics"), subtitle: subtitle)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    MetricStrip(items: metrics)
                    if let statistics {
                        TrafficOverTimeCard(statistics: statistics, protocols: result.capture.protocols, unit: $unit)
                        AdaptiveStack(threshold: .wide, spacing: 14) {
                            ProtocolDistributionCard(protocols: result.capture.protocols, totalPackets: result.capture.packetCount)
                            PacketSizesCard(buckets: statistics.packetSizes)
                        }
                    } else {
                        Text("Statistics are not available for this analysis. Re-analyze the capture to compute them.")
                            .font(.wp(12)).foregroundStyle(Theme.fg3).frame(maxWidth: .infinity, minHeight: 120)
                    }
                    AdaptiveStack(threshold: .wide, spacing: 14) {
                        TopEndpointsCard(document: document)
                        TopConversationsCard(document: document)
                    }
                    TransportCard(document: document)
                }
                .padding(EdgeInsets(top: 18, leading: layoutWidth == .compact ? 14 : 22, bottom: 16, trailing: layoutWidth == .compact ? 14 : 22))
            }
            FooterBar(leading: String(localized: "\(result.capture.packetCount) packets · \(Formatters.bytes(result.capture.byteCount))"),
                      trailing: statistics.map { String(localized: "\(Formatters.count($0.traffic.packets.count)) × \(Formatters.duration($0.traffic.binSeconds)) bins") } ?? "")
        }
        .onAppear { document.loadFlows() }
    }

    private var subtitle: String {
        let capture = result.capture
        return String(localized: "\(Formatters.count(capture.packetCount)) packets · \(capture.protocols.count) protocols · \(Formatters.count(capture.flowCount)) flows")
    }

    private var metrics: [MetricStrip.Item] {
        let capture = result.capture
        var items: [MetricStrip.Item] = [
            .init(label: String(localized: "Packets"), value: Formatters.count(capture.packetCount), caption: Formatters.bytes(capture.byteCount)),
        ]
        if let statistics {
            items.append(.init(label: String(localized: "Mean Rate"),
                               value: statistics.meanPacketsPerSecond.map { String(format: "%.1f", $0) } ?? "—",
                               unit: statistics.meanPacketsPerSecond == nil ? nil : String(localized: "pkt/s"),
                               caption: statistics.meanBitsPerSecond.map { Formatters.bits($0) + "/s" }))
            items.append(.init(label: String(localized: "Peak Second"), value: Formatters.count(statistics.peakPacketsPerSecond), unit: String(localized: "pkt/s"),
                               caption: Formatters.bits(statistics.peakBitsPerSecond) + "/s"
                                   + (statistics.peakSecond.map { " · " + Formatters.clock($0) } ?? "")))
        }
        let average = capture.packetCount > 0 ? Double(capture.byteCount) / Double(capture.packetCount) : 0
        items.append(.init(label: String(localized: "Mean Size"), value: String(format: "%.0f", average), unit: String(localized: "bytes")))
        items.append(.init(label: String(localized: "SIP Calls"), value: Formatters.count(result.calls.count),
                           caption: String(localized: "\(result.sipMessages.count) SIP messages")))
        items.append(.init(label: String(localized: "RTP Streams"), value: Formatters.count(result.streams.count),
                           caption: String(localized: "\(capture.rtpPackets) packets")))
        return items
    }
}

/// Protocols get stable colours from the theme, keyed by protocol name in the capture's protocol order, so the
/// traffic chart, its legend and the distribution agree.
enum ProtocolPalette {
    static let colors: [Color] = [Theme.acc, Theme.m1, Theme.m2, Theme.ok, Theme.warn, Theme.fg3]

    static func color(for index: Int) -> Color { colors[index % colors.count] }

    static func color(for name: String, in protocols: [ProtocolCount]) -> Color {
        guard let index = protocols.firstIndex(where: { $0.name == name }) else { return Theme.fg3.opacity(0.6) }
        return color(for: index)
    }
}

struct TrafficOverTimeCard: View {
    var statistics: CaptureStatistics
    var protocols: [ProtocolCount]
    @Binding var unit: StatisticsScreen.TrafficUnit

    private struct Point: Identifiable {
        var id: String { "\(series)-\(bin)" }
        var bin: Int
        var seconds: Double
        var series: String
        var value: Double
    }

    private var points: [Point] {
        let traffic = statistics.traffic
        if unit == .bits {
            return traffic.bytes.enumerated().map { bin, bytes in
                Point(bin: bin, seconds: Double(bin) * traffic.binSeconds, series: String(localized: "All traffic"),
                      value: Double(bytes) * 8 / traffic.binSeconds)
            }
        }
        var result: [Point] = []
        var tracked = [Int](repeating: 0, count: traffic.packets.count)
        for series in traffic.protocolPackets {
            for (bin, count) in series.packets.enumerated() {
                tracked[bin] += count
                result.append(Point(bin: bin, seconds: Double(bin) * traffic.binSeconds, series: series.protocolKind.displayName,
                                    value: Double(count) / traffic.binSeconds))
            }
        }
        if traffic.packets.enumerated().contains(where: { $0.element > tracked[$0.offset] }) {
            for (bin, count) in traffic.packets.enumerated() {
                result.append(Point(bin: bin, seconds: Double(bin) * traffic.binSeconds, series: String(localized: "Other"),
                                    value: Double(max(0, count - tracked[bin])) / traffic.binSeconds))
            }
        }
        return result
    }

    /// Legend entries: the tracked protocols, plus "Other" only when some packets are outside them.
    private var seriesNames: [String] {
        if unit == .bits { return [String(localized: "All traffic")] }
        let traffic = statistics.traffic
        let tracked = traffic.protocolPackets.reduce(0) { $0 + $1.packets.reduce(0, +) }
        let names = traffic.protocolPackets.map(\.protocolKind.displayName)
        return tracked < traffic.packets.reduce(0, +) ? names + [String(localized: "Other")] : names
    }

    private func valueText(_ value: Double) -> String {
        unit == .packets ? String(format: "%.0f packets per second", value) : Formatters.bits(value) + "/s"
    }

    var body: some View {
        VStack(spacing: 0) {
            CardHeader(title: String(localized: "Traffic"),
                       subtitle: unit == .packets ? String(localized: "packets per second, by protocol") : String(localized: "bits per second")) {
                SegmentedControl(items: [.init(value: StatisticsScreen.TrafficUnit.packets, title: String(localized: "Packets")),
                                         .init(value: .bits, title: String(localized: "Bits"))], selection: $unit)
            }
            // Areas read well for long series; a few bins (a capture shorter than a minute) are clearer as bars, and a
            // single bin cannot form an area at all.
            let bars = statistics.traffic.packets.count < 60
            Chart(points) { point in
                if bars {
                    // A categorical axis: one band per bin, which also works for a single bin.
                    BarMark(x: .value("Time", Formatters.duration(point.seconds)),
                            y: .value(unit == .packets ? String(localized: "Packets/s") : String(localized: "Bits/s"), point.value), width: .ratio(0.8), stacking: .standard)
                        .foregroundStyle(by: .value("Protocol", point.series))
                        .accessibilityLabel(Text("\(point.series), \(Formatters.duration(point.seconds))"))
                        .accessibilityValue(Text(valueText(point.value)))
                } else {
                    AreaMark(x: .value(String(localized: "Time"), point.seconds), y: .value(unit == .packets ? String(localized: "Packets/s") : String(localized: "Bits/s"), point.value),
                             stacking: .standard)
                        .foregroundStyle(by: .value("Protocol", point.series))
                        .interpolationMethod(.stepEnd)
                        .accessibilityLabel(Text("\(point.series), \(Formatters.duration(point.seconds))"))
                        .accessibilityValue(Text(valueText(point.value)))
                }
            }
            .chartForegroundStyleScale(domain: seriesNames, range: seriesNames.map { name in
                unit == .bits ? Theme.acc : ProtocolPalette.color(for: name, in: protocols)
            })
            .chartXAxis {
                AxisMarks(values: .automatic(desiredCount: 8)) { value in
                    AxisGridLine().foregroundStyle(Theme.grid)
                    AxisValueLabel {
                        if let seconds = value.as(Double.self) {
                            Text(Formatters.duration(seconds))
                        } else if let label = value.as(String.self) {
                            Text(label)
                        }
                    }
                    .font(.wp(10)).foregroundStyle(Theme.fg3)
                }
            }
            .chartYAxis {
                AxisMarks(position: .leading) { value in
                    AxisGridLine().foregroundStyle(Theme.grid)
                    AxisValueLabel {
                        if let number = value.as(Double.self) {
                            Text(unit == .packets ? Formatters.compact(Int(number)) : Formatters.bits(number))
                        }
                    }
                    .font(.wp(10)).foregroundStyle(Theme.fg3)
                }
            }
            .chartLegend(position: .top, alignment: .leading)
            .frame(height: 210)
            .padding(EdgeInsets(top: 10, leading: 14, bottom: 12, trailing: 14))
        }
        .card()
    }
}

struct ProtocolDistributionCard: View {
    var protocols: [ProtocolCount]
    var totalPackets: Int

    var body: some View {
        VStack(spacing: 0) {
            let shown = Array(protocols.prefix(10))
            CardHeader(title: String(localized: "Protocols"),
                       subtitle: protocols.count > shown.count ? String(localized: "share of packets · top \(shown.count) of \(protocols.count)")
                           : String(localized: "share of packets")) { EmptyView() }
            Chart(Array(shown.enumerated()), id: \.element.name) { index, item in
                BarMark(x: .value("Packets", item.packets), y: .value("Protocol", item.name), height: .fixed(12))
                    .foregroundStyle(ProtocolPalette.color(for: index))
                    .annotation(position: .trailing, alignment: .leading) {
                        Text(percent(item.packets)).font(.wp(10.5)).foregroundStyle(Theme.fg2).monospacedDigit()
                    }
                    .accessibilityLabel(Text(item.name))
                    .accessibilityValue(Text("\(item.packets) packets, \(percent(item.packets))"))
            }
            .chartXAxis(.hidden)
            .chartYAxis {
                AxisMarks { _ in AxisValueLabel().font(.wp(11)).foregroundStyle(Theme.fg2) }
            }
            .frame(height: max(96, CGFloat(shown.count) * 30))
            .padding(EdgeInsets(top: 10, leading: 14, bottom: 12, trailing: 40))
        }
        .card()
    }

    private func percent(_ packets: Int) -> String {
        totalPackets > 0 ? String(format: "%.1f%%", Double(packets) / Double(totalPackets) * 100) : "—"
    }
}

struct PacketSizesCard: View {
    var buckets: [PacketSizeBucket]

    var body: some View {
        VStack(spacing: 0) {
            CardHeader(title: String(localized: "Packet Sizes"), subtitle: String(localized: "bytes on the wire")) { EmptyView() }
            Chart(buckets, id: \.lowerBound) { bucket in
                // Axis labels show each bucket's lower bound (full ranges would overlap); VoiceOver reads the range.
                BarMark(x: .value("Size", bucket.upperBound == nil ? "\(bucket.lowerBound)+" : "\(bucket.lowerBound)"),
                        y: .value("Packets", bucket.packets))
                    .foregroundStyle(Theme.acc)
                    .accessibilityLabel(Text(String(localized: "\(bucket.label) bytes")))
                    .accessibilityValue(Text("\(bucket.packets) packets"))
            }
            .chartXAxis {
                AxisMarks { _ in AxisValueLabel().font(.wp(9.5)).foregroundStyle(Theme.fg3) }
            }
            .chartYAxis {
                AxisMarks(position: .leading) { value in
                    AxisGridLine().foregroundStyle(Theme.grid)
                    AxisValueLabel { if let n = value.as(Int.self) { Text(Formatters.compact(n)) } }.font(.wp(10)).foregroundStyle(Theme.fg3)
                }
            }
            .frame(height: 200)
            .padding(EdgeInsets(top: 10, leading: 14, bottom: 12, trailing: 14))
        }
        .card()
    }
}

struct TopEndpointsCard: View {
    var document: AnalysisDocument
    @State private var selection: IPAddress?

    var body: some View {
        let endpoints = Array(Conversations.endpoints(document.flows).prefix(20))
        VStack(alignment: .leading, spacing: 8) {
            Text("Top Endpoints").font(.wp(13, .semibold)).foregroundStyle(Theme.fg)
            DataTable(columns: [.flexible(String(localized: "Address")), .fixed(String(localized: "Packets"), 80, .trailing), .fixed(String(localized: "Sent"), 80, .trailing, from: .regular),
                                .fixed(String(localized: "Received"), 80, .trailing, from: .regular), .fixed(String(localized: "Flows"), 56, .trailing)],
                      ids: endpoints.map(\.address), selection: $selection,
                      emptyText: String(localized: "No IP traffic"),
                      cells: { address in
                          guard let e = endpoints.first(where: { $0.address == address }) else { return [] }
                          return [.mono(e.address.description), .text(Formatters.count(e.packets)), .text(Formatters.bytes(e.bytesSent)),
                                  .text(Formatters.bytes(e.bytesReceived)), .text("\(e.flows)")]
                      })
                .frame(height: min(360, CGFloat(max(endpoints.count, 3)) * 26 + 30))
        }
    }
}

struct TopConversationsCard: View {
    var document: AnalysisDocument
    @State private var selection: String?

    var body: some View {
        let conversations = Array(Conversations.ip(document.flows).prefix(20))
        VStack(alignment: .leading, spacing: 8) {
            Text("Top Conversations").font(.wp(13, .semibold)).foregroundStyle(Theme.fg)
            DataTable(columns: [.flexible(String(localized: "Address A")), .flexible(String(localized: "Address B")), .fixed(String(localized: "Packets"), 80, .trailing),
                                .fixed(String(localized: "Bytes"), 80, .trailing, from: .regular), .fixed(String(localized: "Flows"), 56, .trailing, from: .regular)],
                      ids: conversations.map(\.id), selection: $selection,
                      emptyText: String(localized: "No IP traffic"),
                      cells: { id in
                          guard let c = conversations.first(where: { $0.id == id }) else { return [] }
                          return [.mono(c.addressA.description), .mono(c.addressB.description), .text(Formatters.count(c.packets)),
                                  .text(Formatters.bytes(c.bytes)), .text("\(c.flows.count)")]
                      })
                .frame(height: min(360, CGFloat(max(conversations.count, 3)) * 26 + 30))
        }
    }
}

struct TransportCard: View {
    var document: AnalysisDocument

    var body: some View {
        let flows = document.flows
        let tcp = TransportSummary.of(flows, transport: .tcp)
        let udp = TransportSummary.of(flows, transport: .udp)
        let tcpStats = flows.compactMap(\.tcp)
        MetricStrip(items: [
            .init(label: String(localized: "TCP"), value: Formatters.count(tcp.flows), unit: String(localized: "connections"),
                  caption: String(localized: "\(tcp.packets) packets · \(Formatters.bytes(tcp.bytes))")),
            .init(label: String(localized: "TCP Problems"), value: Formatters.count(tcpStats.reduce(0) { $0 + $1.problemCount }),
                  caption: String(localized: "retransmissions, gaps, dup ACKs, zero windows")),
            .init(label: String(localized: "UDP"), value: Formatters.count(udp.flows), unit: String(localized: "flows"),
                  caption: String(localized: "\(udp.packets) packets · \(Formatters.bytes(udp.bytes))")),
            .init(label: String(localized: "Other IP"), value: Formatters.count(flows.count - tcp.flows - udp.flows), unit: String(localized: "flows")),
        ])
    }
}
