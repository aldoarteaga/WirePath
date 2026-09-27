import WirePathCore
import SwiftUI

/// Header shown for analyses without results (analysing, failed, loading).
private struct PlainHeader: View {
    var item: AnalysisItem

    var body: some View {
        HeaderBar(title: item.name, subtitle: "\(Formatters.bytes(item.manifest.fileSize)) · \(item.manifest.originalPath)") {
            EmptyView()
        }
    }
}

struct AnalyzingView: View {
    @Environment(LibraryModel.self) private var library
    var item: AnalysisItem

    var body: some View {
        VStack(spacing: 0) {
            PlainHeader(item: item)
            VStack(spacing: 14) {
                Icon(Icons.captureFile, size: 40).foregroundStyle(Theme.fg3)
                Text("\(Formatters.phase(item.progress?.phase)) \(item.name)…")
                    .font(.wp(15, .semibold)).foregroundStyle(Theme.fg)
                LevelBar(fraction: item.progress?.fraction ?? 0).frame(width: 320)
                Text(detail).font(.wp(12)).foregroundStyle(Theme.fg2).monospacedDigit()
                if let progress = item.progress, progress.packetsProcessed > 0 {
                    // What has been found so far, while the rest of the capture is read.
                    MetricStrip(items: [
                        .init(label: String(localized: "Packets"), value: Formatters.count(progress.packetsProcessed)),
                        .init(label: String(localized: "Flows"), value: Formatters.count(progress.found.flows)),
                        .init(label: String(localized: "Protocols"), value: Formatters.count(progress.found.protocols)),
                        .init(label: String(localized: "SIP Messages"), value: Formatters.count(progress.found.sipMessages)),
                        .init(label: String(localized: "RTP Streams"), value: Formatters.count(progress.found.rtpStreams)),
                    ])
                    .frame(maxWidth: 900)
                    .padding(.horizontal, 22)
                    .accessibilityIdentifier("analysis.found")
                }
                Button("Stop Analysis") { library.cancelAnalysis(item) }
                    .macKeyboardShortcut(".", modifiers: .command)
                    .controlSize(.regular)
                    .padding(.top, 4)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private var detail: String {
        guard let progress = item.progress else { return String(localized: "Preparing…") }
        return String(localized: "\(Int((progress.fraction * 100).rounded()))% · \(Formatters.count(progress.packetsProcessed)) packets processed")
    }
}

struct ProblemView: View {
    @Environment(LibraryModel.self) private var library
    @Environment(WindowModel.self) private var window
    var item: AnalysisItem
    var title: String
    var message: String

    var body: some View {
        VStack(spacing: 0) {
            PlainHeader(item: item)
            VStack(spacing: 12) {
                StatusIcon(severity: .error, size: 32)
                Text(title).font(.wp(15, .semibold)).foregroundStyle(Theme.fg)
                Text(message).font(.wp(12)).foregroundStyle(Theme.fg2).multilineTextAlignment(.center).frame(maxWidth: 460)
                HStack(spacing: 10) {
                    Button("Re-analyze") { library.reanalyze(item) }
                    #if os(macOS)
                    Button("Show in Finder") { library.showInFinder(item) }
                    #endif
                    Button("Delete Analysis…", role: .destructive) { window.pendingDeletion = item }
                }
                .padding(.top, 6)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}

struct LoadingView: View {
    var item: AnalysisItem

    var body: some View {
        VStack(spacing: 0) {
            PlainHeader(item: item)
            ProgressView().controlSize(.small).frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}

/// First launch / empty library: invites importing or dropping captures.
struct EmptyLibraryView: View {
    @Environment(WindowModel.self) private var window

    var body: some View {
        VStack(spacing: 0) {
            HeaderBar(title: String(localized: "WirePath"), subtitle: String(localized: "VoIP capture analyzer")) { EmptyView() }
            VStack(spacing: 12) {
                Icon(Icons.dropFile, size: 44).foregroundStyle(Theme.acc)
                Text("Drop a capture to analyze").font(.wp(16, .semibold)).foregroundStyle(Theme.fg)
                Text(".pcap  .pcapng  .cap  .pcap.gz").font(.wpMono(11.5)).foregroundStyle(Theme.fg2)
                Button("Import PCAP…") { window.importFolders = false; window.showImporter = true }
                    .macKeyboardShortcut("i", modifiers: [.shift, .command])
                    .padding(.top, 4)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(RoundedRectangle(cornerRadius: 12).strokeBorder(Theme.line2, style: StrokeStyle(lineWidth: 1.5, dash: [6, 4])).padding(24))
        }
    }
}
