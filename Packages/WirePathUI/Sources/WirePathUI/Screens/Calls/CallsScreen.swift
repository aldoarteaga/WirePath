import WirePathCore
import SwiftUI

/// Calls list: the Overview's calls table at full height plus duration / setup statistics.
struct CallsScreen: View {
    @Environment(WindowModel.self) private var window
    @Bindable var document: AnalysisDocument

    private var result: AnalysisResult { document.result }

    var body: some View {
        VStack(spacing: 0) {
            HeaderBar(title: String(localized: "Calls"), subtitle: String(localized: "\(document.manifest.displayName) · \(result.calls.count) calls")) {
                OverviewHeaderControls(document: document)
            }
            VStack(spacing: 16) {
                HStack(alignment: .bottom, spacing: 16) {
                    ScreenTitle(title: String(localized: "Calls"), subtitle: subtitle)
                    Spacer(minLength: 8)
                    SeverityLegend()
                }
                MetricStrip(items: metrics)
                CallsSectionHeader(document: document, title: String(localized: "SIP Calls"))
                CallsTable(document: document)
            }
            .padding(EdgeInsets(top: 18, leading: 22, bottom: 16, trailing: 22))
            FooterBar(leading: footerLeading, trailing: footerTrailing)
        }
    }

    private var subtitle: String {
        let v = result.voip
        var parts = [String(localized: "\(v.answeredCalls) answered"), String(localized: "\(v.failedCalls) failed")]
        if v.rejectedCalls > 0 { parts.append(String(localized: "\(v.rejectedCalls) rejected")) }
        if v.cancelledCalls > 0 { parts.append(String(localized: "\(v.cancelledCalls) cancelled")) }
        parts.append(String(localized: "\(document.issueCalls.count) with quality issues"))
        return parts.joined(separator: " · ")
    }

    private var metrics: [MetricStrip.Item] {
        let v = result.voip
        let answered = result.calls.filter { $0.state.wasAnswered }
        let longest = answered.max { ($0.talkDurationSeconds ?? 0) < ($1.talkDurationSeconds ?? 0) }
        let shortest = answered.min { ($0.talkDurationSeconds ?? 0) < ($1.talkDurationSeconds ?? 0) }
        let setups = answered.compactMap(\.setupSeconds)
        let failedCodes = result.calls.filter { $0.state == .failed || $0.state == .noAnswer }.compactMap(\.finalStatusCode)
        let rejectedCodes = result.calls.filter { $0.state == .rejected }.compactMap(\.finalStatusCode)
        func route(_ call: CallRecord?) -> String? { call.map { "\($0.caller.user) → \($0.callee.user)" } }
        return [
            .init(label: String(localized: "Answered"), value: "\(v.answeredCalls)", caption: String(localized: "of \(v.totalCalls) calls")),
            .init(label: String(localized: "Failed"), value: "\(v.failedCalls)", caption: failedCodes.isEmpty ? String(localized: "No failures") : groupedCodes(failedCodes),
                  color: v.failedCalls > 0 ? Theme.warn : Theme.fg),
            .init(label: String(localized: "Rejected · Cancelled"), value: "\(v.rejectedCalls) · \(v.cancelledCalls)",
                  caption: rejectedCodes.isEmpty ? String(localized: "Declined or busy") : groupedCodes(rejectedCodes)),
            .init(label: String(localized: "Average Duration"), value: v.talkTime.map { Formatters.duration($0.mean) } ?? "—",
                  caption: v.talkTime.map { String(localized: "Talk time \(Formatters.hms($0.total))") }),
            .init(label: String(localized: "Longest"), value: v.talkTime.map { Formatters.duration($0.max) } ?? "—", caption: route(longest)),
            .init(label: String(localized: "Shortest"), value: v.talkTime.map { Formatters.duration($0.min) } ?? "—", caption: route(shortest)),
            .init(label: String(localized: "Average Setup"), value: setups.isEmpty ? "—" : String(format: "%.2f", setups.reduce(0, +) / Double(setups.count)),
                  unit: setups.isEmpty ? nil : "s", caption: String(localized: "INVITE → 200 OK")),
        ]
    }

    private var footerLeading: String {
        String(localized: "\(document.visibleCalls.count) shown · \(result.calls.count) calls")
    }

    private var footerTrailing: String {
        guard let index = document.selectedCall, index < result.calls.count else { return String(localized: "No selection") }
        let call = result.calls[index]
        return String(localized: "1 selected · \(Formatters.clock(call.startTime)) · \(call.caller.user) → \(call.callee.user)")
    }
}
