import Foundation

/// Aggregates per-call results into the Overview figures and the sidebar headline.
public enum SummaryBuilder {
    public static func voipSummary(calls: [CallRecord], streams: [RTPStreamRecord], findings: [Finding]) -> VoIPSummary {
        let answered = calls.filter { $0.state.wasAnswered }
        let issueKinds: Set<FindingKind> = [.poorQuality, .oneWayAudio, .noMedia]
        let callsWithIssues = Set(findings.filter { issueKinds.contains($0.kind) }.compactMap(\.callIndex)).count
        let mosValues = answered.compactMap { $0.quality?.mos }
        var histogram = [Int](repeating: 0, count: 5)
        for mos in mosValues { histogram[QualityThresholds.histogramBucket(mos: mos)] += 1 }
        let jitters = answered.compactMap { $0.quality?.meanJitterMs }
        let maxJitters = answered.compactMap { $0.quality?.maxJitterMs }

        var lost = 0, expected = 0, ooo = 0, dup = 0
        for call in answered {
            for index in call.streamIndices where streams[index].codec?.kind.isVoice ?? true {
                lost += max(0, streams[index].lostPackets)
                expected += streams[index].expectedPackets
                ooo += streams[index].outOfOrderPackets
                dup += streams[index].duplicatePackets
            }
        }

        var codecCounts: [String: Int] = [:]
        for call in answered { if let codec = call.codec { codecCounts[codec.kind == .unknown ? codec.displayName : codec.kind.familyName, default: 0] += 1 } }
        let usage = codecCounts.map { CodecUsage(name: $0.key, calls: $0.value) }
            .sorted { $0.calls != $1.calls ? $0.calls > $1.calls : $0.name < $1.name }

        let errorCodes = calls.filter { $0.state.isFailure }.compactMap(\.finalStatusCode)
        return VoIPSummary(
            totalCalls: calls.count, answeredCalls: answered.count,
            failedCalls: calls.filter { $0.state == .failed || $0.state == .noAnswer }.count,
            rejectedCalls: calls.filter { $0.state == .rejected }.count,
            cancelledCalls: calls.filter { $0.state == .cancelled }.count,
            callsWithIssues: callsWithIssues, talkTime: DurationStats(answered.compactMap(\.talkDurationSeconds)),
            meanMOS: mosValues.isEmpty ? nil : mosValues.reduce(0, +) / Double(mosValues.count), minMOS: mosValues.min(),
            mosHistogram: histogram, callsWithMOS: mosValues.count,
            meanJitterMs: jitters.isEmpty ? nil : jitters.reduce(0, +) / Double(jitters.count),
            maxJitterMs: maxJitters.max(),
            lossPercent: expected > 0 ? Double(lost) / Double(expected) * 100 : nil,
            lostPackets: lost, expectedPackets: expected, outOfOrderPackets: ooo, duplicatePackets: dup,
            sipErrorResponses: errorCodes, codecUsage: usage)
    }

    public static func headline(calls: [CallRecord], findings: [Finding], sipMessageCount: Int,
                                webrtcSessionCount: Int = 0) -> AnalysisHeadline {
        let oneWay = Set(findings.filter { $0.kind == .oneWayAudio }.compactMap(\.callIndex)).count
        if oneWay > 0 {
            return AnalysisHeadline(severity: .error, text: String(localized: "One-way audio · \(oneWay) calls", bundle: CoreLocalization.bundle))
        }
        if findings.contains(where: { $0.kind == .registrationFailure }) {
            return AnalysisHeadline(severity: .error, text: String(localized: "Registration failed", bundle: CoreLocalization.bundle))
        }
        if findings.contains(where: { $0.kind == .authenticationFailure }) {
            return AnalysisHeadline(severity: .error, text: String(localized: "Authentication failed", bundle: CoreLocalization.bundle))
        }
        let iceFailures = findings.filter { $0.kind == .iceFailure }.count
        if iceFailures > 0 {
            return AnalysisHeadline(severity: .error, text: String(localized: "ICE failed · \(iceFailures) sessions", bundle: CoreLocalization.bundle))
        }
        let sipErrors = calls.filter { $0.state.isFailure }.count
        if sipErrors > 0 {
            return AnalysisHeadline(severity: .warning, text: String(localized: "\(sipErrors) SIP errors", bundle: CoreLocalization.bundle))
        }
        if let worst = calls.compactMap({ $0.quality?.lossPercent }).max(), worst > QualityThresholds.lossWarningPercent {
            return AnalysisHeadline(severity: .warning, text: String(localized: "Packet loss \(String(format: "%.1f", worst))%", bundle: CoreLocalization.bundle))
        }
        let poor = Set(findings.filter { $0.kind == .poorQuality || $0.kind == .noMedia }.compactMap(\.callIndex)).count
        if poor > 0 {
            return AnalysisHeadline(severity: .warning, text: String(localized: "Quality issues · \(poor) calls", bundle: CoreLocalization.bundle))
        }
        let signalling = findings.filter { [.missingACK, .sipTimeout, .sipErrorResponses].contains($0.kind) }.count
        if signalling > 0 {
            return AnalysisHeadline(severity: .warning, text: String(localized: "SIP problems · \(signalling)", bundle: CoreLocalization.bundle))
        }
        if findings.contains(where: { $0.kind == .turnAllocationFailure || $0.kind == .stunTimeout || $0.kind == .dtlsFailure
            || $0.kind == .noMediaAfterICE }) {
            return AnalysisHeadline(severity: .warning, text: String(localized: "WebRTC problems", bundle: CoreLocalization.bundle))
        }
        if !calls.isEmpty || webrtcSessionCount > 0 { return AnalysisHeadline(severity: .ok, text: String(localized: "No issues", bundle: CoreLocalization.bundle)) }
        if sipMessageCount > 0 { return AnalysisHeadline(severity: .info, text: String(localized: "No calls · \(sipMessageCount) SIP messages", bundle: CoreLocalization.bundle)) }
        return AnalysisHeadline(severity: .info, text: String(localized: "No SIP traffic", bundle: CoreLocalization.bundle))
    }
}
