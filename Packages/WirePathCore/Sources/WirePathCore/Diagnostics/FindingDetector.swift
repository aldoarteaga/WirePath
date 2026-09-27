import Foundation

/// Turns measured call/stream facts into findings. Every finding quotes the measurement behind it.
public enum FindingDetector {
    public static func findings(for call: CallRecord, streams: [RTPStreamRecord], messages: [SIPMessageRecord],
                                firstID: Int) -> [Finding] {
        var result: [Finding] = []
        let callFilter = "call == \(call.id + 1)"
        func add(_ severity: Severity, _ kind: FindingKind, _ title: String, _ detail: String,
                 stream: Int? = nil, time: Timestamp? = nil, end: Timestamp? = nil, frames: [Int] = [], filter: String? = nil) {
            let packetFilter = filter ?? stream.map { "stream == \($0 + 1)" } ?? (frames.isEmpty ? callFilter : nil)
            result.append(Finding(id: firstID + result.count, severity: severity, kind: kind, title: title,
                                  detail: detail, callIndex: call.id, streamIndex: stream, time: time, endTime: end,
                                  packetReferences: frames, packetFilter: packetFilter))
        }
        let callMessages = call.messageIndices.filter { $0 < messages.count }.map { messages[$0] }
        let route = "\(call.caller.user) → \(call.callee.user)"
        let relative = { (t: Timestamp) in t.seconds(since: call.startTime) }

        // SIP outcome.
        switch call.state {
        case .failed, .rejected:
            let finals = callMessages.filter { !$0.isRequest && $0.statusCode == call.finalStatusCode && $0.cseqMethod == "INVITE" }
            add(.warning, .sipFailure, call.statusLabel, "\(route) · \(call.statusLabel)", time: call.endTime,
                frames: finals.map(\.frameNumber))
        case .noAnswer:
            let invites = callMessages.filter { $0.isRequest && $0.method == "INVITE" }
            add(.warning, .noFinalResponse, String(localized: "No final response", bundle: CoreLocalization.bundle), String(localized: "\(route) · INVITE never received a final response", bundle: CoreLocalization.bundle),
                time: call.startTime, frames: invites.map(\.frameNumber))
        default:
            break
        }

        let voice = call.streamIndices.filter { streams[$0].codec?.kind.isVoice ?? true }
        let talk = call.talkDurationSeconds ?? 0

        // Media presence.
        if call.state.wasAnswered && talk >= 2 {
            let quality = call.quality
            let forwardPackets = quality?.forward?.packets ?? 0
            let reversePackets = quality?.reverse?.packets ?? 0
            if voice.isEmpty {
                add(.warning, .noMedia, String(localized: "No RTP captured", bundle: CoreLocalization.bundle),
                    String(localized: "\(route) · answered call with no RTP in the capture (media may have taken another path)", bundle: CoreLocalization.bundle),
                    time: call.answerTime)
            } else if forwardPackets == 0 || reversePackets == 0
                        || Double(min(forwardPackets, reversePackets)) < Double(max(forwardPackets, reversePackets)) * 0.05 {
                let silentSide = forwardPackets <= reversePackets ? call.caller.user : call.callee.user
                let heardSide = forwardPackets <= reversePackets ? call.callee.user : call.caller.user
                add(.error, .oneWayAudio, String(localized: "One-way audio", bundle: CoreLocalization.bundle),
                    String(localized: "\(route) · RTP only from \(heardSide); \(min(forwardPackets, reversePackets)) packets from \(silentSide)", bundle: CoreLocalization.bundle),
                    time: call.answerTime)
            }
        }

        // Combined quality summary (the "Needs Attention" line).
        if let quality = call.quality {
            var phrases: [String] = []
            var severity: Severity = .ok
            if let loss = quality.lossPercent, loss > QualityThresholds.lossWarningPercent {
                phrases.append(String(localized: "packet loss \(Format.percent(loss))", bundle: CoreLocalization.bundle))
                severity = max(severity, QualityThresholds.severity(lossPercent: loss))
            }
            if let jitter = quality.meanJitterMs, jitter > QualityThresholds.jitterWarningMs {
                phrases.append(String(localized: "jitter \(Format.ms(jitter))", bundle: CoreLocalization.bundle))
                severity = max(severity, QualityThresholds.severity(jitterMs: jitter))
            } else if let peak = quality.maxJitterMs, peak > QualityThresholds.jitterSpikeMs {
                phrases.append(String(localized: "jitter spikes to \(Format.ms(peak))", bundle: CoreLocalization.bundle))
                severity = max(severity, .warning)
            }
            let bursts = mergedBursts(voice.map { streams[$0] })
            if let largest = bursts.max(by: { $0.lost < $1.lost }) {
                phrases.append(String(localized: "a loss burst at +\(Int(relative(largest.start).rounded())) s", bundle: CoreLocalization.bundle))
                severity = max(severity, .warning)
            }
            if let mos = quality.mos, mos < QualityThresholds.mosWarning {
                severity = max(severity, QualityThresholds.severity(mos: mos))
            }
            if severity >= .warning || (quality.mos ?? 5) < QualityThresholds.mosWarning {
                // Phrases are joined by the language's list rules ("A, B and C" / "A, B y C").
                var text = phrases.isEmpty ? String(localized: "Low estimated quality", bundle: CoreLocalization.bundle)
                    : ListFormatter.localizedString(byJoining: phrases)
                text = text.prefix(1).uppercased() + text.dropFirst()
                if let mos = quality.mos {
                    text += " — MOS \(String(format: "%.2f", mos)) (\(QualityRating(mos: mos).localizedName))"
                }
                add(max(severity, .warning), .poorQuality, String(localized: "Poor call quality", bundle: CoreLocalization.bundle), text, time: call.answerTime ?? call.startTime,
                    filter: "\(callFilter) and (rtp.seq_gap or rtp.duplicate or rtp.out_of_order)")
            }

            // Detailed events used by the investigation view and timeline.
            // Report the largest bursts individually (the summary line above already mentions the first one).
            let reported = bursts.sorted { $0.lost > $1.lost }.prefix(5).sorted { $0.start < $1.start }
            for burst in reported {
                let directions: String = burst.directions == 2 ? String(localized: "both directions", bundle: CoreLocalization.bundle) : burst.label
                let from = String(format: "%.1f", relative(burst.start))
                let to = String(format: "%.1f", relative(burst.end))
                let detail = String(localized: "Loss burst at +\(from) – \(to) s · \(burst.lost) packets, \(directions)", bundle: CoreLocalization.bundle)
                add(.warning, .lossBurst, String(localized: "Loss burst · \(burst.lost) packets", bundle: CoreLocalization.bundle), detail, time: burst.start, end: burst.end,
                    filter: "\(callFilter) and rtp.seq_gap")
            }
            for index in voice {
                let stream = streams[index]
                if let peak = stream.maxJitterMs, peak > QualityThresholds.jitterSpikeMs, let time = stream.maxJitterTime {
                    let at = String(format: "%.1f", relative(time))
                    let detail = String(localized: "Jitter peak \(Format.ms(peak)) on \(label(stream, call)) at +\(at) s", bundle: CoreLocalization.bundle)
                    add(.warning, .jitterSpike, String(localized: "Jitter \(Int(peak.rounded())) ms", bundle: CoreLocalization.bundle), detail, stream: index, time: time)
                }
                if stream.outOfOrderPackets > 0 && Double(stream.outOfOrderPackets) / Double(max(1, stream.packetCount)) > 0.01 {
                    add(.info, .outOfOrder, String(localized: "Reordered packets", bundle: CoreLocalization.bundle),
                        String(localized: "\(stream.outOfOrderPackets) out-of-order packets on \(label(stream, call))", bundle: CoreLocalization.bundle), stream: index,
                        filter: "stream == \(index + 1) and rtp.out_of_order")
                }
            }
        }

        // SSRC changes without renegotiation.
        for index in call.streamIndices {
            let stream = streams[index]
            guard let previous = stream.replacesSSRC else { continue }
            let reinvite = call.messageIndices.contains { index -> Bool in
                let message = messages[index]
                guard message.isRequest, message.method == "INVITE" || message.method == "UPDATE" else { return false }
                guard message.cseq > 1, message.time > call.startTime else { return false }
                let distance: Double = abs(message.time.seconds(since: stream.firstTime))
                return distance < 5
            }
            let at = String(format: "%.3f", relative(stream.firstTime))
            let change = String(format: "0x%08X", previous) + " → " + stream.ssrcHex
            let detail = reinvite ? String(localized: "SSRC change on \(label(stream, call)) at +\(at) s · \(change)", bundle: CoreLocalization.bundle)
                : String(localized: "SSRC change on \(label(stream, call)) at +\(at) s · \(change) · no re-INVITE", bundle: CoreLocalization.bundle)
            add(.info, .ssrcChange, String(localized: "SSRC change", bundle: CoreLocalization.bundle), detail, stream: index, time: stream.firstTime)
        }

        // Excessive retransmissions hint at signalling loss.
        let retransmitted = callMessages.filter(\.isRetransmission)
        if retransmitted.count >= 3 {
            add(.info, .sipRetransmissions, String(localized: "SIP retransmissions", bundle: CoreLocalization.bundle),
                String(localized: "\(retransmitted.count) retransmitted SIP messages in \(route)", bundle: CoreLocalization.bundle),
                frames: retransmitted.map(\.frameNumber))
        }
        return result
    }

    static func label(_ stream: RTPStreamRecord, _ call: CallRecord) -> String {
        let from = stream.source.address == call.caller.signalling.address ? call.caller.user
            : stream.source.address == call.callee.signalling.address ? call.callee.user : "\(stream.source.address)"
        let to = stream.destination.address == call.caller.signalling.address ? call.caller.user
            : stream.destination.address == call.callee.signalling.address ? call.callee.user : "\(stream.destination.address)"
        return "\(from) → \(to)"
    }

    struct MergedBurst {
        var start: Timestamp
        var end: Timestamp
        var lost: Int
        var directions: Int
        var label: String
    }

    /// Merges overlapping bursts from the call's streams (so a burst seen both ways is reported once).
    static func mergedBursts(_ streams: [RTPStreamRecord]) -> [MergedBurst] {
        var items: [(burst: LossBurst, stream: RTPStreamRecord)] = []
        for stream in streams { for burst in stream.lossBursts { items.append((burst, stream)) } }
        items.sort { $0.burst.start < $1.burst.start }
        var merged: [MergedBurst] = []
        var directionKeys: [[String]] = []
        for item in items {
            let key = "\(item.stream.source)>\(item.stream.destination)"
            if var last = merged.last, item.burst.start <= last.end.adding(seconds: 1) {
                last.end = max(last.end, item.burst.end)
                last.lost += item.burst.lostPackets
                var keys = directionKeys[directionKeys.count - 1]
                if !keys.contains(key) { keys.append(key) }
                directionKeys[directionKeys.count - 1] = keys
                last.directions = keys.count
                merged[merged.count - 1] = last
            } else {
                merged.append(MergedBurst(start: item.burst.start, end: item.burst.end, lost: item.burst.lostPackets,
                                          directions: 1, label: "\(item.stream.source.address) → \(item.stream.destination.address)"))
                directionKeys.append([key])
            }
        }
        return merged
    }
}

/// Number formatting shared by findings and summaries.
public enum Format {
    public static func percent(_ value: Double) -> String {
        value >= 10 ? String(format: "%.1f%%", value) : String(format: "%.2f%%", value)
    }

    public static func ms(_ value: Double) -> String { String(format: "%.1f ms", value) }
}
