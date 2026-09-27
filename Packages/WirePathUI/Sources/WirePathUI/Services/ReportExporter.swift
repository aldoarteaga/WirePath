import WirePathCore
import Foundation
import UniformTypeIdentifiers

/// Builds a self-contained HTML report (opens in any browser, prints to PDF). Presented for saving
/// through `.fileExporter` by the window, so it works the same on macOS and iPadOS.
enum ReportExporter {
    static func exportFile(result: AnalysisResult, name: String) throws -> ExportFile {
        let data = Data(html(for: result, name: name).utf8)
        return try ExportFile.temporary(data, filename: ((name as NSString).deletingPathExtension) + " report.html",
                                        contentType: .html)
    }

    static func html(for result: AnalysisResult, name: String) -> String {
        func esc(_ text: String) -> String {
            text.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;")
                .replacingOccurrences(of: ">", with: "&gt;")
        }
        let v = result.voip
        let capture = result.capture
        /// A label in the interface language, escaped for HTML.
        func L(_ text: LocalizedStringResource) -> String { esc(String(localized: text)) }
        var calls = ""
        for call in result.calls {
            let q = call.quality
            calls += "<tr class=\"s\(call.severity.rawValue)\"><td>\(Formatters.clock(call.startTime))</td><td>\(call.talkDurationSeconds.map(Formatters.duration) ?? "—")</td><td>\(esc(call.caller.user)) <span>\(esc(call.caller.displayName ?? ""))</span></td><td>\(esc(call.callee.user)) <span>\(esc(call.callee.displayName ?? ""))</span></td><td class=m>\(call.caller.signalling.address)</td><td class=m>\(call.callee.signalling.address)</td><td>\(esc(call.statusLabel))</td><td>\(esc(call.codec?.displayName ?? "—"))</td><td class=r>\(Formatters.mos(q?.mos))</td><td class=r>\(Formatters.ms(q?.meanJitterMs))</td><td class=r>\(Formatters.percent(q?.lossPercent))</td></tr>\n"
        }
        var findings = ""
        for finding in result.findings {
            let label = ["OK", String(localized: "Info"), String(localized: "Warning"), String(localized: "Error")][finding.severity.rawValue]
            findings += "<tr class=\"s\(finding.severity.rawValue)\"><td>\(label)</td><td>\(finding.callIndex.map { Formatters.clock(result.calls[$0].startTime) } ?? "")</td><td>\(esc(finding.detail))</td></tr>\n"
        }
        var streams = ""
        for s in result.streams {
            streams += "<tr><td class=m>\(s.ssrcHex)</td><td class=m>\(s.source) → \(s.destination)</td><td>\(esc(s.codecName))</td><td class=r>\(Formatters.count(s.packetCount))</td><td class=r>\(s.lostPackets) (\(String(format: "%.2f", s.lossPercent))%)</td><td class=r>\(Formatters.ms(s.meanJitterMs))</td><td class=r>\(Formatters.ms(s.maxJitterMs))</td><td class=r>\(Formatters.mos(s.mos))</td></tr>\n"
        }
        var webrtc = ""
        for session in result.webrtc.sessions {
            let severity = session.state == .failed ? 3 : 0
            let selected = session.selected.map { "\($0.local) (\($0.localKind.label)) → \($0.remote) (\($0.remoteKind.label))" } ?? "—"
            let dtls = session.dtls.map { $0.established ? String(localized: "Established") : String(localized: "Incomplete") } ?? "—"
            let succeeded = session.pairs.filter { $0.state == .succeeded }.count
            webrtc += "<tr class=\"s\(severity)\"><td>\(esc(WebRTCScreen.stateName(session.state)))</td><td>\(Formatters.clock(session.firstTime))</td><td class=m>\(esc(session.ufrags.joined(separator: " ↔ ")))</td><td class=m>\(esc(selected))</td><td class=r>\(succeeded)/\(session.pairs.count)</td><td class=r>\(Formatters.ms(session.selected?.meanRTTMs))</td><td>\(dtls)</td><td class=r>\(session.streamIndices.count)</td></tr>\n"
        }
        let webrtcSection = webrtc.isEmpty ? "" : """
        <h2>\(L("WebRTC Sessions"))</h2>
        <table><tr><th>\(L("State"))</th><th>\(L("Start"))</th><th>\(L("ICE ufrags"))</th><th>\(L("Selected pair"))</th><th class=r>\(L("Pairs OK"))</th><th class=r>RTT</th><th>DTLS</th><th class=r>\(L("Streams"))</th></tr>\(webrtc)</table>
        """
        return """
        <!doctype html><html lang="\(Locale.current.language.languageCode?.identifier ?? "en")"><head><meta charset="utf-8"><title>\(esc(name)) — \(L("WirePath report"))</title>
        <style>
        body{font:13px -apple-system,BlinkMacSystemFont,"SF Pro Text",sans-serif;color:#1D1D1F;margin:32px;font-variant-numeric:tabular-nums}
        h1{font-size:22px;margin:0 0 4px}h2{font-size:15px;margin:28px 0 8px}p.sub{color:#5E5E65;margin:0 0 16px}
        .grid{display:grid;grid-template-columns:repeat(4,1fr);gap:0;border:1px solid rgba(0,0,0,.085);border-radius:10px}
        .grid div{padding:12px 14px;border-left:1px solid rgba(0,0,0,.085)}.grid div:first-child{border-left:0}
        .grid b{display:block;font-size:24px;font-weight:600}.grid span{font-size:11px;color:#5E5E65}
        table{border-collapse:collapse;width:100%;font-size:12px}th{text-align:left;font-weight:500;color:#5E5E65;background:#F5F5F7;padding:6px 8px}
        td{padding:5px 8px;border-top:1px solid rgba(0,0,0,.06)}td span{color:#6C6C73}.m{font-family:"SF Mono",Menlo,monospace;font-size:11.5px}.r{text-align:right}
        tr.s2 td:first-child{color:#A86400}tr.s3 td:first-child{color:#C63A2F}footer{margin-top:32px;color:#6C6C73;font-size:11px}
        </style></head><body>
        <h1>\(esc(name))</h1>
        <p class="sub">\(Formatters.bytes(capture.fileSize)) · \(capture.format.label) · \(Formatters.range(capture.firstPacketTime, capture.lastPacketTime)) · \(L("\(capture.packetCount) packets"))</p>
        <div class="grid">
        <div><span>\(L("Calls"))</span><b>\(v.totalCalls)</b><span>\(L("\(v.answeredCalls) answered · \(v.failedCalls) failed · \(v.rejectedCalls) rejected · \(v.cancelledCalls) cancelled"))</span></div>
        <div><span>\(L("MOS (E-model estimate)"))</span><b>\(Formatters.mos(v.meanMOS))</b><span>\(L("min \(Formatters.mos(v.minMOS))"))</span></div>
        <div><span>Jitter</span><b>\(Formatters.ms(v.meanJitterMs))</b><span>\(L("max \(Formatters.ms(v.maxJitterMs))"))</span></div>
        <div><span>\(L("Packet loss"))</span><b>\(Formatters.percent(v.lossPercent))</b><span>\(L("\(v.lostPackets) of \(v.expectedPackets) packets"))</span></div>
        </div>
        <h2>\(L("Diagnostics"))</h2>
        <table><tr><th>\(L("Severity"))</th><th>\(L("Call"))</th><th>\(L("Detail"))</th></tr>\(findings.isEmpty ? "<tr><td colspan=3>\(L("No problems detected."))</td></tr>" : findings)</table>
        <h2>\(L("Calls"))</h2>
        <table><tr><th>\(L("Start"))</th><th>\(L("Duration"))</th><th>\(L("Caller"))</th><th>\(L("Callee"))</th><th>\(L("Source IP"))</th><th>\(L("Destination IP"))</th><th>\(L("SIP Status"))</th><th>\(L("Codec"))</th><th class=r>MOS</th><th class=r>Jitter</th><th class=r>\(L("Loss"))</th></tr>\(calls)</table>
        <h2>\(L("RTP Streams"))</h2>
        <table><tr><th>SSRC</th><th>\(L("Flow"))</th><th>\(L("Codec"))</th><th class=r>\(L("Packets"))</th><th class=r>\(L("Lost"))</th><th class=r>\(L("Mean jitter"))</th><th class=r>\(L("Max jitter"))</th><th class=r>MOS</th></tr>\(streams)</table>
        \(webrtcSection)
        <footer>\(L("Generated by WirePath. MOS values are ITU-T G.107 E-model estimates from codec and measured loss; network delay is not observable from a single capture point."))</footer>
        </body></html>
        """
    }
}
