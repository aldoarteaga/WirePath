import WirePathCore
import SwiftUI

/// Audio reconstructed from RTP (spec flow: … → Jitter/Loss → Audio): transport, position, and each stream with what
/// was decoded (codec, losses concealed, comfort noise, DTMF keys) or why it cannot be.
struct AudioCard: View {
    @Environment(WindowModel.self) private var window
    @Environment(\.layoutWidth) private var layoutWidth
    var model: AudioPlaybackModel
    var document: AnalysisDocument
    var callIndex: Int?
    var exportName: String
    var subtitle: String

    var body: some View {
        VStack(spacing: 0) {
            CardHeader(title: String(localized: "Audio"), subtitle: layoutWidth == .compact ? nil : subtitle) {
                PillButton(icon: Icons.export, iconSize: 14, title: String(localized: "Export WAV"),
                           help: String(localized: "Save the reconstructed audio as a WAV file"), isEnabled: model.canPlay) {
                    model.exportWAV(document: document, callIndex: callIndex, name: exportName, into: window)
                }
            }
            transport
                .padding(EdgeInsets(top: 12, leading: 14, bottom: 10, trailing: 14))
            VStack(spacing: 0) {
                ForEach(model.tracks) { track in
                    row(track)
                }
            }
            .overlay(alignment: .top) { Rectangle().fill(Theme.line).frame(height: 1) }
            if case .unavailable(let message) = model.state {
                HStack(spacing: 8) {
                    StatusIcon(severity: .warning, size: 12)
                    Text(message).font(.wp(12)).foregroundStyle(Theme.fg2)
                    Spacer(minLength: 0)
                }
                .padding(EdgeInsets(top: 10, leading: 14, bottom: 12, trailing: 14))
            }
        }
        .card()
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("audio.card")
    }

    private var transport: some View {
        HStack(spacing: 12) {
            IconButton(icon: model.isPlaying ? Icons.pause : Icons.play, iconSize: 13, width: 32, height: 28, tint: Theme.fg,
                       help: model.isPlaying ? String(localized: "Pause") : String(localized: "Play"), isEnabled: model.canPlay) {
                model.togglePlayback(document: document, callIndex: callIndex)
            }
            .background(RoundedRectangle(cornerRadius: 7).fill(Theme.ctrl))
            .accessibilityIdentifier("audio.play")
            if model.state == .preparing {
                ProgressView().controlSize(.small)
                Text("Decoding…").font(.wp(12)).foregroundStyle(Theme.fg2)
                Spacer(minLength: 0)
            } else {
                Text(Self.clock(model.currentTime)).font(.wpMono(11.5)).foregroundStyle(Theme.fg).monospacedDigit()
                Slider(value: Binding(get: { model.currentTime }, set: { model.seek(to: $0) }),
                       in: 0...max(model.duration, 0.1))
                    .tint(Theme.acc)
                    .disabled(model.state != .ready)
                    .accessibilityLabel(String(localized: "Playback position"))
                Text(model.state == .ready ? Self.clock(model.duration) : "—:—").font(.wpMono(11.5)).foregroundStyle(Theme.fg2)
                    .monospacedDigit()
            }
        }
    }

    private func row(_ track: AudioPlaybackModel.Track) -> some View {
        HStack(spacing: 10) {
            StatusIcon(severity: track.playability.isPlayable ? (track.audio.map { $0.lostPackets > 0 ? .warning : .ok } ?? .ok) : .info,
                       size: 12)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(track.label).font(.wp(12.5, .medium)).foregroundStyle(Theme.fg).lineLimit(1)
                    if track.pan != 0 {
                        Text(track.pan < 0 ? String(localized: "Left") : String(localized: "Right")).font(.wp(11)).foregroundStyle(Theme.fg3)
                    }
                    Chip(text: track.stream.codecName, fontSize: 11, foreground: Theme.fg2)
                }
                Text(detail(track)).font(.wp(11.5)).foregroundStyle(Theme.fg2).lineLimit(2).monospacedDigit()
            }
            Spacer(minLength: 8)
            if track.playability.isPlayable {
                IconButton(icon: track.muted ? Icons.speakerMuted : Icons.speaker, iconSize: 15, width: 30, height: 26,
                           tint: track.muted ? Theme.fg3 : Theme.fg2,
                           help: track.muted ? String(localized: "Unmute") : String(localized: "Mute")) {
                    model.setMuted(!track.muted, track: track.id)
                }
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .accessibilityElement(children: .combine)
    }

    private func detail(_ track: AudioPlaybackModel.Track) -> String {
        guard track.playability.isPlayable else { return AudioPlaybackModel.reason(track.playability) }
        guard let audio = track.audio else {
            if case .playable(let decoder) = track.playability { return decoder }
            return ""
        }
        var parts = [String(format: "%.1f s · %d Hz", audio.durationSeconds, audio.sampleRate)]
        if audio.lostPackets > 0 { parts.append(String(localized: "\(audio.lostPackets) lost packets concealed")) }
        let silences = audio.gaps.filter { $0.cause == .silence }.count
        if silences > 0 { parts.append(String(localized: "\(silences) silent periods")) }
        if audio.comfortNoisePackets > 0 { parts.append(String(localized: "comfort noise")) }
        if !audio.dtmf.isEmpty { parts.append(String(localized: "DTMF \(audio.dtmf.map(\.key).joined(separator: " "))")) }
        if audio.failedPackets > 0 { parts.append(String(localized: "\(audio.failedPackets) packets not decoded")) }
        if audio.truncated { parts.append(String(localized: "truncated")) }
        return parts.joined(separator: " · ")
    }

    static func clock(_ seconds: Double) -> String {
        let total = max(0, Int(seconds.rounded(.down)))
        return String(format: "%d:%02d", total / 60, total % 60)
    }
}
