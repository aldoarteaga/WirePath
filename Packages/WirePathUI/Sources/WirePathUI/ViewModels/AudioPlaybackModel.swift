import WirePathCore
#if os(iOS)
import AVFAudio
#endif
import Foundation
import Observation
import UniformTypeIdentifiers

/// Plays a call's or a stream's audio: reconstructs the RTP (off the main actor) and drives the core `AudioEngine`.
/// Each direction of a call is on its own side (caller left, callee right).
@Observable @MainActor
final class AudioPlaybackModel {
    enum State: Equatable {
        case idle
        case preparing
        case ready
        /// Nothing could be reconstructed; the message says why.
        case unavailable(String)
    }

    /// One stream offered for playback, playable or not.
    struct Track: Identifiable {
        var id: Int { stream.id }
        var stream: RTPStreamRecord
        var label: String
        var pan: Float
        var playability: AudioPlayability
        /// Filled once reconstructed.
        var audio: ReconstructedAudio?
        var muted: Bool
    }

    private(set) var state = State.idle
    private(set) var tracks: [Track] = []
    private(set) var isPlaying = false
    private(set) var currentTime = 0.0
    private(set) var duration = 0.0

    private var engine: AudioEngine?
    private var aligned: [AudioTrack] = []
    private var playableIndices: [Int] = []
    private var ticker: Task<Void, Never>?
    private var preparation: Task<Void, Never>?
    private let registry: AudioCodecRegistry

    init(registry: AudioCodecRegistry = .standard) {
        self.registry = registry
    }

    /// The streams of a call: one per direction plays by default; further legs of the same direction (the same audio
    /// relayed through a B2BUA or media server) start muted.
    static func tracks(for call: CallRecord, result: AnalysisResult, registry: AudioCodecRegistry) -> [Track] {
        var tracks: [Track] = []
        func add(_ indices: [Int], label: String, pan: Float) {
            for (offset, index) in indices.enumerated() where index < result.streams.count {
                let stream = result.streams[index]
                tracks.append(Track(stream: stream, label: offset == 0 ? label : String(localized: "\(label) · leg \(offset + 1)"), pan: pan,
                                    playability: registry.playability(of: stream), audio: nil, muted: offset > 0))
            }
        }
        let forward = call.quality?.forward?.streamIndices ?? []
        let reverse = call.quality?.reverse?.streamIndices ?? []
        add(forward, label: String(localized: "\(call.caller.user) → \(call.callee.user)"), pan: -1)
        add(reverse, label: String(localized: "\(call.callee.user) → \(call.caller.user)"), pan: 1)
        // Streams of the call not attributed to a direction.
        let known = Set(forward + reverse)
        add(call.streamIndices.filter { !known.contains($0) }, label: String(localized: "Other stream"), pan: 0)
        return tracks
    }

    static func tracks(for stream: RTPStreamRecord, registry: AudioCodecRegistry) -> [Track] {
        [Track(stream: stream, label: "\(stream.source) → \(stream.destination)", pan: 0,
               playability: registry.playability(of: stream), audio: nil, muted: false)]
    }

    /// Whether anything offered can be played.
    var canPlay: Bool { tracks.contains { $0.playability.isPlayable } }

    /// Shows the tracks without reconstructing them yet.
    func offer(_ tracks: [Track]) {
        stop()
        preparation?.cancel()
        engine = nil
        self.tracks = tracks
        state = .idle
        duration = 0
        currentTime = 0
    }

    func offer(call: CallRecord, result: AnalysisResult) {
        guard tracks.map(\.id) != Self.tracks(for: call, result: result, registry: registry).map(\.id) else { return }
        offer(Self.tracks(for: call, result: result, registry: registry))
    }

    func offer(stream: RTPStreamRecord) {
        guard tracks.map(\.id) != [stream.id] else { return }
        offer(Self.tracks(for: stream, registry: registry))
    }

    /// Decodes the playable tracks ahead of playback, so their details (losses, DTMF, duration) show at once.
    func preload(document: AnalysisDocument, callIndex: Int?) {
        guard state == .idle, canPlay else {
            if state == .idle, !canPlay, !tracks.isEmpty { state = .unavailable(Self.reason(tracks.first?.playability)) }
            return
        }
        prepare(document: document, callIndex: callIndex) {}
    }

    /// Reconstructs the playable tracks (once), then calls `then` on success.
    private func prepare(document: AnalysisDocument, callIndex: Int?, then: @escaping @MainActor () -> Void) {
        guard state != .preparing else { return }
        if state == .ready {
            then()
            return
        }
        let wanted = tracks.filter { $0.playability.isPlayable }.map(\.stream)
        guard !wanted.isEmpty else {
            state = .unavailable(Self.reason(tracks.first?.playability))
            return
        }
        let store: PacketStore
        do {
            store = try document.openPacketStore()
        } catch {
            state = .unavailable(error.localizedDescription)
            return
        }
        state = .preparing
        let registry = self.registry
        preparation = Task {
            let audio = await Task.detached(priority: .userInitiated) {
                await store.reconstructAudio(wanted, callIndex: callIndex, reconstructor: AudioReconstructor(registry: registry))
            }.value
            guard !Task.isCancelled else { return }
            self.finishPreparing(audio)
            if self.state == .ready { then() }
        }
    }

    private func finishPreparing(_ audio: [ReconstructedAudio]) {
        for (index, track) in tracks.enumerated() {
            tracks[index].audio = audio.first { $0.streamIndex == track.stream.id }
        }
        playableIndices = tracks.indices.filter { tracks[$0].audio != nil }
        guard !playableIndices.isEmpty else {
            state = .unavailable(String(localized: "No audio could be decoded from the captured packets"))
            return
        }
        aligned = AudioTrack.aligned(playableIndices.compactMap { index in tracks[index].audio.map { ($0, tracks[index].pan) } })
        do {
            let engine = try AudioEngine(tracks: aligned)
            engine.onFinish = { [weak self] in self?.playbackEnded() }
            for (position, index) in playableIndices.enumerated() where tracks[index].muted {
                engine.setMuted(true, track: position)
            }
            self.engine = engine
            duration = engine.duration
            state = .ready
        } catch {
            state = .unavailable(error.localizedDescription)
        }
    }

    // MARK: Transport

    func togglePlayback(document: AnalysisDocument, callIndex: Int?) {
        if isPlaying {
            pause()
        } else {
            prepare(document: document, callIndex: callIndex) { [weak self] in self?.play() }
        }
    }

    private func play() {
        guard let engine else { return }
        #if os(iOS)
        // Play through the speaker even with the Ring/Silent switch set to silent, like any media player.
        try? AVAudioSession.sharedInstance().setCategory(.playback, mode: .spokenAudio)
        try? AVAudioSession.sharedInstance().setActive(true)
        #endif
        do {
            try engine.play()
        } catch {
            state = .unavailable(error.localizedDescription)
            return
        }
        isPlaying = true
        startTicker()
    }

    func pause() {
        engine?.pause()
        isPlaying = false
        currentTime = engine?.currentTime ?? currentTime
        ticker?.cancel()
    }

    func stop() {
        engine?.stop()
        isPlaying = false
        currentTime = 0
        ticker?.cancel()
    }

    func seek(to seconds: Double) {
        guard let engine else { return }
        try? engine.seek(to: seconds)
        currentTime = engine.currentTime
    }

    func setMuted(_ muted: Bool, track id: Int) {
        guard let index = tracks.firstIndex(where: { $0.id == id }) else { return }
        tracks[index].muted = muted
        if let position = playableIndices.firstIndex(of: index) { engine?.setMuted(muted, track: position) }
    }

    private func playbackEnded() {
        isPlaying = false
        currentTime = duration
        ticker?.cancel()
    }

    private func startTicker() {
        ticker?.cancel()
        ticker = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .milliseconds(100))
                guard let self, let engine = self.engine else { return }
                self.currentTime = engine.currentTime
            }
        }
    }

    // MARK: Export

    /// WAV of the reconstructed audio (a call: stereo, caller left; a stream: mono). Reconstructs first if needed.
    func exportWAV(document: AnalysisDocument, callIndex: Int?, name: String, into window: WindowModel) {
        prepare(document: document, callIndex: callIndex) { [weak self] in
            guard let self else { return }
            let unmuted = self.playableIndices.enumerated().filter { !self.tracks[$0.element].muted }.map { self.aligned[$0.offset] }
            let data = unmuted.count == 1 && unmuted[0].pan == 0 ? AudioExport.wav(unmuted[0].audio) : AudioExport.stereoWAV(unmuted)
            window.pendingExport = try? ExportFile.temporary(data, filename: name + ".wav", contentType: .wav)
        }
    }

    /// Why nothing plays, for the first track.
    static func reason(_ playability: AudioPlayability?) -> String {
        switch playability {
        case .encrypted:
            return String(localized: "The media is encrypted (SRTP). The keys are not in the capture, so it cannot be decoded.")
        case .unsupported(let codec, .licensing):
            return String(localized: "\(codec) is not decoded: WirePath includes no decoder for licence-restricted codecs.")
        case .unsupported(let codec, .notImplemented):
            return String(localized: "\(codec) decoding is not implemented.")
        case .unsupported(let codec, .systemDecoderUnavailable):
            return String(localized: "This device has no \(codec) decoder.")
        case .unknownCodec(let pt):
            return String(localized: "Payload type \(pt) was not negotiated in captured SDP, so its codec is unknown.")
        case .notAudio(let what):
            return String(localized: "The stream carries \(what), not voice.")
        case .playable, nil:
            return String(localized: "No RTP was captured for this call.")
        }
    }
}
