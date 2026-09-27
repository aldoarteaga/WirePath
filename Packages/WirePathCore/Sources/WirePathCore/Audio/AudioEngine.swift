import AVFAudio
import Foundation

/// A reconstructed stream placed in a mix: its audio, where it sits in the stereo field and on the timeline.
public struct AudioTrack: Sendable {
    public var audio: ReconstructedAudio
    /// −1 (left) … 1 (right).
    public var pan: Float
    /// Seconds from the start of the mix to the track's first sample.
    public var offsetSeconds: Double

    public init(audio: ReconstructedAudio, pan: Float, offsetSeconds: Double) {
        self.audio = audio
        self.pan = pan
        self.offsetSeconds = max(0, offsetSeconds)
    }

    public var endSeconds: Double { offsetSeconds + audio.durationSeconds }

    /// Constant-power left/right gains for the pan position (the stereo image is built here, not by the mixer, so it is
    /// identical in live and offline rendering).
    var gains: (left: Float, right: Float) {
        let angle = Double(max(-1, min(1, pan)) + 1) * .pi / 4
        return (Float(cos(angle)), Float(sin(angle)))
    }

    /// Writes `frames` samples starting at `begin` (silence outside the track) into a stereo buffer.
    func fill(_ buffer: AVAudioPCMBuffer, from begin: Int, frames: Int) {
        guard let channels = buffer.floatChannelData else { return }
        let (left, right) = gains
        let total = audio.samples.count
        audio.samples.withUnsafeBufferPointer { pcm in
            for n in 0..<frames {
                let index = begin + n
                let value = index >= 0 && index < total ? Float(pcm[index]) / 32768 : 0
                channels[0][n] = value * left
                channels[1][n] = value * right
            }
        }
        buffer.frameLength = AVAudioFrameCount(frames)
    }

    /// Places tracks on a common timeline starting at the earliest track.
    public static func aligned(_ tracks: [(audio: ReconstructedAudio, pan: Float)]) -> [AudioTrack] {
        guard let start = tracks.map(\.audio.startTime).min() else { return [] }
        return tracks.map { AudioTrack(audio: $0.audio, pan: $0.pan, offsetSeconds: $0.audio.startTime.seconds(since: start)) }
    }
}

/// Plays reconstructed streams with AVAudioEngine (spec §48: RTP stream → codec decoder → audio buffer → AVAudioEngine).
/// One player node per track, panned and started together; audio is scheduled in short chunks so memory stays at
/// the reconstructed 16-bit PCM. Independent of SIP and of the UI.
@MainActor
public final class AudioEngine {
    public private(set) var tracks: [AudioTrack]
    public let duration: Double
    public private(set) var isPlaying = false

    private let engine = AVAudioEngine()
    private var players: [AVAudioPlayerNode] = []
    private var formats: [AVAudioFormat] = []
    /// Next sample (relative to the track's own timeline, may be negative before its offset) to schedule, per track.
    private var cursors: [Int] = []
    private var queued: [Int] = []
    /// Where playback (re)started, in seconds, and the render time it started at.
    private var startPosition = 0.0
    private var pausedPosition = 0.0
    /// Incremented on every stop/seek so completions of discarded buffers are ignored.
    private var generation = 0
    /// Called on the main actor when playback reaches the end.
    public var onFinish: (() -> Void)?

    static let chunkSeconds = 1.0
    static let queuedChunks = 3

    public init(tracks: [AudioTrack]) throws {
        self.tracks = tracks
        duration = tracks.map(\.endSeconds).max() ?? 0
        for track in tracks {
            guard let format = AVAudioFormat(standardFormatWithSampleRate: Double(track.audio.sampleRate), channels: 2)
            else { throw AudioEngineError.unsupportedFormat }
            let player = AVAudioPlayerNode()
            engine.attach(player)
            engine.connect(player, to: engine.mainMixerNode, format: format)
            players.append(player)
            formats.append(format)
        }
        cursors = Array(repeating: 0, count: tracks.count)
        queued = Array(repeating: 0, count: tracks.count)
        engine.prepare()
    }

    public enum AudioEngineError: Error { case unsupportedFormat }

    /// Current playback position in seconds.
    public var currentTime: Double {
        guard isPlaying, let player = players.first, let nodeTime = player.lastRenderTime,
              let playerTime = player.playerTime(forNodeTime: nodeTime), playerTime.sampleRate > 0 else { return pausedPosition }
        return min(duration, startPosition + max(0, Double(playerTime.sampleTime) / playerTime.sampleRate))
    }

    public func play() throws {
        guard !isPlaying, !tracks.isEmpty else { return }
        if pausedPosition >= duration { pausedPosition = 0 }
        try start(at: pausedPosition)
    }

    public func pause() {
        guard isPlaying else { return }
        pausedPosition = currentTime
        halt()
    }

    public func stop() {
        halt()
        pausedPosition = 0
    }

    public func seek(to seconds: Double) throws {
        let target = min(max(0, seconds), duration)
        if isPlaying {
            halt()
            try start(at: target)
        } else {
            pausedPosition = target
        }
    }

    public func setMuted(_ muted: Bool, track: Int) {
        guard track < players.count else { return }
        players[track].volume = muted ? 0 : 1
    }

    private func halt() {
        generation += 1
        for player in players { player.stop() }
        engine.pause()
        isPlaying = false
    }

    private func start(at position: Double) throws {
        generation += 1
        startPosition = position
        pausedPosition = position
        for index in tracks.indices {
            let rate = Double(tracks[index].audio.sampleRate)
            cursors[index] = Int(((position - tracks[index].offsetSeconds) * rate).rounded())
            queued[index] = 0
        }
        if !engine.isRunning { try engine.start() }
        for index in tracks.indices {
            for _ in 0..<Self.queuedChunks { scheduleNext(index) }
        }
        // Start every player on the same render cycle so the directions stay aligned.
        let start = AVAudioTime(hostTime: mach_absolute_time() + AVAudioTime.hostTime(forSeconds: 0.05))
        for player in players { player.play(at: start) }
        isPlaying = true
    }

    /// Schedules the next chunk of a track (silence before its offset). Returns false at its end.
    @discardableResult
    private func scheduleNext(_ index: Int) -> Bool {
        let track = tracks[index]
        let rate = track.audio.sampleRate
        let total = track.audio.samples.count
        let begin = cursors[index]
        // Tracks end together (at the mix duration) so the last chunk of the shortest one does not end playback early.
        let mixEnd = Int((duration - track.offsetSeconds) * Double(rate))
        guard begin < max(total, mixEnd) else { return false }
        let frames = min(Int(Self.chunkSeconds * Double(rate)), max(total, mixEnd) - begin)
        guard frames > 0, let buffer = AVAudioPCMBuffer(pcmFormat: formats[index], frameCapacity: AVAudioFrameCount(frames))
        else { return false }
        track.fill(buffer, from: begin, frames: frames)
        cursors[index] = begin + frames
        queued[index] += 1
        let generation = self.generation
        players[index].scheduleBuffer(buffer, completionCallbackType: .dataPlayedBack) { [weak self] _ in
            Task { @MainActor in self?.chunkFinished(index, generation: generation) }
        }
        return true
    }

    private func chunkFinished(_ index: Int, generation: Int) {
        guard generation == self.generation, isPlaying else { return }
        queued[index] -= 1
        scheduleNext(index)
        if queued.allSatisfy({ $0 == 0 }) {
            halt()
            pausedPosition = duration
            onFinish?()
        }
    }

    // MARK: Offline rendering

    /// Renders the mix offline through the same engine graph (manual rendering), as interleaved stereo at `sampleRate`.
    /// Used by tests, and suitable for short mixes only (everything is scheduled at once).
    public static func renderOffline(_ tracks: [AudioTrack], sampleRate: Double = 48000) throws -> [Float] {
        let engine = AVAudioEngine()
        guard let output = AVAudioFormat(standardFormatWithSampleRate: sampleRate, channels: 2) else { throw AudioEngineError.unsupportedFormat }
        try engine.enableManualRenderingMode(.offline, format: output, maximumFrameCount: 4096)
        var players: [AVAudioPlayerNode] = []
        for track in tracks {
            guard let format = AVAudioFormat(standardFormatWithSampleRate: Double(track.audio.sampleRate), channels: 2)
            else { throw AudioEngineError.unsupportedFormat }
            let player = AVAudioPlayerNode()
            engine.attach(player)
            engine.connect(player, to: engine.mainMixerNode, format: format)
            let lead = Int(track.offsetSeconds * format.sampleRate)
            let frames = lead + track.audio.samples.count
            guard frames > 0, let buffer = AVAudioPCMBuffer(pcmFormat: format, frameCapacity: AVAudioFrameCount(frames)) else { continue }
            track.fill(buffer, from: -lead, frames: frames)
            player.scheduleBuffer(buffer, completionHandler: nil)
            players.append(player)
        }
        try engine.start()
        for player in players { player.play() }
        let duration = tracks.map(\.endSeconds).max() ?? 0
        var remaining = Int(duration * sampleRate)
        var mix: [Float] = []
        mix.reserveCapacity(remaining * 2)
        guard let block = AVAudioPCMBuffer(pcmFormat: engine.manualRenderingFormat, frameCapacity: 4096) else { return [] }
        while remaining > 0 {
            let frames = AVAudioFrameCount(min(4096, remaining))
            guard try engine.renderOffline(frames, to: block) == .success, let channels = block.floatChannelData else { break }
            for n in 0..<Int(block.frameLength) {
                mix.append(channels[0][n])
                mix.append(channels[1][n])
            }
            remaining -= Int(block.frameLength)
        }
        engine.stop()
        return mix
    }
}
