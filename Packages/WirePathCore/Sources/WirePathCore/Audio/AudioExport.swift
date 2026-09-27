import Foundation

/// WAV files from reconstructed audio (16-bit PCM), for saving a stream or a call.
public enum AudioExport {
    /// One stream, mono at its own sample rate.
    public static func wav(_ audio: ReconstructedAudio) -> Data {
        wav(interleaved: audio.samples, channels: 1, sampleRate: audio.sampleRate)
    }

    /// A call: each track mixed into the left or right channel by its pan (≤ 0 left, > 0 right), resampled to the
    /// highest track rate and placed at its offset.
    public static func stereoWAV(_ tracks: [AudioTrack]) -> Data {
        let rate = tracks.map(\.audio.sampleRate).max() ?? 8000
        let frames = min(AudioReconstructor.maxSamples, Int((tracks.map(\.endSeconds).max() ?? 0) * Double(rate)))
        var left = [Int32](repeating: 0, count: frames), right = [Int32](repeating: 0, count: frames)
        for track in tracks {
            let samples = track.audio.sampleRate == rate ? track.audio.samples
                : AudioReconstructor.resample(track.audio.samples, from: track.audio.sampleRate, to: rate)
            let offset = Int(track.offsetSeconds * Double(rate))
            for (n, sample) in samples.enumerated() {
                let position = offset + n
                guard position < frames else { break }
                if track.pan > 0 { right[position] += Int32(sample) } else { left[position] += Int32(sample) }
            }
        }
        var interleaved = [Int16](repeating: 0, count: frames * 2)
        for n in 0..<frames {
            interleaved[2 * n] = Int16(clamping: left[n])
            interleaved[2 * n + 1] = Int16(clamping: right[n])
        }
        return wav(interleaved: interleaved, channels: 2, sampleRate: rate)
    }

    static func wav(interleaved samples: [Int16], channels: Int, sampleRate: Int) -> Data {
        let dataBytes = samples.count * 2
        var data = Data(capacity: 44 + dataBytes)
        func u32(_ v: UInt32) { withUnsafeBytes(of: v.littleEndian) { data.append(contentsOf: $0) } }
        func u16(_ v: UInt16) { withUnsafeBytes(of: v.littleEndian) { data.append(contentsOf: $0) } }
        data.append(contentsOf: Array("RIFF".utf8)); u32(UInt32(clamping: 36 + dataBytes)); data.append(contentsOf: Array("WAVE".utf8))
        data.append(contentsOf: Array("fmt ".utf8)); u32(16); u16(1); u16(UInt16(channels)); u32(UInt32(sampleRate))
        u32(UInt32(sampleRate * channels * 2)); u16(UInt16(channels * 2)); u16(16)
        data.append(contentsOf: Array("data".utf8)); u32(UInt32(clamping: dataBytes))
        samples.withUnsafeBufferPointer { buffer in
            for sample in buffer { withUnsafeBytes(of: sample.littleEndian) { data.append(contentsOf: $0) } }
        }
        return data
    }
}

extension PacketStore {
    /// Reconstructs the audio of the given streams (RTP payloads read from the capture). Streams whose audio cannot be
    /// rendered (encrypted, unsupported codec, no packets) are omitted. Cancellable.
    public func reconstructAudio(_ streams: [RTPStreamRecord], callIndex: Int?,
                                 reconstructor: AudioReconstructor = AudioReconstructor()) async -> [ReconstructedAudio] {
        let wanted = Set(streams.map(\.id))
        guard !wanted.isEmpty else { return [] }
        let payloads = await rtpPayloads(streams: wanted, callIndex: callIndex)
        var byStream: [Int: [AudioReconstructor.Packet]] = [:]
        for sample in payloads {
            byStream[sample.streamIndex, default: []].append(AudioReconstructor.Packet(
                sequenceNumber: sample.sequenceNumber, timestamp: sample.timestamp, payloadType: sample.payloadType,
                marker: sample.marker, arrivalNanos: sample.arrivalNanos, frameNumber: sample.frameNumber, payload: sample.payload))
        }
        var audio: [ReconstructedAudio] = []
        for stream in streams {
            if Task.isCancelled { break }
            guard let packets = byStream[stream.id], let reconstructed = reconstructor.reconstruct(stream: stream, packets: packets)
            else { continue }
            audio.append(reconstructed)
        }
        return audio
    }
}
