import AVFAudio
import Foundation

/// Decodes a compressed payload with a codec that ships with macOS and iPadOS, through `AVAudioConverter`.
/// Used for Opus (RFC 6716, royalty-free) and iLBC (RFC 3951, royalty-free), so WirePath carries no codec code
/// or licence of its own for them.
public final class SystemAudioDecoder: AudioDecoder {
    public let sampleRate: Int
    private let converter: AVAudioConverter
    private let inputFormat: AVAudioFormat
    private let outputFormat: AVAudioFormat
    private let maxFramesPerPacket: AVAudioFrameCount
    /// Bytes per packet for constant-size codecs (iLBC); 0 when packets vary (Opus).
    private let bytesPerPacket: Int

    /// - Parameters:
    ///   - framesPerPacket: frames in one packet as declared to the decoder (Opus: 960 = 20 ms at 48 kHz).
    ///   - maxFramesPerPacket: output capacity for one packet (Opus packets carry up to 120 ms).
    init?(formatID: AudioFormatID, sampleRate: Int, framesPerPacket: UInt32, maxFramesPerPacket: UInt32, bytesPerPacket: UInt32 = 0) {
        var description = AudioStreamBasicDescription(
            mSampleRate: Double(sampleRate), mFormatID: formatID, mFormatFlags: 0, mBytesPerPacket: bytesPerPacket,
            mFramesPerPacket: framesPerPacket, mBytesPerFrame: 0, mChannelsPerFrame: 1, mBitsPerChannel: 0, mReserved: 0)
        guard let input = AVAudioFormat(streamDescription: &description),
              let output = AVAudioFormat(commonFormat: .pcmFormatInt16, sampleRate: Double(sampleRate), channels: 1, interleaved: true),
              let converter = AVAudioConverter(from: input, to: output) else { return nil }
        self.sampleRate = sampleRate
        self.converter = converter
        self.inputFormat = input
        self.outputFormat = output
        self.maxFramesPerPacket = maxFramesPerPacket
        self.bytesPerPacket = Int(bytesPerPacket)
    }

    /// Opus at 48 kHz (the RTP clock of every Opus payload, RFC 7587), mixed down to mono by the decoder.
    public static func opus() -> SystemAudioDecoder? {
        SystemAudioDecoder(formatID: kAudioFormatOpus, sampleRate: 48000, framesPerPacket: 960, maxFramesPerPacket: 5760)
    }

    /// iLBC with 20 ms (38-byte) or 30 ms (50-byte) frames.
    public static func iLBC(frameMs: Int) -> SystemAudioDecoder? {
        let thirty = frameMs == 30
        return SystemAudioDecoder(formatID: kAudioFormatiLBC, sampleRate: 8000, framesPerPacket: thirty ? 240 : 160,
                                  maxFramesPerPacket: thirty ? 240 : 160, bytesPerPacket: thirty ? 50 : 38)
    }

    /// Hands the converter one packet, once.
    private final class OneShot: @unchecked Sendable {
        let buffer: AVAudioCompressedBuffer
        var delivered = false
        init(_ buffer: AVAudioCompressedBuffer) { self.buffer = buffer }
    }

    public func decode(_ payload: UnsafeRawBufferPointer) throws(AudioDecodeError) -> [Int16] {
        guard let base = payload.baseAddress, !payload.isEmpty, payload.count <= 1_500 else { throw .invalidPayload }
        if bytesPerPacket > 0 {
            // Constant-size frames: a payload may carry several.
            guard payload.count % bytesPerPacket == 0 else { throw .invalidPayload }
            var samples: [Int16] = []
            for offset in stride(from: 0, to: payload.count, by: bytesPerPacket) {
                samples += try decodePacket(UnsafeRawBufferPointer(start: base + offset, count: bytesPerPacket))
            }
            return samples
        }
        return try decodePacket(payload)
    }

    private func decodePacket(_ packet: UnsafeRawBufferPointer) throws(AudioDecodeError) -> [Int16] {
        guard let base = packet.baseAddress else { throw .invalidPayload }
        let compressed = AVAudioCompressedBuffer(format: inputFormat, packetCapacity: 1, maximumPacketSize: packet.count)
        compressed.data.copyMemory(from: base, byteCount: packet.count)
        compressed.byteLength = UInt32(packet.count)
        compressed.packetCount = 1
        compressed.packetDescriptions?.pointee = AudioStreamPacketDescription(mStartOffset: 0, mVariableFramesInPacket: 0,
                                                                              mDataByteSize: UInt32(packet.count))
        guard let output = AVAudioPCMBuffer(pcmFormat: outputFormat, frameCapacity: maxFramesPerPacket) else { throw .decoderFailure }
        let source = OneShot(compressed)
        var error: NSError?
        let status = converter.convert(to: output, error: &error) { _, inputStatus in
            if source.delivered {
                inputStatus.pointee = .noDataNow
                return nil
            }
            source.delivered = true
            inputStatus.pointee = .haveData
            return source.buffer
        }
        guard status != .error, error == nil, let channel = output.int16ChannelData else { throw .decoderFailure }
        return Array(UnsafeBufferPointer(start: channel[0], count: Int(output.frameLength)))
    }
}
