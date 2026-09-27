import Foundation

/// Why a payload could not be decoded.
public enum AudioDecodeError: Error, Sendable, Equatable {
    /// The payload is not valid for the codec (wrong size, damaged frame).
    case invalidPayload
    /// The system decoder refused the payload.
    case decoderFailure
}

/// Decodes one RTP payload format to mono 16-bit PCM.
///
/// Decoders are stateful (ADPCM predictors, Opus state), so one instance decodes one stream, in RTP order.
/// Multi-channel payloads are mixed down to mono: WirePath plays each direction of a call on its own side.
public protocol AudioDecoder: AnyObject {
    /// Sampling rate of the PCM produced, in Hz.
    var sampleRate: Int { get }
    /// Decodes one payload.
    func decode(_ payload: UnsafeRawBufferPointer) throws(AudioDecodeError) -> [Int16]
    /// Samples for `frames` samples lost in the network (packet-loss concealment).
    func conceal(frames: Int) -> [Int16]
}

extension AudioDecoder {
    /// Silence, unless the codec conceals better.
    public func conceal(frames: Int) -> [Int16] { [Int16](repeating: 0, count: max(0, frames)) }
}

/// ITU-T G.711 µ-law and A-law (PCMU, PCMA).
public final class G711Decoder: AudioDecoder {
    public enum Law: Sendable { case muLaw, aLaw }

    public let sampleRate = 8000
    private let table: [Int16]

    public init(_ law: Law) {
        table = law == .muLaw ? Self.muLaw : Self.aLaw
    }

    public func decode(_ payload: UnsafeRawBufferPointer) throws(AudioDecodeError) -> [Int16] {
        payload.map { table[Int($0)] }
    }

    /// µ-law expansion (G.711 table 2).
    public static let muLaw: [Int16] = (0..<256).map { value in
        let u = ~UInt8(value)
        let exponent = Int((u >> 4) & 0x07)
        let mantissa = Int(u & 0x0F)
        let magnitude = (((mantissa << 3) + 0x84) << exponent) - 0x84
        return Int16(u & 0x80 != 0 ? -magnitude : magnitude)
    }

    /// A-law expansion (G.711 table 1).
    public static let aLaw: [Int16] = (0..<256).map { value in
        let a = UInt8(value) ^ 0x55
        let exponent = Int((a >> 4) & 0x07)
        let mantissa = Int(a & 0x0F)
        let magnitude: Int
        switch exponent {
        case 0: magnitude = (mantissa << 4) + 8
        default: magnitude = ((mantissa << 4) + 0x108) << (exponent - 1)
        }
        return Int16(a & 0x80 != 0 ? magnitude : -magnitude)
    }
}

/// Linear 16-bit PCM, network byte order (RFC 3551 L16). Channels are interleaved and mixed down to mono.
public final class L16Decoder: AudioDecoder {
    public let sampleRate: Int
    private let channels: Int

    public init(sampleRate: Int, channels: Int) {
        self.sampleRate = sampleRate
        self.channels = max(1, min(channels, 8))
    }

    public func decode(_ payload: UnsafeRawBufferPointer) throws(AudioDecodeError) -> [Int16] {
        let frameBytes = 2 * channels
        guard payload.count % frameBytes == 0 else { throw .invalidPayload }
        var samples = [Int16]()
        samples.reserveCapacity(payload.count / frameBytes)
        var offset = 0
        while offset + frameBytes <= payload.count {
            var sum = 0
            for channel in 0..<channels { sum += Int(Int16(bitPattern: payload.u16be(offset + 2 * channel))) }
            samples.append(Int16(sum / channels))
            offset += frameBytes
        }
        return samples
    }
}
