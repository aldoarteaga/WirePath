import Foundation

/// Whether a stream's audio can be reconstructed, and why not.
public enum AudioPlayability: Sendable, Equatable {
    case playable(decoder: String)
    /// SRTP (negotiated in SDP, or WebRTC media): payloads are encrypted and the keys are not in the capture.
    case encrypted
    /// A codec WirePath does not decode.
    case unsupported(codec: String, reason: UnsupportedReason)
    /// Dynamic payload type without SDP: the codec is unknown.
    case unknownCodec(payloadType: UInt8)
    /// The stream carries no voice (video, DTMF events only, comfort noise only).
    case notAudio(String)

    public enum UnsupportedReason: String, Sendable {
        /// Patent-pool or licence-restricted codec; not included until its licence is reviewed.
        case licensing
        /// License-free, but WirePath has no decoder for it yet.
        case notImplemented
        /// The system decoder could not be created on this device.
        case systemDecoderUnavailable
    }

    public var isPlayable: Bool {
        if case .playable = self { return true }
        return false
    }
}

/// Codec decoders by kind. Extensible: `register` adds or replaces one (tests, future codecs).
public struct AudioCodecRegistry: Sendable {
    public typealias Factory = @Sendable (CodecDescriptor) -> (any AudioDecoder)?

    public struct Entry: Sendable {
        /// Shown to the user ("G.711 (built in)", "Opus (system decoder)").
        public var name: String
        public var make: Factory
    }

    private var entries: [CodecKind: Entry] = [:]

    public init() {}

    public mutating func register(_ kind: CodecKind, name: String, make: @escaping Factory) {
        entries[kind] = Entry(name: name, make: make)
    }

    public func entry(for kind: CodecKind) -> Entry? { entries[kind] }

    public func makeDecoder(for codec: CodecDescriptor) -> (any AudioDecoder)? {
        entries[codec.kind]?.make(codec)
    }

    /// The decoders WirePath ships: G.711, G.722 and L16 in Swift; Opus and iLBC through the system codecs.
    public static let standard: AudioCodecRegistry = {
        var registry = AudioCodecRegistry()
        registry.register(.pcmu, name: String(localized: "G.711 µ-law (built in)", bundle: CoreLocalization.bundle)) { _ in G711Decoder(.muLaw) }
        registry.register(.pcma, name: String(localized: "G.711 A-law (built in)", bundle: CoreLocalization.bundle)) { _ in G711Decoder(.aLaw) }
        registry.register(.g722, name: String(localized: "G.722 (built in)", bundle: CoreLocalization.bundle)) { _ in G722Decoder() }
        registry.register(.l16, name: String(localized: "L16 linear PCM (built in)", bundle: CoreLocalization.bundle)) { codec in
            L16Decoder(sampleRate: codec.clockRate ?? 44100, channels: codec.channels ?? 1)
        }
        registry.register(.opus, name: String(localized: "Opus (system decoder)", bundle: CoreLocalization.bundle)) { _ in SystemAudioDecoder.opus() }
        registry.register(.ilbc, name: String(localized: "iLBC (system decoder)", bundle: CoreLocalization.bundle)) { _ in ILBCDecoder() }
        return registry
    }()

    /// Codecs deliberately left out because of licensing.
    public static let licenseRestricted: Set<CodecKind> = [.g729, .g723, .amr, .amrWB, .g7221]

    /// What can be done with a stream's audio.
    public func playability(of stream: RTPStreamRecord) -> AudioPlayability {
        if stream.secure == true { return .encrypted }
        let formats = stream.payloadFormats ?? stream.codec.map { [$0] } ?? []
        let voice = formats.filter { $0.kind.isVoice }
        guard let codec = stream.codec ?? voice.first else {
            return .unknownCodec(payloadType: stream.payloadType)
        }
        switch codec.kind {
        case .video: return .notAudio(codec.displayName)
        case .telephoneEvent, .comfortNoise:
            // A stream made only of events or noise; playable if a voice format also appears in it.
            guard let other = voice.first else { return .notAudio(codec.displayName) }
            return playability(of: other)
        case .unknown:
            return .unknownCodec(payloadType: codec.payloadType)
        default:
            return playability(of: codec)
        }
    }

    public func playability(of codec: CodecDescriptor) -> AudioPlayability {
        if let entry = entries[codec.kind] {
            return entry.make(codec) != nil ? .playable(decoder: entry.name)
                : .unsupported(codec: codec.displayName, reason: .systemDecoderUnavailable)
        }
        if codec.kind == .unknown { return .unknownCodec(payloadType: codec.payloadType) }
        if !codec.kind.isVoice { return .notAudio(codec.displayName) }
        return .unsupported(codec: codec.displayName,
                            reason: Self.licenseRestricted.contains(codec.kind) ? .licensing : .notImplemented)
    }
}

/// iLBC with the frame mode taken from each payload's size (38-byte 20 ms or 50-byte 30 ms frames).
public final class ILBCDecoder: AudioDecoder {
    public let sampleRate = 8000
    private var twenty: SystemAudioDecoder?
    private var thirty: SystemAudioDecoder?

    public init?() {
        // Fail early when the system has no iLBC decoder.
        guard let probe = SystemAudioDecoder.iLBC(frameMs: 20) else { return nil }
        twenty = probe
    }

    public func decode(_ payload: UnsafeRawBufferPointer) throws(AudioDecodeError) -> [Int16] {
        if payload.count % 38 == 0, let twenty {
            return try twenty.decode(payload)
        }
        if payload.count % 50 == 0 {
            if thirty == nil { thirty = SystemAudioDecoder.iLBC(frameMs: 30) }
            if let thirty { return try thirty.decode(payload) }
        }
        throw .invalidPayload
    }
}
