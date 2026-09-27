import Foundation

/// Equipment impairment parameters from ITU-T G.113 Appendix I.
public struct CodecImpairment: Sendable, Hashable {
    /// Equipment impairment factor Ie.
    public var ie: Double
    /// Packet-loss robustness factor Bpl.
    public var bpl: Double
}

/// ITU-T G.107 E-model, narrowband, default parameter set.
///
/// WirePath measures loss and its burstiness from RTP; one-way network delay is not observable from a
/// single capture point, so the delay impairment Id is only applied when a delay is supplied.
/// The result is therefore a *listening-quality estimate* and is labelled as such in the UI.
public enum EModel {
    /// Ro − Is with the G.107 default parameter values.
    public static let defaultR: Double = 93.2

    /// Ie/Bpl for codecs with published values; nil when the E-model has no parameters for the codec.
    public static func impairment(for codec: CodecKind) -> CodecImpairment? {
        switch codec {
        // G.711 with packet-loss concealment (G.711 Appendix I), as implemented by current endpoints.
        case .pcmu, .pcma: return CodecImpairment(ie: 0, bpl: 25.1)
        // G.729A + VAD.
        case .g729: return CodecImpairment(ie: 11, bpl: 19.0)
        // G.723.1 6.3 kbit/s + VAD.
        case .g723: return CodecImpairment(ie: 15, bpl: 16.1)
        default: return nil
        }
    }

    /// Effective equipment impairment Ie,eff (G.107 eq. 7-29).
    public static func effectiveImpairment(_ impairment: CodecImpairment, packetLossPercent: Double,
                                           burstRatio: Double) -> Double {
        let ppl = max(0, min(100, packetLossPercent))
        let burstR = max(1, burstRatio)
        return impairment.ie + (95 - impairment.ie) * ppl / (ppl / burstR + impairment.bpl)
    }

    /// Delay impairment Idd for absolute delay Ta in ms (G.107 eq. 7-27); 0 up to 100 ms.
    public static func delayImpairment(oneWayDelayMs ta: Double) -> Double {
        guard ta > 100 else { return 0 }
        let x = log10(ta / 100) / log10(2)
        return 25 * (pow(1 + pow(x, 6), 1.0 / 6) - 3 * pow(1 + pow(x / 3, 6), 1.0 / 6) + 2)
    }

    /// Transmission rating factor R, or nil when the codec has no E-model parameters.
    public static func rFactor(codec: CodecKind, packetLossPercent: Double, burstRatio: Double = 1,
                               oneWayDelayMs: Double? = nil) -> Double? {
        guard let impairment = impairment(for: codec) else { return nil }
        let ieEff = effectiveImpairment(impairment, packetLossPercent: packetLossPercent, burstRatio: burstRatio)
        let id = oneWayDelayMs.map(delayImpairment) ?? 0
        return defaultR - ieEff - id
    }

    /// MOS (conversational quality estimate) from R (G.107 Annex B).
    public static func mos(fromR r: Double) -> Double {
        if r <= 0 { return 1 }
        if r >= 100 { return 4.5 }
        return 1 + 0.035 * r + r * (r - 60) * (100 - r) * 7e-6
    }

    public static func mos(codec: CodecKind, packetLossPercent: Double, burstRatio: Double = 1,
                           oneWayDelayMs: Double? = nil) -> Double? {
        rFactor(codec: codec, packetLossPercent: packetLossPercent, burstRatio: burstRatio,
                oneWayDelayMs: oneWayDelayMs).map(mos(fromR:))
    }
}

/// Qualitative bands used by the Overview and call headers.
public enum QualityRating: String, Sendable {
    case good = "Good", fair = "Fair", poor = "Poor", bad = "Bad"

    public init(mos: Double) {
        switch mos {
        case 4.0...: self = .good
        case 3.6..<4.0: self = .fair
        case 3.1..<3.6: self = .poor
        default: self = .bad
        }
    }

    /// The rating in the interface language.
    public var localizedName: String {
        switch self {
        case .good: return String(localized: "Good", bundle: CoreLocalization.bundle)
        case .fair: return String(localized: "Fair", bundle: CoreLocalization.bundle)
        case .poor: return String(localized: "Poor", bundle: CoreLocalization.bundle)
        case .bad: return String(localized: "Bad", bundle: CoreLocalization.bundle)
        }
    }
}

/// Colour thresholds from the WirePath design (warning / error).
public enum QualityThresholds {
    public static let mosWarning = 4.0
    public static let mosError = 3.7
    public static let jitterWarningMs = 10.0
    public static let jitterErrorMs = 15.0
    public static let lossWarningPercent = 1.0
    public static let lossErrorPercent = 2.0
    /// Jitter peaks above this are called out as spikes (dashed line on the jitter chart).
    public static let jitterSpikeMs = 30.0

    public static func severity(mos: Double?) -> Severity {
        guard let mos else { return .ok }
        return mos < mosError ? .error : mos < mosWarning ? .warning : .ok
    }

    public static func severity(jitterMs: Double?) -> Severity {
        guard let jitterMs else { return .ok }
        return jitterMs > jitterErrorMs ? .error : jitterMs > jitterWarningMs ? .warning : .ok
    }

    public static func severity(lossPercent: Double?) -> Severity {
        guard let lossPercent else { return .ok }
        return lossPercent > lossErrorPercent ? .error : lossPercent > lossWarningPercent ? .warning : .ok
    }

    /// MOS histogram bucket (< 3.1, 3.1–3.6, 3.6–4.0, 4.0–4.3, ≥ 4.3).
    public static func histogramBucket(mos: Double) -> Int {
        switch mos {
        case ..<3.1: return 0
        case 3.1..<3.6: return 1
        case 3.6..<4.0: return 2
        case 4.0..<4.3: return 3
        default: return 4
        }
    }

    public static let histogramLabels = ["< 3.1", "3.1–3.6", "3.6–4.0", "4.0–4.3", "≥ 4.3"]
}
